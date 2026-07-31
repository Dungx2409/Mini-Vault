from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy import desc, select
from sqlalchemy.orm import Session
from app.core.crypto_service import decrypt, encrypt
from app.core.vault_state import VaultState
from app.exceptions import AppError
from app.models import TransitKey, TransitKeyVersion
from app.utils.base64_utils import b64d, b64e
from app.utils.datetime_utils import utcnow
from app.utils.validation import validate_key_name
import os


class TransitService:
    def __init__(self, db: Session, state: VaultState):
        self.db, self.state = db, state

    def _find(self, email: str, name: str, usage: str | None = None) -> TransitKey:
        self.state.require_dek()
        key = self.db.scalar(select(TransitKey).where(TransitKey.owner_email == email,
                                                     TransitKey.key_name == name))
        if not key:
            # No key by this name in the caller's namespace: a name owned by another user and a
            # name that does not exist at all must be indistinguishable, so a probe cannot learn
            # which key names exist (spec 2.3). PERMISSION_DENIED also triggers the audit hook.
            raise AppError("PERMISSION_DENIED", "Permission denied", 403)
        if key.revoked_at:
            # Only reachable for the caller's own revoked key, so this leaks nothing cross-user.
            raise AppError("KEY_NOT_FOUND", "Key not found", 404)
        if usage and key.key_usage != usage:
            raise AppError("INVALID_KEY_USAGE", "Key cannot be used for this operation", 400)
        return key

    def create_aes(self, email: str, name: str) -> dict:
        validate_key_name(name); dek = self.state.require_dek()
        if self.db.scalar(select(TransitKey).where(TransitKey.owner_email == email, TransitKey.key_name == name)):
            raise AppError("KEY_ALREADY_EXISTS", "Key already exists", 409)
        nonce, wrapped = encrypt(dek, os.urandom(32), f"key:{email}:{name}".encode())
        key = TransitKey(key_name=name, owner_email=email, key_usage="ENCRYPT_DECRYPT",
                         algorithm="AES-256-GCM", encrypted_key_material_b64=b64e(wrapped),
                         key_nonce_b64=b64e(nonce))
        self.db.add(key); self.db.flush()
        self.db.add(TransitKeyVersion(transit_key_id=key.id, version=1,
                                      encrypted_key_material_b64=key.encrypted_key_material_b64,
                                      key_nonce_b64=key.key_nonce_b64))
        self.db.commit()
        return self.metadata(key)

    def create_signing(self, email: str, name: str) -> dict:
        validate_key_name(name); dek = self.state.require_dek()
        if self.db.scalar(select(TransitKey).where(TransitKey.owner_email == email, TransitKey.key_name == name)):
            raise AppError("KEY_ALREADY_EXISTS", "Key already exists", 409)
        private = Ed25519PrivateKey.generate()
        raw = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                    serialization.NoEncryption())
        public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        nonce, wrapped = encrypt(dek, raw, f"key:{email}:{name}".encode())
        key = TransitKey(key_name=name, owner_email=email, key_usage="SIGN_VERIFY", algorithm="ED25519",
                         encrypted_key_material_b64=b64e(wrapped), key_nonce_b64=b64e(nonce),
                         public_key_b64=b64e(public))
        self.db.add(key); self.db.commit()
        return self.metadata(key)

    @staticmethod
    def metadata(key: TransitKey, current_version: int = 1) -> dict:
        return {"key_name": key.key_name, "key_usage": key.key_usage, "algorithm": key.algorithm,
                "current_version": current_version,
                "created_at": key.created_at.isoformat(), "revoked": key.revoked_at is not None}

    def _current_version(self, key: TransitKey) -> TransitKeyVersion | None:
        return self.db.scalar(select(TransitKeyVersion).where(
            TransitKeyVersion.transit_key_id == key.id).order_by(desc(TransitKeyVersion.version)))

    def _metadata(self, key: TransitKey) -> dict:
        version = self._current_version(key)
        return self.metadata(key, version.version if version else 1)

    def list(self, email: str) -> list[dict]:
        self.state.require_dek()
        return [self._metadata(k) for k in self.db.scalars(select(TransitKey).where(
            TransitKey.owner_email == email, TransitKey.revoked_at.is_(None))).all()]

    def get(self, email: str, name: str) -> dict:
        return self._metadata(self._find(email, name))

    def revoke(self, email: str, name: str) -> None:
        key = self._find(email, name); key.revoked_at = utcnow(); self.db.commit()

    def rotate(self, email: str, name: str) -> dict:
        key = self._find(email, name, "ENCRYPT_DECRYPT")
        dek = self.state.require_dek()
        latest = self._current_version(key)
        next_version = (latest.version if latest else 1) + 1
        nonce, wrapped = encrypt(dek, os.urandom(32), f"key:{email}:{name}:v{next_version}".encode())
        key.encrypted_key_material_b64 = b64e(wrapped)
        key.key_nonce_b64 = b64e(nonce)
        self.db.add(TransitKeyVersion(transit_key_id=key.id, version=next_version,
                                      encrypted_key_material_b64=key.encrypted_key_material_b64,
                                      key_nonce_b64=key.key_nonce_b64))
        self.db.commit()
        return self._metadata(key)

    def _material(self, key: TransitKey, version: int | None = None) -> bytes:
        record = None
        if version is not None:
            record = self.db.scalar(select(TransitKeyVersion).where(
                TransitKeyVersion.transit_key_id == key.id, TransitKeyVersion.version == version))
            if not record and version != 1:
                raise AppError("KEY_VERSION_NOT_FOUND", "Key version not found", 404)
        elif key.key_usage == "ENCRYPT_DECRYPT":
            record = self._current_version(key)
            version = record.version if record else 1
        else:
            version = 1
        aad = f"key:{key.owner_email}:{key.key_name}".encode() if version == 1 else \
            f"key:{key.owner_email}:{key.key_name}:v{version}".encode()
        nonce_b64 = record.key_nonce_b64 if record else key.key_nonce_b64
        material_b64 = record.encrypted_key_material_b64 if record else key.encrypted_key_material_b64
        try:
            return decrypt(self.state.require_dek(), b64d(nonce_b64), b64d(material_b64), aad)
        except InvalidTag:
            raise AppError("DECRYPTION_FAILED", "Key material could not be decrypted", 400)

    def encrypt(self, email: str, name: str, plaintext_b64: str) -> str:
        key = self._find(email, name, "ENCRYPT_DECRYPT"); raw = b64d(plaintext_b64)
        if len(raw) > 1_048_576: raise AppError("VALIDATION_ERROR", "Plaintext is too large", 413)
        version = self._current_version(key)
        key_version = version.version if version else 1
        nonce, ciphertext = encrypt(self._material(key, key_version), raw,
                                    f"transit:{email}:{name}:v{key_version}".encode())
        return f"vault:v{key_version}:{name}:{b64e(nonce + ciphertext)}"

    def decrypt(self, email: str, envelope: str) -> str:
        parts = envelope.split(":", 3)
        if len(parts) != 4 or parts[0] != "vault" or not parts[1].startswith("v") or not parts[2]:
            raise AppError("INVALID_CIPHERTEXT", "Invalid ciphertext", 400)
        try:
            key_version = int(parts[1][1:])
        except ValueError:
            raise AppError("INVALID_CIPHERTEXT", "Invalid ciphertext", 400)
        if key_version < 1:
            raise AppError("INVALID_CIPHERTEXT", "Invalid ciphertext", 400)
        name, blob = parts[2], b64d(parts[3], "INVALID_CIPHERTEXT")
        if len(blob) < 28: raise AppError("INVALID_CIPHERTEXT", "Invalid ciphertext", 400)  # 12B nonce + 16B GCM tag
        key = self._find(email, name, "ENCRYPT_DECRYPT")
        try:
            raw = decrypt(self._material(key, key_version), blob[:12], blob[12:],
                          f"transit:{email}:{name}:v{key_version}".encode())
        except InvalidTag:
            raise AppError("DECRYPTION_FAILED", "Ciphertext could not be decrypted", 400)
        return b64e(raw)

    def sign(self, email: str, name: str, message_b64: str, message_type: str) -> dict:
        key = self._find(email, name, "SIGN_VERIFY"); message = b64d(message_b64)
        if message_type == "DIGEST" and len(message) != 32:
            raise AppError("INVALID_DIGEST_LENGTH", "Digest must be 32 bytes", 400)
        private = Ed25519PrivateKey.from_private_bytes(self._material(key))
        return {"key_name": name, "signature_b64": b64e(private.sign(message)), "signing_algorithm": "ED25519"}

    def verify(self, email: str, name: str, message_b64: str, message_type: str, signature_b64: str,
               signing_algorithm: str | None = None) -> dict:
        key = self._find(email, name, "SIGN_VERIFY"); message = b64d(message_b64)
        if signing_algorithm and signing_algorithm != key.algorithm:
            raise AppError("INVALID_SIGNING_ALGORITHM",
                           "Signing algorithm does not match the key", 400)
        if message_type == "DIGEST" and len(message) != 32:
            raise AppError("INVALID_DIGEST_LENGTH", "Digest must be 32 bytes", 400)
        try:
            signature = b64d(signature_b64)
            Ed25519PublicKey.from_public_bytes(b64d(key.public_key_b64 or "")).verify(signature, message)
            valid = True
        except (InvalidSignature, ValueError, AppError):
            valid = False
        return {"key_name": name, "signature_valid": valid, "signing_algorithm": "ED25519"}
