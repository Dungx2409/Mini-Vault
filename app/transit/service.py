from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.core.crypto_service import decrypt, encrypt
from app.core.vault_state import VaultState
from app.exceptions import AppError
from app.models import TransitKey
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
        self.db.add(key); self.db.commit()
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
    def metadata(key: TransitKey) -> dict:
        return {"key_name": key.key_name, "key_usage": key.key_usage, "algorithm": key.algorithm,
                "created_at": key.created_at.isoformat(), "revoked": key.revoked_at is not None}

    def list(self, email: str) -> list[dict]:
        self.state.require_dek()
        return [self.metadata(k) for k in self.db.scalars(select(TransitKey).where(
            TransitKey.owner_email == email, TransitKey.revoked_at.is_(None))).all()]

    def get(self, email: str, name: str) -> dict:
        return self.metadata(self._find(email, name))

    def revoke(self, email: str, name: str) -> None:
        key = self._find(email, name); key.revoked_at = utcnow(); self.db.commit()

    def _material(self, key: TransitKey) -> bytes:
        try:
            return decrypt(self.state.require_dek(), b64d(key.key_nonce_b64),
                           b64d(key.encrypted_key_material_b64),
                           f"key:{key.owner_email}:{key.key_name}".encode())
        except InvalidTag:
            raise AppError("DECRYPTION_FAILED", "Key material could not be decrypted", 400)

    def encrypt(self, email: str, name: str, plaintext_b64: str) -> str:
        key = self._find(email, name, "ENCRYPT_DECRYPT"); raw = b64d(plaintext_b64)
        if len(raw) > 1_048_576: raise AppError("VALIDATION_ERROR", "Plaintext is too large", 413)
        nonce, ciphertext = encrypt(self._material(key), raw, f"transit:{email}:{name}:v1".encode())
        return f"vault:v1:{name}:{b64e(nonce + ciphertext)}"

    def decrypt(self, email: str, envelope: str) -> str:
        parts = envelope.split(":", 3)
        if len(parts) != 4 or parts[:2] != ["vault", "v1"] or not parts[2]:
            raise AppError("INVALID_CIPHERTEXT", "Invalid ciphertext", 400)
        name, blob = parts[2], b64d(parts[3], "INVALID_CIPHERTEXT")
        if len(blob) < 28: raise AppError("INVALID_CIPHERTEXT", "Invalid ciphertext", 400)  # 12B nonce + 16B GCM tag
        key = self._find(email, name, "ENCRYPT_DECRYPT")
        try:
            raw = decrypt(self._material(key), blob[:12], blob[12:], f"transit:{email}:{name}:v1".encode())
        except InvalidTag:
            raise AppError("DECRYPTION_FAILED", "Ciphertext could not be decrypted", 400)
        return b64e(raw)

    def sign(self, email: str, name: str, message_b64: str, message_type: str) -> dict:
        key = self._find(email, name, "SIGN_VERIFY"); message = b64d(message_b64)
        if message_type == "DIGEST" and len(message) != 32:
            raise AppError("INVALID_DIGEST_LENGTH", "Digest must be 32 bytes", 400)
        private = Ed25519PrivateKey.from_private_bytes(self._material(key))
        return {"key_name": name, "signature_b64": b64e(private.sign(message)), "signing_algorithm": "ED25519"}

    def verify(self, email: str, name: str, message_b64: str, message_type: str, signature_b64: str) -> dict:
        key = self._find(email, name, "SIGN_VERIFY"); message = b64d(message_b64)
        if message_type == "DIGEST" and len(message) != 32:
            raise AppError("INVALID_DIGEST_LENGTH", "Digest must be 32 bytes", 400)
        try:
            signature = b64d(signature_b64)
            Ed25519PublicKey.from_public_bytes(b64d(key.public_key_b64 or "")).verify(signature, message)
            valid = True
        except (InvalidSignature, ValueError, AppError):
            valid = False
        return {"key_name": name, "signature_valid": valid, "signing_algorithm": "ED25519"}
