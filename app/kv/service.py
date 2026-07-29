import json
from cryptography.exceptions import InvalidTag
from sqlalchemy import delete, desc, select
from sqlalchemy.orm import Session
from app.core.crypto_service import decrypt, encrypt
from app.core.vault_state import VaultState
from app.exceptions import AppError
from app.models import KVSecret, KVSecretVersion
from app.utils.base64_utils import b64d, b64e
from app.utils.datetime_utils import utcnow
from app.utils.validation import validate_path


def iso(value) -> str:
    return value.isoformat()


class KVService:
    def __init__(self, db: Session, state: VaultState):
        self.db, self.state = db, state

    def write(self, path: str, email: str, data: dict) -> dict:
        validate_path(path, email)
        dek = self.state.require_dek()
        raw = json.dumps(data, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
        if len(raw) > 1_048_576:
            raise AppError("VALIDATION_ERROR", "Secret is too large", 413)
        nonce, ciphertext = encrypt(dek, raw, path.encode())
        item = self.db.scalar(select(KVSecret).where(KVSecret.path == path))
        now = utcnow()
        if item:
            latest = self._current_version(item)
            next_version = (latest.version if latest else 1) + 1
            item.nonce_b64, item.ciphertext_b64, item.updated_at = b64e(nonce), b64e(ciphertext), now
        else:
            next_version = 1
            item = KVSecret(path=path, owner_email=email, nonce_b64=b64e(nonce),
                            ciphertext_b64=b64e(ciphertext), created_at=now, updated_at=now)
            self.db.add(item); self.db.flush()
        self.db.add(KVSecretVersion(kv_secret_id=item.id, version=next_version, nonce_b64=b64e(nonce),
                                    ciphertext_b64=b64e(ciphertext), created_at=now))
        self.db.commit()
        return {"path": item.path, "version": next_version, "created_at": iso(item.created_at),
                "updated_at": iso(item.updated_at)}

    def _current_version(self, item: KVSecret) -> KVSecretVersion | None:
        return self.db.scalar(select(KVSecretVersion).where(
            KVSecretVersion.kv_secret_id == item.id).order_by(desc(KVSecretVersion.version)))

    def read(self, path: str, email: str, version: int | None = None) -> dict:
        validate_path(path, email)
        dek = self.state.require_dek()
        item = self.db.scalar(select(KVSecret).where(KVSecret.path == path, KVSecret.owner_email == email))
        if not item:
            raise AppError("NOT_FOUND", "Secret not found", 404)
        record = None
        if version is not None:
            if version < 1:
                raise AppError("VALIDATION_ERROR", "Invalid version", 422)
            record = self.db.scalar(select(KVSecretVersion).where(
                KVSecretVersion.kv_secret_id == item.id, KVSecretVersion.version == version))
            if not record:
                raise AppError("NOT_FOUND", "Secret version not found", 404)
        else:
            record = self._current_version(item)
        nonce_b64 = record.nonce_b64 if record else item.nonce_b64
        ciphertext_b64 = record.ciphertext_b64 if record else item.ciphertext_b64
        current_version = record.version if record else 1
        try:
            raw = decrypt(dek, b64d(nonce_b64), b64d(ciphertext_b64), path.encode())
            value = json.loads(raw)
        except (InvalidTag, ValueError, json.JSONDecodeError):
            raise AppError("DECRYPTION_FAILED", "Secret could not be decrypted", 400)
        return {"path": path, "version": current_version, "value": value}

    def versions(self, path: str, email: str) -> list[dict]:
        validate_path(path, email)
        self.state.require_dek()
        item = self.db.scalar(select(KVSecret).where(KVSecret.path == path, KVSecret.owner_email == email))
        if not item:
            raise AppError("NOT_FOUND", "Secret not found", 404)
        rows = self.db.scalars(select(KVSecretVersion).where(
            KVSecretVersion.kv_secret_id == item.id).order_by(KVSecretVersion.version)).all()
        if not rows:
            return [{"version": 1, "created_at": iso(item.created_at)}]
        return [{"version": x.version, "created_at": iso(x.created_at)} for x in rows]

    def delete(self, path: str, email: str) -> None:
        validate_path(path, email)
        self.state.require_dek()
        item = self.db.scalar(select(KVSecret).where(KVSecret.path == path, KVSecret.owner_email == email))
        if not item:
            raise AppError("NOT_FOUND", "Secret not found", 404)
        self.db.execute(delete(KVSecretVersion).where(KVSecretVersion.kv_secret_id == item.id))
        self.db.delete(item); self.db.commit()

    def list(self, email: str) -> list[dict]:
        self.state.require_dek()
        rows = self.db.scalars(select(KVSecret).where(KVSecret.owner_email == email).order_by(KVSecret.path)).all()
        return [{"path": x.path, "current_version": (self._current_version(x).version if self._current_version(x) else 1),
                 "created_at": iso(x.created_at), "updated_at": iso(x.updated_at)} for x in rows]
