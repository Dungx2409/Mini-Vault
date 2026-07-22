import json
import os
from cryptography.exceptions import InvalidTag
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.core.crypto_service import decrypt, encrypt
from app.core.key_derivation import DEFAULT_PARAMS, derive_key
from app.core.vault_state import VaultState
from app.exceptions import AppError
from app.models import VaultConfig
from app.utils.base64_utils import b64d, b64e
from app.utils.validation import validate_passphrase


class VaultService:
    def __init__(self, db: Session, state: VaultState):
        self.db, self.state = db, state

    def init(self, passphrase: str, confirmation: str) -> dict:
        if self.db.scalar(select(VaultConfig)):
            raise AppError("VAULT_ALREADY_INITIALIZED", "Vault is already initialized", 409)
        if passphrase != confirmation:
            raise AppError("VALIDATION_ERROR", "Passphrases do not match", 400)
        validate_passphrase(passphrase)
        salt, dek = os.urandom(16), os.urandom(32)
        derived = derive_key(passphrase, salt, DEFAULT_PARAMS)
        nonce, wrapped = encrypt(derived, dek, b"mini-vault-dek-v1")
        self.db.add(VaultConfig(kdf_algorithm="ARGON2ID", kdf_salt_b64=b64e(salt),
                    kdf_parameters_json=json.dumps(DEFAULT_PARAMS), encrypted_dek_b64=b64e(wrapped),
                    dek_nonce_b64=b64e(nonce)))
        self.db.commit()
        self.state.lock()
        return {"initialized": True, "status": "locked"}

    def unlock(self, passphrase: str) -> dict:
        config = self.db.scalar(select(VaultConfig))
        if not config:
            raise AppError("VAULT_NOT_INITIALIZED", "Vault is not initialized", 400)
        try:
            derived = derive_key(passphrase, b64d(config.kdf_salt_b64),
                                 json.loads(config.kdf_parameters_json))
            dek = decrypt(derived, b64d(config.dek_nonce_b64), b64d(config.encrypted_dek_b64),
                          b"mini-vault-dek-v1")
        except (InvalidTag, ValueError, TypeError):
            raise AppError("INVALID_MASTER_PASSPHRASE", "Invalid master passphrase", 401)
        self.state.unlock(dek)
        return {"status": "unlocked"}

    def status(self) -> dict:
        initialized = self.db.scalar(select(VaultConfig.id)) is not None
        return {"initialized": initialized, "status": "unlocked" if self.state.unlocked else "locked"}

