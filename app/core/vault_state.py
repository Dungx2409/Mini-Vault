import threading
from app.exceptions import AppError


class VaultState:
    """Process-local holder for the plaintext DEK; never persists it."""
    def __init__(self) -> None:
        self._dek: bytes | None = None
        self._lock = threading.RLock()

    @property
    def unlocked(self) -> bool:
        with self._lock:
            return self._dek is not None

    def unlock(self, dek: bytes) -> None:
        with self._lock:
            self._dek = bytes(dek)

    def lock(self) -> None:
        with self._lock:
            self._dek = None

    def require_dek(self) -> bytes:
        with self._lock:
            if self._dek is None:
                raise AppError("VAULT_LOCKED", "Vault is locked", 423)
            return self._dek


vault_state = VaultState()

