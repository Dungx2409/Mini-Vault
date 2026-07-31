from argon2.low_level import Type, hash_secret_raw

DEFAULT_PARAMS = {"time_cost": 3, "memory_cost": 65536, "parallelism": 2, "hash_len": 32}


def derive_key(passphrase: str, salt: bytes, params: dict) -> bytes:
    return hash_secret_raw(passphrase.encode(), salt, type=Type.ID, version=19, **params)

