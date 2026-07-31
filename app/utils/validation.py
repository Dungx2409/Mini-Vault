import re
from app.exceptions import AppError

KEY_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{3,64}$")


def validate_passphrase(value: str) -> None:
    if (len(value) < 12 or not re.search(r"[A-Z]", value)
            or not re.search(r"[a-z]", value) or not re.search(r"\d", value)
            or not re.search(r"[^A-Za-z0-9]", value)):
        raise AppError("WEAK_PASSPHRASE", "Passphrase does not meet security requirements", 400)


def validate_key_name(value: str) -> None:
    if not KEY_NAME_RE.fullmatch(value):
        raise AppError("VALIDATION_ERROR", "Invalid key name", 422)


def validate_path(path: str, email: str) -> None:
    if len(path) > 512 or not path or ".." in path or "\\" in path or "\x00" in path:
        raise AppError("VALIDATION_ERROR", "Invalid secret path", 422)
    prefix = f"secret/{email}/"
    if not path.startswith("secret/"):
        raise AppError("VALIDATION_ERROR", "Invalid secret path", 422)
    if not path.startswith(prefix) or len(path) == len(prefix):
        raise AppError("PERMISSION_DENIED", "Permission denied", 403)

