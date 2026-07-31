import base64
import binascii
from app.exceptions import AppError


def b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def b64d(value: str, code: str = "VALIDATION_ERROR") -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError, TypeError) as exc:
        raise AppError(code, "Invalid Base64 data", 400) from exc

