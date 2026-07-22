from typing import Any, Literal
from pydantic import BaseModel, EmailStr, Field, field_validator


class InitRequest(BaseModel):
    master_passphrase: str = Field(max_length=1024)
    confirm_master_passphrase: str = Field(max_length=1024)


class UnlockRequest(BaseModel):
    master_passphrase: str = Field(max_length=1024)


class RegisterRequest(BaseModel):
    email: EmailStr
    passphrase: str = Field(max_length=1024)
    confirm_passphrase: str = Field(max_length=1024)

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value):
        return value.strip().lower() if isinstance(value, str) else value


class LoginRequest(BaseModel):
    email: EmailStr
    passphrase: str = Field(max_length=1024)

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value):
        return value.strip().lower() if isinstance(value, str) else value


class KVWriteRequest(BaseModel):
    data: dict[str, Any]


class CreateKeyRequest(BaseModel):
    key_name: str
    key_usage: Literal["ENCRYPT_DECRYPT"]


class CreateSigningKeyRequest(BaseModel):
    key_name: str
    signing_algorithm: Literal["ED25519"]


class EncryptRequest(BaseModel):
    key_name: str
    plaintext_b64: str


class DecryptRequest(BaseModel):
    ciphertext: str


class SignRequest(BaseModel):
    key_name: str
    message_b64: str
    message_type: Literal["RAW", "DIGEST"]


class VerifyRequest(SignRequest):
    signature_b64: str
