import hashlib
import secrets
from datetime import timedelta, timezone
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy import select
from sqlalchemy.orm import Session as DBSession
from app.config import Settings
from app.exceptions import AppError
from app.models import Session, User
from app.utils.datetime_utils import utcnow
from app.utils.validation import validate_passphrase

hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class AuthService:
    def __init__(self, db: DBSession, settings: Settings):
        self.db, self.settings = db, settings

    def register(self, email: str, password: str, confirmation: str) -> dict:
        email = email.strip().lower()
        if password != confirmation:
            raise AppError("VALIDATION_ERROR", "Passphrases do not match", 400)
        validate_passphrase(password)
        if self.db.scalar(select(User).where(User.email == email)):
            raise AppError("EMAIL_ALREADY_EXISTS", "Email already exists", 409)
        self.db.add(User(email=email, password_hash=hasher.hash(password)))
        self.db.commit()
        return {"email": email}

    def login(self, email: str, password: str) -> dict:
        user = self.db.scalar(select(User).where(User.email == email.strip().lower()))
        now = utcnow()
        if user and user.locked_until:
            locked_until = user.locked_until if user.locked_until.tzinfo else user.locked_until.replace(tzinfo=timezone.utc)
            if locked_until > now:
                raise AppError("ACCOUNT_LOCKED", "Account is temporarily locked", 423)
        valid = False
        if user:
            try:
                valid = hasher.verify(user.password_hash, password)
            except VerifyMismatchError:
                valid = False
        if not valid:
            if user:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= 5:
                    user.locked_until = now + timedelta(minutes=5)
                self.db.commit()
            raise AppError("INVALID_CREDENTIALS", "Invalid credentials", 401)
        user.failed_login_attempts, user.locked_until = 0, None
        token = secrets.token_urlsafe(32)
        self.db.add(Session(user_id=user.id, token_hash=token_digest(token),
                            expires_at=now + timedelta(seconds=self.settings.session_ttl_seconds)))
        self.db.commit()
        return {"access_token": token, "token_type": "Bearer",
                "expires_in": self.settings.session_ttl_seconds}

    def logout(self, session: Session) -> None:
        session.revoked_at = utcnow()
        self.db.commit()
