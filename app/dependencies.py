import secrets
from datetime import timezone
from fastapi import Depends, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session as DBSession
from app.auth.service import token_digest
from app.database import get_db
from app.exceptions import AppError
from app.models import Session, User
from app.utils.datetime_utils import utcnow


class Principal:
    def __init__(self, user: User, session: Session):
        self.user, self.session = user, session


bearer_scheme = HTTPBearer(auto_error=False)


async def current_principal(
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
    db: DBSession = Depends(get_db),
) -> Principal:
    if not credentials or credentials.scheme.lower() != "bearer":
        raise AppError("UNAUTHENTICATED", "Authentication required", 401)
    token = credentials.credentials
    if not token:
        raise AppError("UNAUTHENTICATED", "Authentication required", 401)
    digest = token_digest(token)
    session = db.scalar(select(Session).where(Session.token_hash == digest))
    if not session or not secrets.compare_digest(session.token_hash, digest) or session.revoked_at:
        raise AppError("UNAUTHENTICATED", "Invalid session", 401)
    expires = session.expires_at if session.expires_at.tzinfo else session.expires_at.replace(tzinfo=timezone.utc)
    if expires <= utcnow():
        raise AppError("TOKEN_EXPIRED", "Session expired", 401)
    user = db.get(User, session.user_id)
    if not user:
        raise AppError("UNAUTHENTICATED", "Invalid session", 401)
    return Principal(user, session)
