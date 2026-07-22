from datetime import timedelta
from app.models import Session, User
from app.utils.datetime_utils import utcnow
from tests.conftest import PASSWORD, TestingSession, register_login


def test_register_login_logout(client):
    r = client.post("/api/v1/auth/register", json={"email":" Alice@Example.com ","passphrase":PASSWORD,"confirm_passphrase":PASSWORD})
    assert r.status_code == 201 and r.json()["data"]["email"] == "alice@example.com"
    assert client.post("/api/v1/auth/register", json={"email":"alice@example.com","passphrase":PASSWORD,"confirm_passphrase":PASSWORD}).status_code == 409
    with TestingSession() as db: assert db.query(User).one().password_hash != PASSWORD
    headers = register_login(client, "bob@example.com")
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200
    assert client.post("/api/v1/auth/logout", headers=headers).status_code == 200
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401


def test_lockout_and_expiry(client):
    client.post("/api/v1/auth/register", json={"email":"alice@example.com","passphrase":PASSWORD,"confirm_passphrase":PASSWORD})
    for _ in range(5): client.post("/api/v1/auth/login", json={"email":"alice@example.com","passphrase":"WrongPassword@123"})
    assert client.post("/api/v1/auth/login", json={"email":"alice@example.com","passphrase":PASSWORD}).json()["error"]["code"] == "ACCOUNT_LOCKED"
    with TestingSession() as db:
        user=db.query(User).one(); user.locked_until=utcnow()-timedelta(seconds=1); db.commit()
    headers=register_login(client)
    with TestingSession() as db:
        s=db.query(Session).order_by(Session.id.desc()).first(); s.expires_at=utcnow()-timedelta(seconds=1); db.commit()
    assert client.get("/api/v1/auth/me", headers=headers).json()["error"]["code"] == "TOKEN_EXPIRED"

