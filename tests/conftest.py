import os
os.environ["DATABASE_URL"] = "sqlite:///./test-mini-vault.db"

import asyncio
import httpx
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.config import get_settings
get_settings.cache_clear()
from app.database import Base, get_db
from app.main import app
from app.core.vault_state import vault_state

engine = create_engine("sqlite:///./test-mini-vault.db", connect_args={"check_same_thread": False})
TestingSession = sessionmaker(bind=engine, expire_on_commit=False)


async def override_db():
    db = TestingSession()
    try: yield db
    finally: db.close()


app.dependency_overrides[get_db] = override_db


@pytest.fixture(autouse=True)
def clean_db():
    vault_state.lock(); Base.metadata.drop_all(engine); Base.metadata.create_all(engine)
    yield
    vault_state.lock()


@pytest.fixture
def client():
    class Client:
        def request(self, method, url, **kwargs):
            async def call():
                transport = httpx.ASGITransport(app=app)
                async with httpx.AsyncClient(transport=transport, base_url="http://test") as value:
                    return await value.request(method, url, **kwargs)
            return asyncio.run(call())
        def get(self, url, **kwargs): return self.request("GET", url, **kwargs)
        def post(self, url, **kwargs): return self.request("POST", url, **kwargs)
        def put(self, url, **kwargs): return self.request("PUT", url, **kwargs)
        def delete(self, url, **kwargs): return self.request("DELETE", url, **kwargs)
    yield Client()


MASTER = "Strong-Master-Passphrase-2026!"
PASSWORD = "StrongPassword@123"


@pytest.fixture
def initialized(client):
    assert client.post("/api/v1/vault/init", json={"master_passphrase": MASTER,
        "confirm_master_passphrase": MASTER}).status_code == 201
    assert client.post("/api/v1/vault/unlock", json={"master_passphrase": MASTER}).status_code == 200
    return client


def register_login(client, email="alice@example.com"):
    client.post("/api/v1/auth/register", json={"email": email, "passphrase": PASSWORD,
                                                "confirm_passphrase": PASSWORD})
    token = client.post("/api/v1/auth/login", json={"email": email, "passphrase": PASSWORD}).json()["data"]["access_token"]
    return {"Authorization": f"Bearer {token}"}
