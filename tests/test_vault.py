from app.core.vault_state import vault_state
from app.models import VaultConfig
from tests.conftest import MASTER, TestingSession


def test_init_unlock_lock_and_no_plaintext_dek(client):
    r = client.post("/api/v1/vault/init", json={"master_passphrase": MASTER, "confirm_master_passphrase": MASTER})
    assert r.status_code == 201 and r.json()["data"]["status"] == "locked"
    assert client.post("/api/v1/vault/init", json={"master_passphrase": MASTER, "confirm_master_passphrase": MASTER}).json()["error"]["code"] == "VAULT_ALREADY_INITIALIZED"
    assert client.post("/api/v1/vault/unlock", json={"master_passphrase": "Wrong-Passphrase-123!"}).json()["error"]["code"] == "INVALID_MASTER_PASSPHRASE"
    assert client.post("/api/v1/vault/unlock", json={"master_passphrase": MASTER}).status_code == 200
    dek = vault_state.require_dek()
    with TestingSession() as db:
        row = db.query(VaultConfig).one()
        assert dek.hex() not in " ".join([row.encrypted_dek_b64, row.kdf_salt_b64, row.dek_nonce_b64])
    client.post("/api/v1/vault/lock")
    assert not vault_state.unlocked


def test_state_is_locked_on_new_application_lifespan(client):
    client.post("/api/v1/vault/init", json={"master_passphrase": MASTER, "confirm_master_passphrase": MASTER})
    client.post("/api/v1/vault/unlock", json={"master_passphrase": MASTER})
    vault_state.lock()
    assert client.get("/api/v1/vault/status").json()["data"]["status"] == "locked"

