from app.models import AuditLog, KVSecret
from tests.conftest import TestingSession, register_login


def test_kv_crud_tamper_and_access(initialized):
    c=initialized; alice=register_login(c); bob=register_login(c,"bob@example.com")
    path="secret/alice@example.com/database"; value={"password":"not-on-disk","host":"localhost"}
    assert c.put(f"/api/v1/kv/{path}",json={"data":value},headers=alice).status_code == 200
    assert c.get(f"/api/v1/kv/{path}",headers=alice).json()["data"]["value"] == value
    assert "value" not in c.get("/api/v1/kv",headers=alice).json()["data"][0]
    for method in (c.get,c.delete): assert method(f"/api/v1/kv/{path}",headers=bob).status_code == 403
    assert c.put(f"/api/v1/kv/{path}",json={"data":{"x":1}},headers=bob).status_code == 403
    with TestingSession() as db:
        row=db.query(KVSecret).one(); assert "not-on-disk" not in row.ciphertext_b64
        row.ciphertext_b64=("A" if row.ciphertext_b64[0] != "A" else "B")+row.ciphertext_b64[1:]; db.commit()
        assert db.query(AuditLog).count() == 3
    assert c.get(f"/api/v1/kv/{path}",headers=alice).json()["error"]["code"] == "DECRYPTION_FAILED"


def test_locked_and_auth_order(initialized):
    c=initialized; h=register_login(c); c.post("/api/v1/vault/lock")
    assert c.get("/api/v1/kv",headers=h).status_code == 423
    assert c.get("/api/v1/kv").status_code == 401

