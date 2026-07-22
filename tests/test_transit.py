import base64
import json
import os
from app.models import AuditLog, TransitKey
from tests.conftest import TestingSession, register_login


def b64(x): return base64.b64encode(x).decode()


def test_encrypt_decrypt_binary_access_revoke(initialized):
    c=initialized; a=register_login(c); b=register_login(c,"bob@example.com")
    assert c.post("/api/v1/transit/keys",json={"key_name":"payment-key","key_usage":"ENCRYPT_DECRYPT"},headers=a).status_code==201
    keys=c.get("/api/v1/transit/keys",headers=a).json()["data"]
    assert "encrypted_key_material_b64" not in str(keys)
    raw=os.urandom(128); enc=c.post("/api/v1/transit/encrypt",json={"key_name":"payment-key","plaintext_b64":b64(raw)},headers=a).json()["data"]["ciphertext"]
    assert base64.b64decode(c.post("/api/v1/transit/decrypt",json={"ciphertext":enc},headers=a).json()["data"]["plaintext_b64"])==raw
    assert c.post("/api/v1/transit/encrypt",json={"key_name":"payment-key","plaintext_b64":b64(raw)},headers=b).status_code==403
    assert c.post("/api/v1/transit/decrypt",json={"ciphertext":enc},headers=b).status_code==403
    bad=enc[:-2]+("AA" if enc[-2:]!="AA" else "BB")
    assert c.post("/api/v1/transit/decrypt",json={"ciphertext":bad},headers=a).status_code==400
    assert c.delete("/api/v1/transit/keys/payment-key",headers=a).status_code==200
    assert c.post("/api/v1/transit/decrypt",json={"ciphertext":enc},headers=a).status_code==404
    with TestingSession() as db: assert db.query(AuditLog).count() == 2


def test_sign_verify_tamper_wrong_key_and_private_encrypted(initialized):
    c=initialized; a=register_login(c)
    for name in ("sign-key-a","sign-key-b"):
        assert c.post("/api/v1/transit/signing-keys",json={"key_name":name,"signing_algorithm":"ED25519"},headers=a).status_code==201
    msg=b"hello vault"; signature=c.post("/api/v1/transit/sign",json={"key_name":"sign-key-a","message_b64":b64(msg),"message_type":"RAW"},headers=a).json()["data"]["signature_b64"]
    def verify(name, data, sig=signature):
        return c.post("/api/v1/transit/verify",json={"key_name":name,"message_b64":b64(data),"message_type":"RAW","signature_b64":sig},headers=a).json()["data"]["signature_valid"]
    assert verify("sign-key-a",msg) is True
    assert verify("sign-key-a",b"jello vault") is False
    assert verify("sign-key-b",msg) is False
    assert verify("sign-key-a",msg,"AAAA") is False
    assert c.post("/api/v1/transit/sign",json={"key_name":"sign-key-a","message_b64":b64(b"short"),"message_type":"DIGEST"},headers=a).json()["error"]["code"]=="INVALID_DIGEST_LENGTH"
    with TestingSession() as db:
        key=db.query(TransitKey).filter_by(key_name="sign-key-a").one()
        assert key.encrypted_key_material_b64 and key.encrypted_key_material_b64 != key.public_key_b64


def test_key_existence_not_leaked_across_users(initialized):
    # Bug #1 regression: a name owned by another user and a name that does not exist at all
    # must produce identical responses, so an attacker cannot probe which key names exist.
    c=initialized; a=register_login(c); b=register_login(c,"bob@example.com")
    assert c.post("/api/v1/transit/keys",json={"key_name":"alice-key","key_usage":"ENCRYPT_DECRYPT"},headers=a).status_code==201
    owned=c.post("/api/v1/transit/encrypt",json={"key_name":"alice-key","plaintext_b64":b64(b"x")},headers=b)
    missing=c.post("/api/v1/transit/encrypt",json={"key_name":"does-not-exist","plaintext_b64":b64(b"x")},headers=b)
    assert owned.status_code == missing.status_code == 403
    assert owned.json()["error"]["code"] == missing.json()["error"]["code"] == "PERMISSION_DENIED"


def test_encrypt_decrypt_empty_plaintext_round_trip(initialized):
    # Bug #2 regression: empty plaintext yields a 28-byte blob (12B nonce + 16B tag) that must
    # still decrypt back to empty bytes.
    c=initialized; a=register_login(c)
    assert c.post("/api/v1/transit/keys",json={"key_name":"empty-key","key_usage":"ENCRYPT_DECRYPT"},headers=a).status_code==201
    enc=c.post("/api/v1/transit/encrypt",json={"key_name":"empty-key","plaintext_b64":""},headers=a).json()["data"]["ciphertext"]
    r=c.post("/api/v1/transit/decrypt",json={"ciphertext":enc},headers=a)
    assert r.status_code == 200 and base64.b64decode(r.json()["data"]["plaintext_b64"]) == b""


def test_encrypt_decrypt_text_and_json_round_trip(initialized):
    # Spec 2.2 acceptance: round-trip must hold across multiple data types (text, JSON, binary);
    # binary is covered above, this covers UTF-8 text and a serialized JSON document.
    c=initialized; a=register_login(c)
    assert c.post("/api/v1/transit/keys",json={"key_name":"roundtrip-key","key_usage":"ENCRYPT_DECRYPT"},headers=a).status_code==201
    text="Xin chào Mini Vault — tiếng Việt có dấu".encode()
    doc=json.dumps({"user":"alice","roles":["admin","dev"],"pin":1234}).encode()
    for raw in (text, doc):
        enc=c.post("/api/v1/transit/encrypt",json={"key_name":"roundtrip-key","plaintext_b64":b64(raw)},headers=a).json()["data"]["ciphertext"]
        out=c.post("/api/v1/transit/decrypt",json={"ciphertext":enc},headers=a).json()["data"]["plaintext_b64"]
        assert base64.b64decode(out)==raw


def test_transit_locked_returns_vault_locked(initialized):
    c=initialized; a=register_login(c)
    assert c.post("/api/v1/transit/keys",json={"key_name":"locked-key","key_usage":"ENCRYPT_DECRYPT"},headers=a).status_code==201
    c.post("/api/v1/vault/lock")
    r=c.post("/api/v1/transit/encrypt",json={"key_name":"locked-key","plaintext_b64":b64(b"x")},headers=a)
    assert r.status_code==423 and r.json()["error"]["code"]=="VAULT_LOCKED"
    assert c.post("/api/v1/transit/signing-keys",json={"key_name":"locked-sign","signing_algorithm":"ED25519"},headers=a).status_code==423


def test_verify_rejects_mismatched_signing_algorithm(initialized):
    # Spec 2.4 error case: verify() with a signing_algorithm other than the key's must be rejected.
    c=initialized; a=register_login(c)
    assert c.post("/api/v1/transit/signing-keys",json={"key_name":"algo-key","signing_algorithm":"ED25519"},headers=a).status_code==201
    msg=b64(b"hello vault")
    sig=c.post("/api/v1/transit/sign",json={"key_name":"algo-key","message_b64":msg,"message_type":"RAW"},headers=a).json()["data"]["signature_b64"]
    match=c.post("/api/v1/transit/verify",json={"key_name":"algo-key","message_b64":msg,"message_type":"RAW","signature_b64":sig,"signing_algorithm":"ED25519"},headers=a)
    assert match.json()["data"]["signature_valid"] is True
    mismatch=c.post("/api/v1/transit/verify",json={"key_name":"algo-key","message_b64":msg,"message_type":"RAW","signature_b64":sig,"signing_algorithm":"RSASSA_PKCS1_V1_5_SHA_256"},headers=a)
    assert mismatch.status_code==400 and mismatch.json()["error"]["code"]=="INVALID_SIGNING_ALGORITHM"
