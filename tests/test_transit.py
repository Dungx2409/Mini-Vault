import base64
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
