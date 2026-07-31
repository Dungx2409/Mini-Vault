"""Generate the sample data files required by the assignment (section VI).

Produces, using the real application stack (no crypto is faked):
  data/samples/sample_vault.db      encrypted KV/Transit data file (SQLite)
  data/samples/transit_ciphertext.txt  one self-describing Transit ciphertext
  data/samples/transit_samples.json    full encrypt/decrypt + sign/verify round-trip material
  data/logs/audit_log_sample.txt       audit trail including DENIED cross-user attempts

Run from anywhere: python scripts/make_samples.py
Credentials used here are documented in data/samples/README.md.
"""
import base64
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
sys.path.insert(0, str(ROOT))
SAMPLES, LOGS = ROOT / "data" / "samples", ROOT / "data" / "logs"
SAMPLES.mkdir(parents=True, exist_ok=True)
LOGS.mkdir(parents=True, exist_ok=True)
DB_FILE = SAMPLES / "sample_vault.db"
if DB_FILE.exists():
    DB_FILE.unlink()
os.environ["DATABASE_URL"] = "sqlite:///./data/samples/sample_vault.db"

import asyncio
import httpx
from app.database import Base, SessionLocal, engine
from app.main import app
from app.models import AuditLog

MASTER = "Sample-Master-Passphrase-2026!"
ALICE, ALICE_PW = "alice@example.com", "AliceSample@2026"
BOB, BOB_PW = "bob@example.com", "BobSample@2026!!"
DB_SECRET = {"username": "admin", "password": "S3cr3t-DB-P@ssw0rd", "host": "db.internal.local", "port": 5432}
API_SECRET = {"api_key": "sk-sample-1234567890abcdef"}
CARD_PLAINTEXT = "Thông tin thẻ: 4111-1111-1111-1111"
SIGN_MESSAGE = "Mini Vault sample document v1"


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


async def main() -> None:
    Base.metadata.create_all(engine)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://sample") as c:
        assert (await c.post("/api/v1/vault/init", json={
            "master_passphrase": MASTER, "confirm_master_passphrase": MASTER})).status_code == 201
        assert (await c.post("/api/v1/vault/unlock", json={"master_passphrase": MASTER})).status_code == 200
        for email, pw in ((ALICE, ALICE_PW), (BOB, BOB_PW)):
            assert (await c.post("/api/v1/auth/register", json={
                "email": email, "passphrase": pw, "confirm_passphrase": pw})).status_code == 201
        alice = {"Authorization": "Bearer " + (await c.post("/api/v1/auth/login", json={
            "email": ALICE, "passphrase": ALICE_PW})).json()["data"]["access_token"]}
        bob = {"Authorization": "Bearer " + (await c.post("/api/v1/auth/login", json={
            "email": BOB, "passphrase": BOB_PW})).json()["data"]["access_token"]}

        # KV: two encrypted secrets for Alice, then Bob's denied cross-user read (audited).
        assert (await c.put(f"/api/v1/kv/secret/{ALICE}/database",
                            json={"data": DB_SECRET}, headers=alice)).status_code == 200
        assert (await c.put(f"/api/v1/kv/secret/{ALICE}/payment-gateway",
                            json={"data": API_SECRET}, headers=alice)).status_code == 200
        assert (await c.get(f"/api/v1/kv/secret/{ALICE}/database", headers=bob)).status_code == 403

        # Transit: encrypt/decrypt round-trip, Bob's denied use of Alice's key (audited).
        assert (await c.post("/api/v1/transit/keys", json={
            "key_name": "payment-key", "key_usage": "ENCRYPT_DECRYPT"}, headers=alice)).status_code == 201
        plaintext_b64 = b64(CARD_PLAINTEXT.encode())
        ciphertext = (await c.post("/api/v1/transit/encrypt", json={
            "key_name": "payment-key", "plaintext_b64": plaintext_b64},
            headers=alice)).json()["data"]["ciphertext"]
        decrypted = (await c.post("/api/v1/transit/decrypt", json={"ciphertext": ciphertext},
                                  headers=alice)).json()["data"]["plaintext_b64"]
        assert decrypted == plaintext_b64
        assert (await c.post("/api/v1/transit/encrypt", json={
            "key_name": "payment-key", "plaintext_b64": plaintext_b64}, headers=bob)).status_code == 403

        # Transit: sign/verify round-trip.
        assert (await c.post("/api/v1/transit/signing-keys", json={
            "key_name": "document-signing-key", "signing_algorithm": "ED25519"},
            headers=alice)).status_code == 201
        message_b64 = b64(SIGN_MESSAGE.encode())
        signed = (await c.post("/api/v1/transit/sign", json={
            "key_name": "document-signing-key", "message_b64": message_b64,
            "message_type": "RAW"}, headers=alice)).json()["data"]
        verified = (await c.post("/api/v1/transit/verify", json={
            "key_name": "document-signing-key", "message_b64": message_b64, "message_type": "RAW",
            "signature_b64": signed["signature_b64"]}, headers=alice)).json()["data"]
        assert verified["signature_valid"] is True

    (SAMPLES / "transit_ciphertext.txt").write_text(ciphertext + "\n")
    (SAMPLES / "transit_samples.json").write_text(json.dumps({
        "encrypt_decrypt": {"key_name": "payment-key", "plaintext_b64": plaintext_b64,
                            "ciphertext": ciphertext},
        "sign_verify": {"key_name": "document-signing-key", "message_b64": message_b64,
                        "message_type": "RAW", "signature_b64": signed["signature_b64"],
                        "signing_algorithm": signed["signing_algorithm"]},
    }, indent=2) + "\n")
    with SessionLocal() as db:
        rows = db.query(AuditLog).order_by(AuditLog.id).all()
        (LOGS / "audit_log_sample.txt").write_text("".join(
            f"{r.created_at.isoformat()} | {r.requester_email} | {r.action} "
            f"{r.resource_type} {r.resource_identifier} | {r.result}\n" for r in rows))

    # Encrypted-at-rest check: no secret plaintext may appear anywhere in the stored DB bytes.
    blob = DB_FILE.read_bytes()
    for needle in (DB_SECRET["password"], API_SECRET["api_key"], CARD_PLAINTEXT, MASTER,
                   ALICE_PW, BOB_PW, SIGN_MESSAGE):
        assert needle.encode() not in blob, f"plaintext leaked to disk: {needle!r}"
    print(f"OK: {DB_FILE.relative_to(ROOT)} ({len(blob)} bytes), "
          f"{len(rows)} audit rows, no plaintext on disk.")


if __name__ == "__main__":
    asyncio.run(main())
