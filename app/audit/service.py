from sqlalchemy import inspect, text
from sqlalchemy.orm import Session
from app.models import AuditLog
import threading
import hashlib
import base64

_audit_lock = threading.Lock()


def ensure_schema(engine) -> None:
    # Base.metadata.create_all() chi tao bang con thieu, khong tu them cot moi vao bang da
    # ton tai. Neu audit_logs da co tu truoc khi co hash-chain, phai tu ALTER TABLE roi backfill
    # lai hash cho cac dong cu, neu khong /audit/verify se bao "tamper" gia voi du lieu cu.
    inspector = inspect(engine)
    if "audit_logs" not in inspector.get_table_names():
        return
    existing = {c["name"] for c in inspector.get_columns("audit_logs")}
    if "previous_hash_b64" in existing and "hash_b64" in existing:
        return
    with engine.begin() as conn:
        if "previous_hash_b64" not in existing:
            conn.execute(text("ALTER TABLE audit_logs ADD COLUMN previous_hash_b64 VARCHAR(64)"))
        if "hash_b64" not in existing:
            conn.execute(text("ALTER TABLE audit_logs ADD COLUMN hash_b64 VARCHAR(64)"))
        rows = conn.execute(text(
            "SELECT id, requester_email, action, resource_identifier, result "
            "FROM audit_logs ORDER BY id ASC")).fetchall()
        prev_hash = "GENESIS"
        for row in rows:
            data_str = f"{row.id}|{prev_hash}|{row.requester_email}|{row.action}|{row.resource_identifier}|{row.result}"
            new_hash = base64.b64encode(hashlib.sha256(data_str.encode()).digest()).decode()
            conn.execute(text("UPDATE audit_logs SET previous_hash_b64 = :prev, hash_b64 = :h WHERE id = :id"),
                        {"prev": prev_hash, "h": new_hash, "id": row.id})
            prev_hash = new_hash


def audit(db: Session, email: str, action: str, resource_type: str,
          identifier: str, result: str, client_ip: str | None = None) -> None:
    with _audit_lock:
        # Lay log cuoi cung de lay previous_hash
        last_log = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
        prev_hash = last_log.hash_b64 if last_log else "GENESIS"

        new_log = AuditLog(requester_email=email, action=action, resource_type=resource_type,
                           resource_identifier=identifier, result=result, client_ip=client_ip,
                           previous_hash_b64=prev_hash)
        db.add(new_log)
        db.flush() # Cap phat ID va created_at

        # Tinh toan ma bam SHA-256 (Khong bao gom created_at de tranh loi parse format datetime)
        data_str = f"{new_log.id}|{prev_hash}|{email}|{action}|{identifier}|{result}"
        h = hashlib.sha256(data_str.encode()).digest()
        new_log.hash_b64 = base64.b64encode(h).decode()

        db.commit()

