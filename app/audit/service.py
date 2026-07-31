from sqlalchemy.orm import Session
from app.models import AuditLog
import threading
import hashlib
import base64

_audit_lock = threading.Lock()

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

