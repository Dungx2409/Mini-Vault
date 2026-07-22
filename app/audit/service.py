from sqlalchemy.orm import Session
from app.models import AuditLog


def audit(db: Session, email: str, action: str, resource_type: str,
          identifier: str, result: str, client_ip: str | None = None) -> None:
    db.add(AuditLog(requester_email=email, action=action, resource_type=resource_type,
                    resource_identifier=identifier, result=result, client_ip=client_ip))
    db.commit()

