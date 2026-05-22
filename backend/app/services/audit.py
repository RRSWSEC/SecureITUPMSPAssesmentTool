from typing import Any

from sqlalchemy.orm import Session

from app.models import AuditLog, User


def write_audit(
    db: Session,
    *,
    action: str,
    user: User | None = None,
    entity_type: str | None = None,
    entity_id: str | int | None = None,
    client_id: int | None = None,
    assessment_id: int | None = None,
    details: dict[str, Any] | None = None,
    request_ip: str | None = None,
) -> None:
    db.add(
        AuditLog(
            actor_user_id=user.id if user else None,
            action=action,
            entity_type=entity_type,
            entity_id=str(entity_id) if entity_id is not None else None,
            client_id=client_id,
            assessment_id=assessment_id,
            details=details or {},
            request_ip=request_ip,
        )
    )
