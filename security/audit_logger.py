from sqlalchemy.orm import Session

from backend.models import AuditLog, utc_now


def log_action(db: Session, request_id, agent_id, action, resource_id,
               risk_score, decision, reason) -> AuditLog:
    """
    Save one record in the audit_logs table and return it.
    The timestamp is set automatically to the current UTC time.
    """
    log = AuditLog(
        request_id=request_id,
        agent_id=agent_id,
        action=action,
        resource_id=resource_id,
        risk_score=risk_score,
        decision=decision,
        reason=reason,
        timestamp=utc_now(),
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    return log