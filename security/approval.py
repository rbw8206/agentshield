from sqlalchemy.orm import Session
 
from backend.models import (
    Approval, ActionRequest, User, Resource, RiskEvent, AuditLog, PendingAction,
)
from security.audit_logger import log_action
 
VALID_DECISIONS = ("APPROVED", "REJECTED")
 
 
# These are ValueError subclasses, so existing "except ValueError" code keeps working.
# The API uses them to pick the right HTTP status (404 / 403 / 409).
class ApprovalNotFound(ValueError):
    pass
 
 
class NotAdmin(ValueError):
    pass
 
 
class WrongStatus(ValueError):
    pass
 
 
def log_workflow_event(db: Session, action_request: ActionRequest, decision: str, reason: str):
    """Write an audit-log row for a step after the original decision (approval, execution...)."""
    risk_event = db.query(RiskEvent).filter(
        RiskEvent.request_id == action_request.request_id
    ).first()
    return log_action(
        db, action_request.request_id, action_request.agent_id, action_request.action,
        action_request.resource_id, risk_event.risk_score if risk_event else None,
        decision, reason,
    )
 
 
def create_approval_request(db: Session, request_id: str) -> ActionRequest:
    """
    Mark an action request as waiting for human approval (status = "REVIEW").
    Call this when the Decision Engine returns REVIEW.
    Only a brand-new (PENDING) request can be put on hold, so an approved,
    executed or blocked request can never be re-opened.
    """
    action_request = (
        db.query(ActionRequest).filter(ActionRequest.request_id == request_id).first()
    )
    if action_request is None:
        raise ApprovalNotFound(f"Action request '{request_id}' does not exist")
 
    if action_request.status not in ("PENDING", "REVIEW"):
        raise WrongStatus(
            f"Request '{request_id}' cannot be put on hold (status: {action_request.status})"
        )
 
    action_request.status = "REVIEW"
    db.commit()
    db.refresh(action_request)
    return action_request
 
 
def review_request(db: Session, request_id: str, admin_id: int,
                   decision: str, reason: str = None) -> Approval:
    """
    Record an administrator's decision on a request that is waiting for approval.
    decision must be "APPROVED" or "REJECTED". The decision is also written to the audit log.
    This does NOT run the tool; see execute_approved_request in tool_gateway.py.
    """
    decision = (decision or "").upper()
    if decision not in VALID_DECISIONS:
        raise ValueError("Decision must be 'APPROVED' or 'REJECTED'")
 
    # Only administrators may decide (SQLite does not enforce foreign keys, so check here)
    admin = db.query(User).filter(User.user_id == admin_id).first()
    if admin is None or admin.role != "admin":
        raise NotAdmin("Only an administrator can approve or reject requests")
 
    action_request = (
        db.query(ActionRequest).filter(ActionRequest.request_id == request_id).first()
    )
    if action_request is None:
        raise ApprovalNotFound(f"Action request '{request_id}' does not exist")
 
    if action_request.status != "REVIEW":
        raise WrongStatus(
            f"Request '{request_id}' is not waiting for approval (status: {action_request.status})"
        )
 
    # Atomic step: the database only lets ONE caller move the request out of REVIEW,
    # so two admins deciding at the same moment cannot both succeed.
    claimed = (
        db.query(ActionRequest)
        .filter(ActionRequest.request_id == request_id, ActionRequest.status == "REVIEW")
        .update({"status": decision}, synchronize_session=False)
    )
    if claimed == 0:
        db.rollback()
        raise WrongStatus(f"Request '{request_id}' was already decided")
 
    approval = Approval(
        request_id=request_id,
        admin_id=admin_id,
        decision=decision,
        reason=reason,
    )
    db.add(approval)
    db.commit()          # saves the status change and the approval record together
    db.refresh(approval)
 
    log_workflow_event(
        db, action_request, decision,
        f"{decision} by admin {admin_id}" + (f": {reason}" if reason else ""),
    )
    return approval
 
 
def get_approval(db: Session, request_id: str):
    """
    Return the approval record for a request, or None if no decision has been made yet.
    """
    return (
        db.query(Approval)
        .filter(Approval.request_id == request_id)
        .order_by(Approval.approval_id.desc())
        .first()
    )
 
 
def list_pending_approvals(db: Session) -> list:
    """All requests currently waiting for a human decision, oldest first."""
    rows = (
        db.query(ActionRequest, Resource)
        .join(Resource, Resource.resource_id == ActionRequest.resource_id)
        .filter(ActionRequest.status == "REVIEW")
        .order_by(ActionRequest.timestamp, ActionRequest.request_id)
        .all()
    )
 
    pending = []
    for action_request, resource in rows:
        rid = action_request.request_id
        risk = db.query(RiskEvent).filter(RiskEvent.request_id == rid).first()
        held = db.query(PendingAction).filter(PendingAction.request_id == rid).first()
        review_log = (
            db.query(AuditLog)
            .filter(AuditLog.request_id == rid, AuditLog.decision == "REVIEW")
            .order_by(AuditLog.log_id).first()
        )
        pending.append({
            "request_id": rid,
            "agent_id": action_request.agent_id,
            "action": action_request.action,
            "resource": resource.name,
            "sensitivity": resource.sensitivity_level,
            "destination": held.destination if held else None,
            "risk_score": risk.risk_score if risk else None,
            "risk_level": risk.risk_level if risk else None,
            "risk_factors": risk.factors if risk else None,
            "reason": review_log.reason if review_log else None,
            "requested_at": action_request.timestamp.isoformat() if action_request.timestamp else None,
        })
    return pending
 