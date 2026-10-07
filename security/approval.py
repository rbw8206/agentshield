from sqlalchemy.orm import Session

from backend.models import Approval, ActionRequest, User

VALID_DECISIONS = ("APPROVED", "REJECTED")


def create_approval_request(db: Session, request_id: str) -> ActionRequest:
    """
    Mark an action request as waiting for human approval (status = "REVIEW").
    Call this when the Decision Engine returns REVIEW.
    """
    action_request = (
        db.query(ActionRequest).filter(ActionRequest.request_id == request_id).first()
    )
    if action_request is None:
        raise ValueError(f"Action request '{request_id}' does not exist")

    if action_request.status in ("APPROVED", "REJECTED"):
        raise ValueError(f"Request '{request_id}' has already been decided")

    action_request.status = "REVIEW"
    db.commit()
    db.refresh(action_request)
    return action_request


def review_request(db: Session, request_id: str, admin_id: int,
                   decision: str, reason: str = None) -> Approval:
    """
    Record an administrator's decision on a request that is waiting for approval.
    decision must be "APPROVED" or "REJECTED".
    """
    decision = (decision or "").upper()
    if decision not in VALID_DECISIONS:
        raise ValueError("Decision must be 'APPROVED' or 'REJECTED'")

    # Only administrators may decide (SQLite does not enforce foreign keys, so check here)
    admin = db.query(User).filter(User.user_id == admin_id).first()
    if admin is None or admin.role != "admin":
        raise ValueError("Only an administrator can approve or reject requests")

    action_request = (
        db.query(ActionRequest).filter(ActionRequest.request_id == request_id).first()
    )
    if action_request is None:
        raise ValueError(f"Action request '{request_id}' does not exist")

    # Only requests waiting for review can be decided, and only once
    if action_request.status != "REVIEW":
        raise ValueError(
            f"Request '{request_id}' is not waiting for approval (status: {action_request.status})"
        )

    approval = Approval(
        request_id=request_id,
        admin_id=admin_id,
        decision=decision,
        reason=reason,
    )
    db.add(approval)

    # Keep the request's status in sync with the decision
    action_request.status = decision

    db.commit()  # saves both changes together
    db.refresh(approval)
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