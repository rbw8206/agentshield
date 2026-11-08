import hmac
import os
from typing import List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.database import get_db
from security.approval import (
    review_request, list_pending_approvals,
    ApprovalNotFound, NotAdmin, WrongStatus,
)
from security.tool_gateway import execute_approved_request


# ---------- Admin protection (temporary, until real login/JWT exists) ----------
# Agents use the same API, so without this an agent could approve its own request.
# Set the secret before starting the server, e.g. in PowerShell:
#   $env:AGENTSHIELD_ADMIN_KEY = "choose-a-long-random-secret"
# Never give this key to an agent.
def require_admin_key(x_admin_key: Optional[str] = Header(default=None)):
    expected = os.environ.get("AGENTSHIELD_ADMIN_KEY")
    if not expected:
        raise HTTPException(503, "Approvals are disabled: AGENTSHIELD_ADMIN_KEY is not set")
    if not x_admin_key or not hmac.compare_digest(x_admin_key.encode(), expected.encode()):
        raise HTTPException(401, "Invalid or missing admin key")


router = APIRouter(
    prefix="/approvals", tags=["approvals"], dependencies=[Depends(require_admin_key)]
)


# ---------- Request and response shapes ----------
class PendingApprovalOut(BaseModel):
    request_id: str
    agent_id: str
    action: str
    resource: str
    sensitivity: Optional[str] = None
    destination: Optional[str] = None
    risk_score: Optional[int] = None
    risk_level: Optional[str] = None
    risk_factors: Optional[str] = None
    reason: Optional[str] = None
    requested_at: Optional[str] = None


class DecisionIn(BaseModel):
    admin_id: int                    # must be a user whose role is "admin"
    reason: Optional[str] = None


class DecisionOut(BaseModel):
    request_id: str
    decision: str                    # APPROVED or REJECTED
    status: str                      # final status: EXECUTED, EXECUTION_FAILED or REJECTED
    executed: bool
    tool_result: Optional[dict] = None


def to_http_error(error: ValueError) -> HTTPException:
    if isinstance(error, ApprovalNotFound):
        return HTTPException(404, str(error))
    if isinstance(error, NotAdmin):
        return HTTPException(403, str(error))
    return HTTPException(409, str(error))      # WrongStatus: already decided / executed


# ---------- Endpoints ----------
@router.get("/pending", response_model=List[PendingApprovalOut])
def pending_approvals(db: Session = Depends(get_db)):
    """Requests waiting for a human decision, oldest first."""
    return list_pending_approvals(db)


@router.post("/{request_id}/approve", response_model=DecisionOut)
def approve_request(request_id: str, body: DecisionIn, db: Session = Depends(get_db)):
    """Approve a held request and run it (once)."""
    try:
        review_request(db, request_id, body.admin_id, "APPROVED", body.reason)
        outcome = execute_approved_request(db, request_id)
    except (ApprovalNotFound, NotAdmin, WrongStatus) as error:
        raise to_http_error(error)
    return {"request_id": request_id, "decision": "APPROVED", **outcome}


@router.post("/{request_id}/reject", response_model=DecisionOut)
def reject_request(request_id: str, body: DecisionIn, db: Session = Depends(get_db)):
    """Reject a held request. It will never run."""
    try:
        review_request(db, request_id, body.admin_id, "REJECTED", body.reason)
    except (ApprovalNotFound, NotAdmin, WrongStatus) as error:
        raise to_http_error(error)
    return {"request_id": request_id, "decision": "REJECTED", "status": "REJECTED",
            "executed": False, "tool_result": None}
