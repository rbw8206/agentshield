from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import Resource
from security.tool_gateway import handle_request

router = APIRouter(prefix="/actions", tags=["actions"])


# ---------- Request and response shapes ----------
class ActionContext(BaseModel):
    """Optional extra information. Any other keys the agent sends are ignored."""
    destination: Optional[str] = None   # where data is going, e.g. an email address
    input_text: Optional[str] = None    # the instruction the agent was working from
    payload: Optional[dict] = None      # tool data, e.g. {"record": ...} or {"subject": ..., "body": ...}


class ActionRequestIn(BaseModel):
    agent_id: str = Field(..., min_length=1)
    action: str = Field(..., min_length=1)   # e.g. "READ_FILE"
    resource_id: int
    context: Optional[ActionContext] = None


class ActionResponse(BaseModel):
    request_id: Optional[str] = None
    decision: str                            # ALLOW, REVIEW or BLOCK
    reason: str
    rule: Optional[str] = None
    risk_score: Optional[int] = None
    risk_level: Optional[str] = None
    threat_type: Optional[str] = None
    executed: bool
    approval_required: bool
    tool_result: Optional[dict] = None       # only filled when the tool actually ran


# ---------- Endpoint ----------
@router.post("/request", response_model=ActionResponse)
def submit_action_request(request: ActionRequestIn, db: Session = Depends(get_db)):
    """An agent submits an action. The Tool Gateway does ALL the security work."""

    # Translate resource_id into the resource name the gateway expects.
    # If the ID does not exist, pass a placeholder so the gateway blocks and logs it.
    resource_row = db.query(Resource).filter(Resource.resource_id == request.resource_id).first()
    resource_name = resource_row.name if resource_row else f"resource_id:{request.resource_id}"

    context = request.context or ActionContext()

    return handle_request(
        db,
        agent_id=request.agent_id,
        action=request.action,
        resource=resource_name,
        destination=context.destination,
        input_text=context.input_text,
        payload=context.payload,
    )