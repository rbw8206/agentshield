from sqlalchemy.orm import Session

from backend.models import Permission, AgentPermission


def check_permission(db: Session, agent_id: str, action: str, resource: str) -> bool:
    """
    Return True if the agent has been assigned a permission that matches
    BOTH the action and the resource. Otherwise return False.

    Unknown agents, unknown actions and unknown resources all return False,
    so anything that isn't explicitly granted is denied.
    """
    match = (
        db.query(Permission)
        .join(AgentPermission, AgentPermission.permission_id == Permission.permission_id)
        .filter(
            AgentPermission.agent_id == agent_id,
            Permission.action == action,
            Permission.resource == resource,
        )
        .first()
    )

    return match is not None