import json

from sqlalchemy.orm import Session

from backend.models import Policy, Resource

VALID_DECISIONS = ("ALLOW", "REVIEW", "BLOCK")


def condition_matches(condition: dict, request: dict) -> bool:
    """A policy matches only if every key in its condition equals the request's value."""
    for key, expected in condition.items():
        if request.get(key) != expected:   # unknown keys never match
            return False
    return True


def evaluate_policy(db: Session, agent_id: str, action: str, resource: str) -> dict:
    """
    Check the request against all enabled policies, highest priority first.
    The first matching policy wins.

    Returns a dict:
      {"decision": "ALLOW" | "REVIEW" | "BLOCK" | "NO_MATCH",
       "policy": policy name or None,
       "reason": short explanation}
    """
    # Sensitivity comes from the Resources table, never from the agent
    resource_row = db.query(Resource).filter(Resource.name == resource).first()
    sensitivity = resource_row.sensitivity_level if resource_row else None

    request = {
        "agent_id": agent_id,
        "action": action,
        "resource": resource,
        "sensitivity": sensitivity,
    }

    policies = (
        db.query(Policy)
        .filter(Policy.enabled == True)  # noqa: E712
        .order_by(Policy.priority.desc(), Policy.policy_id)
        .all()
    )

    for policy in policies:
        # Skip policies whose condition or action is invalid
        try:
            condition = json.loads(policy.condition)
        except (TypeError, ValueError):
            continue
        if not isinstance(condition, dict):
            continue
        decision = (policy.action or "").upper()
        if decision not in VALID_DECISIONS:
            continue

        if condition_matches(condition, request):
            return {
                "decision": decision,
                "policy": policy.name,
                "reason": f"Matched policy '{policy.name}' (priority {policy.priority})",
            }

    return {"decision": "NO_MATCH", "policy": None, "reason": "No enabled policy matched this request"}