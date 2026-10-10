import uuid

from sqlalchemy.orm import Session

from agents import tools  # the ONLY place in the project that should import the tools
from backend.models import (
    Agent, Resource, ActionRequest, AuditLog, RiskEvent, SecurityIncident,
    Permission, AgentPermission, utc_now,
)
from security.permissions import check_permission
from security.policy_engine import evaluate_policy
from security.risk_engine import calculate_risk
from security.threat_detection import detect_threat, ADMIN_ACTIONS
from security.behavior_monitor import monitor_behavior
from security.decision_engine import make_decision
from security.approval import create_approval_request
from security.audit_logger import log_action


# ---------- Settings (simulated organisation, edit freely) ----------
# Email domains or destination names that count as inside the organisation
INTERNAL_DESTINATIONS = {"company.com", "internal_storage"}
# Actions that are bulk operations by nature
BULK_ACTIONS = {"EXPORT_DATA"}
# Actions that move data somewhere, so their destination matters
DATA_MOVING_ACTIONS = {"SEND_EMAIL", "EXPORT_DATA"}
# How many past audit-log entries to analyze for behavior
HISTORY_LIMIT = 50


# ---------- Tool connections ----------
# Each runner turns the gateway's values into the arguments the matching
# simulated tool in agents/tools.py expects.
# payload holds optional tool-specific data (record, subject, body). It is only
# passed to the tool and is NEVER used by the security checks.

def run_read_file(resource, destination, payload):
    return tools.read_file(resource)


def run_read_database(resource, destination, payload):
    return tools.read_database(resource)


def run_write_database(resource, destination, payload):
    return tools.write_database(resource, payload.get("record", "(no record supplied)"))


def run_send_email(resource, destination, payload):
    return tools.send_email(
        destination or "(no recipient)",
        payload.get("subject", resource),
        payload.get("body", ""),
    )


def run_export_data(resource, destination, payload):
    return tools.export_data(resource, destination or "(no destination)")


# Maps an action name to the function that runs its simulated tool
TOOL_RUNNERS = {
    "READ_FILE": run_read_file,
    "READ_DATABASE": run_read_database,
    "WRITE_DATABASE": run_write_database,
    "SEND_EMAIL": run_send_email,
    "EXPORT_DATA": run_export_data,
}


# ---------- Helper functions ----------
def classify_destination(action, destination):
    """Return "INTERNAL" or "EXTERNAL". AgentShield decides this, not the agent."""
    if action not in DATA_MOVING_ACTIONS:
        return "INTERNAL"
    if not destination:
        return "EXTERNAL"  # unknown destination is treated as external (safer)
    # For an email address this gives the domain; for a plain name it gives the name itself
    name = destination.split("@")[-1].lower()
    return "INTERNAL" if name in INTERNAL_DESTINATIONS else "EXTERNAL"


def load_history(db: Session, agent_id: str):
    """The agent's recent past actions from the audit log, oldest first."""
    resource_names = {r.resource_id: r.name for r in db.query(Resource).all()}
    rows = (
        db.query(AuditLog)
        .filter(AuditLog.agent_id == agent_id)
        .order_by(AuditLog.timestamp.desc(), AuditLog.log_id.desc())
        .limit(HISTORY_LIMIT)
        .all()
    )
    rows.reverse()
    return [
        {
            "timestamp": row.timestamp,
            "action": row.action,
            "resource": resource_names.get(row.resource_id),
            "decision": row.decision,
        }
        for row in rows
    ]


def load_usual_resources(db: Session, agent_id: str):
    """The resources this agent has been granted permissions for."""
    rows = (
        db.query(Permission.resource)
        .join(AgentPermission, AgentPermission.permission_id == Permission.permission_id)
        .filter(AgentPermission.agent_id == agent_id)
        .distinct()
        .all()
    )
    return {row[0] for row in rows}


def block_early(db, agent_id, action, resource_row, reason, rule):
    """Block a request that cannot even be processed (unknown agent/resource, suspended agent)."""
    resource_id = resource_row.resource_id if resource_row else None
    log_action(db, None, agent_id, action, resource_id, None, "BLOCK", reason)
    return {
        "request_id": None, "decision": "BLOCK", "reason": reason, "rule": rule,
        "risk_score": None, "risk_level": None, "threat_type": None,
        "executed": False, "approval_required": False, "tool_result": None,
    }


# ---------- The gateway ----------
def handle_request(db: Session, agent_id: str, action: str, resource: str,
                   destination: str = None, input_text: str = None,
                   payload: dict = None) -> dict:
    """
    Every agent action goes through this function. Agents never call tools directly.

    agent_id    : must come from authentication, NOT from what the agent claims
    action      : "READ_FILE", "READ_DATABASE", "WRITE_DATABASE", "SEND_EMAIL" or "EXPORT_DATA"
    resource    : resource name, e.g. "public_research.pdf"
    destination : where data is going (email address or location), if any
    input_text  : the instruction text the agent was working from, if any
    payload     : optional tool data, e.g. {"record": ...} or {"subject": ..., "body": ...}
    """
    payload = payload or {}

    # --- Step 0: identify the agent and the resource ---
    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    resource_row = db.query(Resource).filter(Resource.name == resource).first()

    if agent is None:
        return block_early(db, agent_id, action, resource_row,
                           "Unknown agent", "unknown_agent")
    if agent.status != "ACTIVE":
        return block_early(db, agent_id, action, resource_row,
                           f"Agent is {agent.status}", "agent_not_active")
    if resource_row is None:
        return block_early(db, agent_id, action, None,
                           f"Unknown resource '{resource}'", "unknown_resource")

    # --- Step 1: record the request ---
    request_id = "REQ-" + uuid.uuid4().hex[:8].upper()
    action_request = ActionRequest(
        request_id=request_id, agent_id=agent_id, action=action,
        resource_id=resource_row.resource_id, status="PENDING",
    )
    db.add(action_request)
    db.commit()

    # The agent's history, including this request as the newest entry
    # (naive UTC time, to match what SQLite returns for older entries)
    history = load_history(db, agent_id)
    history.append({
        "timestamp": utc_now().replace(tzinfo=None),
        "action": action, "resource": resource, "decision": "PENDING",
    })

    # --- Steps 2-4: permission, policy, behavior ---
    permission_allowed = check_permission(db, agent_id, action, resource)
    policy = evaluate_policy(db, agent_id, action, resource)
    behavior = monitor_behavior(history, load_usual_resources(db, agent_id))

    # --- Step 5: risk (inputs are worked out here, never taken from the agent) ---
    destination_type = classify_destination(action, destination)
    risk = calculate_risk(
        sensitive_data=(resource_row.sensitivity_level == "HIGH"),
        external_destination=(destination_type == "EXTERNAL"),
        high_privilege=(agent.risk_level == "HIGH" or action in ADMIN_ACTIONS),
        bulk_operation=(action in BULK_ACTIONS),
        unusual_behavior=behavior["unusual_behavior"],
    )

    # --- Step 6: threat detection ---
    threat = detect_threat(action, resource, agent_id, {
        "has_permission": permission_allowed,
        "sensitivity": resource_row.sensitivity_level,
        "destination": destination_type,
        "recent_actions": [entry["action"] for entry in history[:-1]],
        "input_text": input_text,
    })

    # --- Step 7: final decision (precedence lives in decision_engine.PRECEDENCE) ---
    result = make_decision(permission_allowed, policy, risk, threat, behavior)
    final = result["decision"]
    reason = result["reason"]

    # --- Save the risk result and any incident ---
    db.add(RiskEvent(
        request_id=request_id, risk_score=risk["risk_score"],
        risk_level=risk["risk_level"], factors=", ".join(risk["factors"]),
    ))
    for found in threat["threats"]:   # one incident row per detected threat
        db.add(SecurityIncident(
            request_id=request_id, agent_id=agent_id,
            threat_type=found["threat_type"], severity=found["severity"],
            description=found["description"],
        ))
    db.commit()

    # The decision reason names only the most severe threat, so list ALL of them here
    audit_reason = reason
    if threat["threats"]:
        names = ", ".join(f"{t['threat_type']} ({t['severity']})" for t in threat["threats"])
        audit_reason += f" | Threats detected: {names}"
    log_action(db, request_id, agent_id, action, resource_row.resource_id,
               risk["risk_score"], final, audit_reason)

    # --- Step 8: act on the decision ---
    executed = False
    approval_required = False
    tool_result = None

    if final == "ALLOW":
        action_request.status = "ALLOWED"
        db.commit()
        runner = TOOL_RUNNERS.get(action)
        if runner is None:
            reason += " (no simulated tool is registered for this action)"
        else:
            try:
                tool_result = runner(resource, destination, payload)
            except Exception as error:  # e.g. a bad payload; report it instead of crashing
                tool_result = {"success": False, "error": str(error)}
            executed = True

    elif final == "REVIEW":
        create_approval_request(db, request_id)   # sets status to REVIEW
        approval_required = True                  # tool is NOT executed

    else:  # BLOCK: the tool is never touched
        action_request.status = "BLOCKED"
        db.commit()

    return {
        "request_id": request_id,
        "decision": final,
        "reason": reason,
        "rule": result["rule"],
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "threat_type": threat["threat_type"],
        "executed": executed,
        "approval_required": approval_required,
        "tool_result": tool_result,   # None unless the tool actually ran
    }