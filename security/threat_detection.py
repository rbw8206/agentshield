# Actions that only an administrator should ever perform
ADMIN_ACTIONS = {
    "CREATE_USER", "DELETE_USER", "CHANGE_PERMISSIONS",
    "GRANT_PERMISSION", "MODIFY_POLICY", "DISABLE_POLICY", "DELETE_AUDIT_LOG",
}

# Resources that agents should never modify
ADMIN_RESOURCES = {"users", "permissions", "policies", "audit_logs", "agent_permissions"}

# Actions that move data out of the system
EXFILTRATION_ACTIONS = {"EXPORT_DATA", "SEND_EMAIL"}

# Phrases commonly used to try to override an agent's rules (lowercase)
INJECTION_PHRASES = [
    "ignore all security",
    "ignore previous instructions",
    "ignore all previous",
    "ignore your rules",
    "disregard your instructions",
    "bypass security",
    "override security",
    "disable security",
    "you are now an admin",
    "pretend you have permission",
]

# Same action repeated this many times in the recent history counts as tool abuse
TOOL_ABUSE_LIMIT = 5

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def detect_threat(action, resource, agent_id, context=None):
    """
    Run simple rule-based checks on one action request.

    Optional context keys (filled in by AgentShield, NOT by the agent):
      has_permission : bool   - result from the permission engine
      sensitivity    : str    - "LOW" / "MEDIUM" / "HIGH", from the Resources table
      destination    : str    - "INTERNAL" or "EXTERNAL"
      recent_actions : list   - this agent's recent action names (from the audit log)
      input_text     : str    - the instruction text the agent was given

    Returns a dict:
      {"threat_detected": bool, "threat_type": str or None,
       "severity": str or None, "description": str,
       "all_threats": list of every threat type found}
    """
    context = context or {}
    findings = []  # each item: (threat_type, severity, description)

    # 1. Privilege escalation: an agent attempting administrator-level work
    if action in ADMIN_ACTIONS or (action == "WRITE_DATABASE" and resource in ADMIN_RESOURCES):
        findings.append((
            "PRIVILEGE_ESCALATION", "CRITICAL",
            f"{agent_id} attempted administrator-level action {action} on {resource}",
        ))

    # 2. Data exfiltration: sensitive or external data movement
    if action in EXFILTRATION_ACTIONS:
        sensitivity = context.get("sensitivity")
        destination = context.get("destination")
        if sensitivity == "HIGH" or (destination == "EXTERNAL" and sensitivity == "MEDIUM"):
            findings.append((
                "DATA_EXFILTRATION", "HIGH",
                f"{agent_id} attempted {action} on {sensitivity}-sensitivity data "
                f"({resource}), destination: {destination or 'unknown'}",
            ))

    # 3. Prompt injection: instruction text that tries to override the rules
    input_text = str(context.get("input_text") or "").lower()
    for phrase in INJECTION_PHRASES:
        if phrase in input_text:
            findings.append((
                "PROMPT_INJECTION", "HIGH",
                f"Input contains an attempt to override security rules: '{phrase}'",
            ))
            break

    # 4. Unauthorized access: the permission engine already said no
    if context.get("has_permission") is False:
        findings.append((
            "UNAUTHORIZED_ACCESS", "HIGH",
            f"{agent_id} has no permission for {action} on {resource}",
        ))

    # 5. Tool abuse: the same action repeated too many times
    recent_actions = context.get("recent_actions") or []
    repeat_count = recent_actions.count(action)
    if repeat_count >= TOOL_ABUSE_LIMIT:
        findings.append((
            "TOOL_ABUSE", "MEDIUM",
            f"{agent_id} repeated {action} {repeat_count} times recently",
        ))

    if not findings:
        return {
            "threat_detected": False,
            "threat_type": None,
            "severity": None,
            "description": "No threat detected",
            "all_threats": [],
        }

    # Report the most severe finding (ties go to the first one found)
    top = max(findings, key=lambda f: SEVERITY_RANK[f[1]])
    return {
        "threat_detected": True,
        "threat_type": top[0],
        "severity": top[1],
        "description": top[2],
        "all_threats": [f[0] for f in findings],
    }