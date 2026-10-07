# Settings: adjust these during testing
BURST_WINDOW_SECONDS = 60   # look at the last 60 seconds of activity
BURST_LIMIT = 20            # this many actions inside the window is "too many"
RECENT_COUNT = 10           # how many of the latest actions to examine
DENIAL_LIMIT = 3            # this many BLOCKs among the recent actions is suspicious

# An ordered pattern that looks like stealing data (read, then export, then send out)
SUSPICIOUS_SEQUENCE = ["READ_DATABASE", "EXPORT_DATA", "SEND_EMAIL"]

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


def contains_sequence(actions, pattern):
    """True if the pattern's actions appear in order (other actions may sit between them)."""
    position = 0
    for action in actions:
        if action == pattern[position]:
            position += 1
            if position == len(pattern):
                return True
    return False


def monitor_behavior(action_history, usual_resources=None):
    """
    Look at one agent's recent action history and decide if its behavior is unusual.

    action_history: a list of dicts, OLDEST first. Each dict has:
        "timestamp" : a datetime
        "action"    : e.g. "READ_FILE"
        "resource"  : e.g. "public_research.pdf"
        "decision"  : e.g. "ALLOW", "REVIEW" or "BLOCK"
    (Build this from the audit log, never from anything the agent sends.)

    usual_resources: optional set of resources this agent normally uses.
        If given, access to anything outside it is flagged.

    Returns a dict:
      {"unusual_behavior": True/False, "reason": text, "severity": "LOW"/"MEDIUM"/"HIGH" or None}
    """
    if not action_history:
        return {"unusual_behavior": False, "reason": "No history to analyze", "severity": None}

    findings = []  # each item: (severity, reason)
    recent = action_history[-RECENT_COUNT:]

    # 1. Too many actions in a short period
    # The newest timestamp is the reference point, so no clock/timezone issues
    timestamps = [entry["timestamp"] for entry in action_history if entry.get("timestamp")]
    if timestamps:
        newest = max(timestamps)
        in_window = [
            t for t in timestamps
            if (newest - t).total_seconds() <= BURST_WINDOW_SECONDS
        ]
        if len(in_window) >= BURST_LIMIT:
            findings.append((
                "MEDIUM",
                f"{len(in_window)} actions within {BURST_WINDOW_SECONDS} seconds",
            ))

    # 2. Repeated denied actions
    denied = sum(1 for entry in recent if entry.get("decision") == "BLOCK")
    if denied >= DENIAL_LIMIT:
        findings.append((
            "HIGH",
            f"{denied} blocked requests among the last {len(recent)} actions",
        ))

    # 3. Unusual action/resource combinations
    recent_actions = [entry.get("action") for entry in recent]
    if contains_sequence(recent_actions, SUSPICIOUS_SEQUENCE):
        findings.append((
            "HIGH",
            "Suspicious sequence: " + " -> ".join(SUSPICIOUS_SEQUENCE),
        ))

    if usual_resources:
        odd = {
            entry.get("resource") for entry in recent
            if entry.get("resource") not in usual_resources
        }
        if odd:
            findings.append((
                "MEDIUM",
                "Access to resources outside the agent's usual set: " + ", ".join(sorted(odd)),
            ))

    if not findings:
        return {"unusual_behavior": False, "reason": "Behavior looks normal", "severity": None}

    top_severity = max((f[0] for f in findings), key=lambda s: SEVERITY_RANK[s])
    return {
        "unusual_behavior": True,
        "reason": "; ".join(f[1] for f in findings),
        "severity": top_severity,
    }