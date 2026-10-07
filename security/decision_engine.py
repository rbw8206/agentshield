# The Decision Engine does NOT query the database or run any checks itself.
# It only combines results that the other security modules already produced.


# ---------- Rules ----------
# Each rule looks at the combined inputs and returns either:
#   (decision, reason)  -> this rule has an opinion
#   None                -> this rule does not apply, try the next one

def rule_permission_denied(inputs):
    # Anything other than an explicit True is treated as "no permission" (deny by default)
    if inputs["permission_allowed"] is not True:
        return "BLOCK", "Agent does not have permission for this action on this resource"
    return None


def rule_policy_block(inputs):
    policy = inputs["policy"]
    if policy.get("decision") == "BLOCK":
        return "BLOCK", f"Blocked by policy: {policy.get('reason')}"
    return None


def rule_threat_high(inputs):
    threat = inputs["threat"]
    if threat.get("threat_detected") and threat.get("severity") in ("HIGH", "CRITICAL"):
        return "BLOCK", (
            f"High-severity threat detected ({threat.get('threat_type')}): "
            f"{threat.get('description')}"
        )
    return None


def rule_risk_high(inputs):
    risk = inputs["risk"]
    if risk.get("risk_level") == "HIGH":
        return "BLOCK", f"Risk level HIGH (score {risk.get('risk_score')})"
    return None


def rule_policy_review(inputs):
    policy = inputs["policy"]
    if policy.get("decision") == "REVIEW":
        return "REVIEW", f"Policy requires review: {policy.get('reason')}"
    return None


def rule_risk_medium(inputs):
    risk = inputs["risk"]
    if risk.get("risk_level") == "MEDIUM":
        return "REVIEW", f"Risk level MEDIUM (score {risk.get('risk_score')})"
    return None


def rule_behavior_high(inputs):
    behavior = inputs["behavior"]
    if behavior.get("unusual_behavior") and behavior.get("severity") == "HIGH":
        return "REVIEW", f"Unusual agent behavior: {behavior.get('reason')}"
    return None


def rule_risk_missing(inputs):
    # Safety net: if no risk result was supplied, do not silently allow
    if not inputs["risk"].get("risk_level"):
        return "REVIEW", "Risk was not evaluated, so the request needs review"
    return None


# ---------- Precedence ----------
# The FIRST rule in this list that returns a result decides the outcome.
# To change which check wins (for example Policy vs Risk), just reorder the lines.
# To remove a check completely, delete its line.
PRECEDENCE = [
    ("permission_denied", rule_permission_denied),
    ("policy_block",      rule_policy_block),
    ("threat_high",       rule_threat_high),
    ("risk_high",         rule_risk_high),
    ("policy_review",     rule_policy_review),
    ("risk_medium",       rule_risk_medium),
    ("behavior_high",     rule_behavior_high),
    ("risk_missing",      rule_risk_missing),
]


def make_decision(permission_allowed, policy_result, risk_result,
                  threat_result, behavior_result):
    """
    Combine the results of all security checks into one final decision.

    permission_allowed : True / False  (from check_permission)
    policy_result      : dict from evaluate_policy
    risk_result        : dict from calculate_risk
    threat_result      : dict from detect_threat
    behavior_result    : dict from monitor_behavior

    Returns a dict:
      {"decision": "ALLOW" | "REVIEW" | "BLOCK",
       "reason": text,
       "rule": name of the rule that decided}
    """
    inputs = {
        "permission_allowed": permission_allowed,
        "policy": policy_result or {},
        "risk": risk_result or {},
        "threat": threat_result or {},
        "behavior": behavior_result or {},
    }

    for rule_name, rule in PRECEDENCE:
        outcome = rule(inputs)
        if outcome is not None:
            decision, reason = outcome
            return {"decision": decision, "reason": reason, "rule": rule_name}

    return {
        "decision": "ALLOW",
        "reason": "No rule blocked or flagged this request",
        "rule": "default_allow",
    }