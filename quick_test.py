from security.decision_engine import make_decision

# Building blocks for the test cases
no_policy = {"decision": "NO_MATCH", "reason": "No enabled policy matched this request"}
low = {"risk_score": 5, "risk_level": "LOW"}
medium = {"risk_score": 40, "risk_level": "MEDIUM"}
high = {"risk_score": 78, "risk_level": "HIGH"}
no_threat = {"threat_detected": False}
no_behavior = {"unusual_behavior": False}

def show(title, result):
    print(f"{title:35} -> {result['decision']:7} ({result['rule']})")

show("1. Clean request",
     make_decision(True, no_policy, low, no_threat, no_behavior))
show("2. No permission",
     make_decision(False, no_policy, low, no_threat, no_behavior))
show("3. Policy BLOCK",
     make_decision(True, {"decision": "BLOCK", "reason": "Matched policy X"}, low, no_threat, no_behavior))
show("4. High-severity threat",
     make_decision(True, no_policy, low,
                   {"threat_detected": True, "threat_type": "PROMPT_INJECTION",
                    "severity": "HIGH", "description": "Override attempt"}, no_behavior))
show("5. Risk HIGH",
     make_decision(True, no_policy, high, no_threat, no_behavior))
show("6. Risk MEDIUM",
     make_decision(True, no_policy, medium, no_threat, no_behavior))
show("7. Policy REVIEW, low risk",
     make_decision(True, {"decision": "REVIEW", "reason": "Matched policy Y"}, low, no_threat, no_behavior))
show("8. HR export: policy REVIEW + risk HIGH",
     make_decision(True, {"decision": "REVIEW", "reason": "Matched policy Y"}, high, no_threat, no_behavior))
show("9. Unusual behavior HIGH",
     make_decision(True, no_policy, low, no_threat,
                   {"unusual_behavior": True, "severity": "HIGH", "reason": "Repeated denials"}))