# Points added for each risk factor (they add up to exactly 100)
RISK_POINTS = {
    "sensitive_data": 30,
    "external_destination": 25,
    "high_privilege": 20,
    "bulk_operation": 15,
    "unusual_behavior": 10,
}

# Risk level boundaries
MEDIUM_THRESHOLD = 30
HIGH_THRESHOLD = 70


def calculate_risk(
    sensitive_data: bool = False,
    external_destination: bool = False,
    high_privilege: bool = False,
    bulk_operation: bool = False,
    unusual_behavior: bool = False,
) -> dict:
    """
    Add up the points for every factor that is True and return the result.

    Returns a dict:
      {"risk_score": 0-100,
       "risk_level": "LOW" | "MEDIUM" | "HIGH",
       "factors": list of the factors that added points}
    """
    flags = {
        "sensitive_data": sensitive_data,
        "external_destination": external_destination,
        "high_privilege": high_privilege,
        "bulk_operation": bulk_operation,
        "unusual_behavior": unusual_behavior,
    }

    risk_score = 0
    factors = []
    for name, is_present in flags.items():
        if is_present:
            risk_score += RISK_POINTS[name]
            factors.append(f"{name} (+{RISK_POINTS[name]})")

    if risk_score >= HIGH_THRESHOLD:
        risk_level = "HIGH"
    elif risk_score >= MEDIUM_THRESHOLD:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {"risk_score": risk_score, "risk_level": risk_level, "factors": factors}