from datetime import datetime, timedelta
from security.behavior_monitor import monitor_behavior

start = datetime(2026, 10, 7, 10, 0, 0)

def entry(seconds, action, resource, decision="ALLOW"):
    return {"timestamp": start + timedelta(seconds=seconds),
            "action": action, "resource": resource, "decision": decision}

# 1. Normal behavior
normal = [entry(i * 30, "READ_FILE", "public_research.pdf") for i in range(4)]
print(monitor_behavior(normal))

# 2. Too many actions in a short period (25 actions in 25 seconds)
burst = [entry(i, "READ_FILE", "public_research.pdf") for i in range(25)]
print(monitor_behavior(burst))

# 3. Repeated denied actions
denied = [entry(i * 10, "READ_DATABASE", "employee_salary", "BLOCK") for i in range(3)]
print(monitor_behavior(denied))

# 4. Suspicious sequence
sequence = [
    entry(0, "READ_DATABASE", "employee_records"),
    entry(10, "EXPORT_DATA", "employee_records"),
    entry(20, "SEND_EMAIL", "external_address"),
]
print(monitor_behavior(sequence))

# 5. Unusual resource for this agent
print(monitor_behavior(normal, usual_resources={"research_notes.pdf"}))

# 6. Empty history
print(monitor_behavior([]))