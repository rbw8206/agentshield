import json
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.database import Base
from backend.models import Policy, Resource
from security.policy_engine import evaluate_policy

engine = create_engine("sqlite:///:memory:")
Base.metadata.create_all(bind=engine)
db = sessionmaker(bind=engine)()

db.add(Resource(name="employee_records", type="database", sensitivity_level="HIGH"))
db.add(Policy(
    name="Research cannot read salaries",
    condition=json.dumps({"agent_id": "research_agent", "resource": "employee_salary"}),
    action="BLOCK", priority=10, enabled=True))
db.add(Policy(
    name="High-sensitivity exports need approval",
    condition=json.dumps({"action": "EXPORT_DATA", "sensitivity": "HIGH"}),
    action="REVIEW", priority=5, enabled=True))
db.commit()

print(evaluate_policy(db, "research_agent", "READ_DATABASE", "employee_salary"))
print(evaluate_policy(db, "hr_agent", "EXPORT_DATA", "employee_records"))
print(evaluate_policy(db, "research_agent", "READ_FILE", "public_research.pdf"))