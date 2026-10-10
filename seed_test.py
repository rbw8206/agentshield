import json
from backend.database import SessionLocal, Base, engine
from backend.models import Agent, Resource, Permission, AgentPermission, Policy

Base.metadata.create_all(bind=engine)
db = SessionLocal()

db.add(Agent(agent_id="research_agent", name="Research Agent", type="research"))
db.add(Resource(name="public_research.pdf", type="file", sensitivity_level="LOW"))      # id 1
db.add(Resource(name="employee_salary", type="database", sensitivity_level="HIGH"))     # id 2
db.add(Resource(name="employee_records", type="database", sensitivity_level="HIGH"))    # id 3
db.add(Permission(permission_id=1, action="READ_FILE", resource="public_research.pdf"))
db.add(AgentPermission(agent_id="research_agent", permission_id=1))
db.add(Policy(name="Research cannot read salaries",
              condition=json.dumps({"agent_id": "research_agent", "resource": "employee_salary"}),
              action="BLOCK", priority=10, enabled=True))
db.commit()
print("Seeded.")