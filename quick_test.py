from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.database import Base
from backend.models import Agent, Permission, AgentPermission
from security.permissions import check_permission

engine = create_engine("sqlite:///:memory:")
Base.metadata.create_all(bind=engine)
db = sessionmaker(bind=engine)()

db.add(Agent(agent_id="research_agent", name="Research Agent", type="research"))
db.add(Permission(permission_id=1, action="READ_FILE", resource="public_research.pdf"))
db.add(AgentPermission(agent_id="research_agent", permission_id=1))
db.commit()

print(check_permission(db, "research_agent", "READ_FILE", "public_research.pdf"))   # True
print(check_permission(db, "research_agent", "READ_FILE", "employee_salary"))       # False
print(check_permission(db, "research_agent", "EXPORT_DATA", "public_research.pdf")) # False
print(check_permission(db, "unknown_agent", "READ_FILE", "public_research.pdf"))    # False