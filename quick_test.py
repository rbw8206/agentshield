from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.database import Base
from backend.models import User, Agent, Resource, ActionRequest
from security.approval import create_approval_request, review_request, get_approval

engine = create_engine("sqlite:///:memory:")
Base.metadata.create_all(bind=engine)
db = sessionmaker(bind=engine)()

db.add(User(user_id=1, name="Admin", email="admin@test.com", role="admin", password_hash="x"))
db.add(User(user_id=2, name="Normal", email="user@test.com", role="user", password_hash="x"))
db.add(Agent(agent_id="hr_agent", name="HR Agent", type="hr"))
db.add(Resource(resource_id=1, name="employee_records", type="database", sensitivity_level="HIGH"))
db.add(ActionRequest(request_id="REQ-001", agent_id="hr_agent", action="EXPORT_DATA", resource_id=1))
db.commit()

req = create_approval_request(db, "REQ-001")
print("1. Status after create:", req.status)                    # REVIEW
print("2. Approval before decision:", get_approval(db, "REQ-001"))  # None

try:
    review_request(db, "REQ-001", 2, "APPROVED")                # normal user
except ValueError as e:
    print("3. Non-admin:", e)

try:
    review_request(db, "REQ-001", 1, "MAYBE")                   # invalid decision
except ValueError as e:
    print("4. Bad decision:", e)

approval = review_request(db, "REQ-001", 1, "approved", "Needed for payroll audit")
print("5. Decision:", approval.decision, "| admin:", approval.admin_id, "| reason:", approval.reason)
print("6. Request status now:", db.query(ActionRequest).first().status)  # APPROVED
print("7. Retrieved:", get_approval(db, "REQ-001").decision)    # APPROVED

try:
    review_request(db, "REQ-001", 1, "REJECTED")                # decided twice
except ValueError as e:
    print("8. Second decision:", e)