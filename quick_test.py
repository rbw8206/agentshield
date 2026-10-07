from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.database import Base
from backend.models import AuditLog
from security.audit_logger import log_action

engine = create_engine("sqlite:///:memory:")
Base.metadata.create_all(bind=engine)
db = sessionmaker(bind=engine)()

log = log_action(db, "REQ-001", "research_agent", "READ_DATABASE", 3,
                 90, "BLOCK", "Agent lacks permission for sensitive resource")

print("log_id:", log.log_id)
print("agent:", log.agent_id, "| action:", log.action, "| decision:", log.decision)
print("risk:", log.risk_score, "| reason:", log.reason)
print("timestamp:", log.timestamp)
print("rows in table:", db.query(AuditLog).count())