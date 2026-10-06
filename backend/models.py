from datetime import datetime, timezone

from sqlalchemy import (
    Column, Integer, String, Text, Boolean, DateTime, ForeignKey
)
from sqlalchemy.orm import relationship

from backend.database import Base, engine


def utc_now():
    return datetime.now(timezone.utc)


# 1. Users (administrators and normal users)
class User(Base):
    __tablename__ = "users"

    user_id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    email = Column(String(150), unique=True, nullable=False)
    role = Column(String(50), nullable=False, default="user")  # e.g. "admin" or "user"
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=utc_now)

    approvals = relationship("Approval", back_populates="admin")


# 2. Agents (agent_id is text like "research_agent")
class Agent(Base):
    __tablename__ = "agents"

    agent_id = Column(String(50), primary_key=True)
    name = Column(String(100), nullable=False)
    type = Column(String(50), nullable=False)
    status = Column(String(20), default="ACTIVE")      # ACTIVE / SUSPENDED
    risk_level = Column(String(20), default="LOW")     # LOW / MEDIUM / HIGH
    created_at = Column(DateTime, default=utc_now)

    permissions = relationship("Permission", secondary="agent_permissions", back_populates="agents")
    action_requests = relationship("ActionRequest", back_populates="agent")
    incidents = relationship("SecurityIncident", back_populates="agent")


# 3. Roles
class Role(Base):
    __tablename__ = "roles"

    role_id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, nullable=False)
    description = Column(Text)


# 4. Permissions
class Permission(Base):
    __tablename__ = "permissions"

    permission_id = Column(Integer, primary_key=True, index=True)
    action = Column(String(50), nullable=False)        # e.g. "READ_FILE"
    resource = Column(String(100), nullable=False)     # e.g. "public_research.pdf"
    description = Column(Text)

    agents = relationship("Agent", secondary="agent_permissions", back_populates="permissions")


# 5. Agent Permissions (links agents and permissions)
class AgentPermission(Base):
    __tablename__ = "agent_permissions"

    agent_id = Column(String(50), ForeignKey("agents.agent_id"), primary_key=True)
    permission_id = Column(Integer, ForeignKey("permissions.permission_id"), primary_key=True)


# 6. Resources (files, databases, etc. with a sensitivity level)
class Resource(Base):
    __tablename__ = "resources"

    resource_id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    type = Column(String(50), nullable=False)          # e.g. "file", "database"
    sensitivity_level = Column(String(20), default="LOW")  # LOW / MEDIUM / HIGH

    action_requests = relationship("ActionRequest", back_populates="resource")


# 7. Policies
class Policy(Base):
    __tablename__ = "policies"

    policy_id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text)
    condition = Column(Text, nullable=False)           # the rule, stored as text
    action = Column(String(20), nullable=False)        # ALLOW / REVIEW / BLOCK
    priority = Column(Integer, default=0)
    enabled = Column(Boolean, default=True)


# 8. Action Requests (request_id is text like "REQ-001")
class ActionRequest(Base):
    __tablename__ = "action_requests"

    request_id = Column(String(50), primary_key=True)
    agent_id = Column(String(50), ForeignKey("agents.agent_id"), nullable=False)
    action = Column(String(50), nullable=False)
    resource_id = Column(Integer, ForeignKey("resources.resource_id"), nullable=False)
    timestamp = Column(DateTime, default=utc_now)
    status = Column(String(20), default="PENDING")     # PENDING / ALLOWED / BLOCKED / REVIEW

    agent = relationship("Agent", back_populates="action_requests")
    resource = relationship("Resource", back_populates="action_requests")
    risk_event = relationship("RiskEvent", back_populates="request", uselist=False)
    approvals = relationship("Approval", back_populates="request")
    incidents = relationship("SecurityIncident", back_populates="request")


# 9. Risk Events
class RiskEvent(Base):
    __tablename__ = "risk_events"

    risk_id = Column(Integer, primary_key=True, index=True)
    request_id = Column(String(50), ForeignKey("action_requests.request_id"), nullable=False)
    risk_score = Column(Integer, nullable=False)       # 0-100
    risk_level = Column(String(20))                    # LOW / MEDIUM / HIGH
    factors = Column(Text)                             # explanation of the score

    request = relationship("ActionRequest", back_populates="risk_event")


# 10. Approvals (human decisions on REVIEW actions)
class Approval(Base):
    __tablename__ = "approvals"

    approval_id = Column(Integer, primary_key=True, index=True)
    request_id = Column(String(50), ForeignKey("action_requests.request_id"), nullable=False)
    admin_id = Column(Integer, ForeignKey("users.user_id"), nullable=False)
    decision = Column(String(20), nullable=False)      # APPROVED / DENIED
    timestamp = Column(DateTime, default=utc_now)
    reason = Column(Text)

    request = relationship("ActionRequest", back_populates="approvals")
    admin = relationship("User", back_populates="approvals")


# 11. Audit Logs
# Deliberately plain columns (no foreign keys except request_id) so each log is a
# frozen snapshot that stays correct even if other rows change later.
class AuditLog(Base):
    __tablename__ = "audit_logs"

    log_id = Column(Integer, primary_key=True, index=True)
    request_id = Column(String(50), ForeignKey("action_requests.request_id"))
    agent_id = Column(String(50))
    action = Column(String(50))
    resource_id = Column(Integer)
    risk_score = Column(Integer)
    decision = Column(String(20))
    reason = Column(Text)
    timestamp = Column(DateTime, default=utc_now)


# 12. Security Incidents
class SecurityIncident(Base):
    __tablename__ = "security_incidents"

    incident_id = Column(Integer, primary_key=True, index=True)
    request_id = Column(String(50), ForeignKey("action_requests.request_id"))
    agent_id = Column(String(50), ForeignKey("agents.agent_id"))
    threat_type = Column(String(50), nullable=False)   # e.g. "UNAUTHORIZED_ACCESS"
    severity = Column(String(20), default="MEDIUM")    # LOW / MEDIUM / HIGH / CRITICAL
    description = Column(Text)
    status = Column(String(20), default="OPEN")        # OPEN / INVESTIGATING / RESOLVED
    timestamp = Column(DateTime, default=utc_now)

    request = relationship("ActionRequest", back_populates="incidents")
    agent = relationship("Agent", back_populates="incidents")


# Create all tables when this file is run directly
if __name__ == "__main__":
    Base.metadata.create_all(bind=engine)
    print("All tables created successfully.")