"""
AgentShield demo data.

Creates, only if missing: one administrator, three agents, resources, permissions and policies.
Safe to run many times: existing rows are never changed, duplicated or deleted.

Run it from the project root (the folder that contains backend/ and security/).
PowerShell example:

    $env:AGENTSHIELD_ADMIN_EMAIL = "admin@agentshield.local"
    $env:AGENTSHIELD_ADMIN_PASSWORD = "choose-a-long-password-here"
    python -m database.seed

The password is only needed the first time, while the admin user does not exist yet.
It is hashed before it is stored and is never printed or kept in the source code.
"""
import json
import os
import sys
from pathlib import Path

from sqlalchemy import func

# Lets "python database/seed.py" find the project packages, as well as "python -m database.seed"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.database import Base, SessionLocal, engine
from backend.models import User, Agent, Resource, Permission, AgentPermission, Policy
from security.auth import hash_password

MIN_PASSWORD_LENGTH = 12
POLICY_KEYS = {"agent_id", "action", "resource", "sensitivity"}   # keys the policy engine can match
DECISIONS = ("ALLOW", "REVIEW", "BLOCK")

# ---------------------------------------------------------------------------------------------
# Demo data. The gateway only counts HIGH sensitivity as "sensitive data" (+30 risk = REVIEW),
# so routine work on LOW/MEDIUM resources is allowed, while salary data needs approval.
# ---------------------------------------------------------------------------------------------
AGENTS = [
    # agent_id, name, type, risk_level
    ("research_agent", "Research Agent", "research", "LOW"),
    ("finance_agent", "Finance Agent", "finance", "MEDIUM"),
    ("hr_agent", "HR Agent", "hr", "MEDIUM"),
]

RESOURCES = [
    # name, type, sensitivity_level
    ("public_research.pdf", "file", "LOW"),
    ("research_papers", "database", "LOW"),
    ("team_announcements", "file", "LOW"),
    ("finance_records", "database", "MEDIUM"),
    ("employee_records", "database", "MEDIUM"),
    ("employee_salary", "database", "HIGH"),
]

# Least privilege: an agent can only do what is listed here. Anything else is denied.
PERMISSIONS = [
    # agent_id, action, resource, description
    ("research_agent", "READ_FILE", "public_research.pdf", "Read the public research file"),
    ("research_agent", "READ_DATABASE", "research_papers", "Search approved research papers"),
    ("finance_agent", "READ_DATABASE", "finance_records", "Read financial records"),
    ("finance_agent", "WRITE_DATABASE", "finance_records", "Update approved financial records"),
    ("finance_agent", "EXPORT_DATA", "finance_records", "Limited export of financial records"),
    ("hr_agent", "READ_DATABASE", "employee_records", "Read employee records"),
    ("hr_agent", "WRITE_DATABASE", "employee_records", "Update approved employee records"),
    ("hr_agent", "EXPORT_DATA", "employee_records", "Export employee records"),
    ("hr_agent", "READ_DATABASE", "employee_salary", "Read salary data"),
    ("hr_agent", "SEND_EMAIL", "team_announcements", "Email team announcements"),
]

POLICIES = [
    # name, description, condition, decision, priority (higher number is checked first)
    ("Research cannot read salaries", "Research agent must never touch salary data",
     {"agent_id": "research_agent", "resource": "employee_salary"}, "BLOCK", 100),
    ("Research cannot read employee records", "Research agent must never touch HR data",
     {"agent_id": "research_agent", "resource": "employee_records"}, "BLOCK", 100),
    ("Research cannot read finance records", "Research agent must never touch finance data",
     {"agent_id": "research_agent", "resource": "finance_records"}, "BLOCK", 100),
    ("Salary data is read-only", "Nobody may write salary data",
     {"action": "WRITE_DATABASE", "resource": "employee_salary"}, "BLOCK", 90),
    ("No emailing high-sensitivity data", "Highly sensitive data must never be sent by email",
     {"action": "SEND_EMAIL", "sensitivity": "HIGH"}, "BLOCK", 90),
    ("Employee exports need approval", "Exporting employee records needs a human decision",
     {"action": "EXPORT_DATA", "resource": "employee_records"}, "REVIEW", 80),
    ("Finance exports need approval", "Exporting finance records needs a human decision",
     {"action": "EXPORT_DATA", "resource": "finance_records"}, "REVIEW", 80),
    ("High-sensitivity exports need approval", "Any export of highly sensitive data is high risk",
     {"action": "EXPORT_DATA", "sensitivity": "HIGH"}, "REVIEW", 70),
]


def check_seed_data():
    """Stop early if the lists above contain a mistake, so nothing half-valid is stored."""
    agent_ids = {a[0] for a in AGENTS}
    resource_names = {r[0] for r in RESOURCES}
    for agent_id, action, resource, _ in PERMISSIONS:
        if agent_id not in agent_ids or resource not in resource_names:
            sys.exit(f"Seed data error: permission {action} on {resource} for {agent_id} "
                     "refers to an unknown agent or resource")
    for name, _, condition, decision, _ in POLICIES:
        if decision not in DECISIONS or not set(condition) <= POLICY_KEYS:
            sys.exit(f"Seed data error: policy '{name}' has an invalid decision or condition key")


def get_or_create(db, model, lookup, values):
    """Return (row, created). An existing row is returned exactly as it is."""
    row = db.query(model).filter_by(**lookup).first()
    if row is not None:
        return row, False
    row = model(**lookup, **values)
    db.add(row)
    db.flush()   # gives the new row its id; nothing is saved until the final commit
    return row, True


def differences(label, row, expected):
    """Describe fields where an existing row differs from what this seed would have created."""
    notes = []
    for field, wanted in expected.items():
        current = getattr(row, field)
        if field == "condition":
            try:
                same = json.loads(current) == json.loads(wanted)
            except ValueError:
                same = False
        else:
            same = current == wanted
        if not same:
            notes.append(f"{label}: {field} is {current!r}, the seed expects {wanted!r}")
    return notes


def main():
    check_seed_data()

    email = os.environ.get("AGENTSHIELD_ADMIN_EMAIL", "").strip().lower()
    if not email:
        sys.exit("Set AGENTSHIELD_ADMIN_EMAIL (and AGENTSHIELD_ADMIN_PASSWORD the first time) first.")

    Base.metadata.create_all(bind=engine)   # creates only tables that are missing
    db = SessionLocal()
    counts = {}   # label -> [created, already existed]
    notes = []    # differences found in rows that already existed

    def count(label, created):
        counts.setdefault(label, [0, 0])[0 if created else 1] += 1

    try:
        # ---- 1. Administrator ----
        admin = db.query(User).filter(func.lower(User.email) == email).first()
        if admin is None:
            password = os.environ.get("AGENTSHIELD_ADMIN_PASSWORD", "")
            if len(password) < MIN_PASSWORD_LENGTH:
                sys.exit(f"The admin user does not exist yet: set AGENTSHIELD_ADMIN_PASSWORD "
                         f"(at least {MIN_PASSWORD_LENGTH} characters).")
            try:
                password_hash = hash_password(password)
            except ValueError as error:
                sys.exit(f"Password rejected: {error}")
            name = os.environ.get("AGENTSHIELD_ADMIN_NAME", "").strip() or "Administrator"
            admin = User(name=name, email=email, role="admin", password_hash=password_hash)
            db.add(admin)
            db.flush()
            admin_created = True
        else:
            admin_created = False
            if admin.role != "admin":
                notes.append(f"user {admin.email}: role is {admin.role!r}, the seed expects 'admin'")

        # ---- 2. Agents ----
        for agent_id, name, agent_type, risk_level in AGENTS:
            values = {"name": name, "type": agent_type, "status": "ACTIVE", "risk_level": risk_level}
            row, created = get_or_create(db, Agent, {"agent_id": agent_id}, values)
            count("agents", created)
            if not created:
                notes += differences(f"agent {agent_id}", row, values)

        # ---- 3. Resources ----
        for name, resource_type, sensitivity in RESOURCES:
            values = {"type": resource_type, "sensitivity_level": sensitivity}
            row, created = get_or_create(db, Resource, {"name": name}, values)
            count("resources", created)
            if not created:
                notes += differences(f"resource {name}", row, values)

        # ---- 4. Permissions, and which agent gets which ----
        for agent_id, action, resource, description in PERMISSIONS:
            permission, created = get_or_create(
                db, Permission, {"action": action, "resource": resource}, {"description": description})
            count("permissions", created)
            _, linked = get_or_create(
                db, AgentPermission, {"agent_id": agent_id, "permission_id": permission.permission_id}, {})
            count("agent permission grants", linked)

        # ---- 5. Policies (matched by name) ----
        for name, description, condition, decision, priority in POLICIES:
            values = {"description": description, "condition": json.dumps(condition, sort_keys=True),
                      "action": decision, "priority": priority, "enabled": True}
            row, created = get_or_create(db, Policy, {"name": name}, values)
            count("policies", created)
            if not created:
                notes += differences(f"policy '{name}'", row, values)

        db.commit()
        admin_id, admin_email = admin.user_id, admin.email
    except Exception:
        db.rollback()   # a failed run leaves the database exactly as it was
        raise
    finally:
        db.close()

    print("AgentShield seed finished.")
    print(f"Database: {Path(engine.url.database).resolve()}")
    print(f"  admin user              : {'created' if admin_created else 'already existed'} "
          f"({admin_email}, user_id {admin_id})")
    for label, (created, existing) in counts.items():
        print(f"  {label:<24}: {created} created, {existing} already existed")
    if notes:
        print("Existing rows differ from the seed (they were left unchanged):")
        for note in notes:
            print(f"  - {note}")
    print("Note: approving requests through the API also needs AGENTSHIELD_ADMIN_KEY (a separate secret).")


if __name__ == "__main__":
    main()
