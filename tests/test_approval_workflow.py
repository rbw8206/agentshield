import os
import tempfile
import threading
import unittest
from unittest import mock

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from agents import tools
from backend.database import Base, get_db
from backend.main import app
from backend.models import (
    User, Agent, Resource, Permission, AgentPermission,
    ActionRequest, Approval, AuditLog, PendingAction,
)
from security.approval import create_approval_request, review_request, ApprovalNotFound, WrongStatus
from security.tool_gateway import handle_request, execute_approved_request, load_history

ADMIN_KEY = "test-admin-key"
HEADERS = {"X-Admin-Key": ADMIN_KEY}
RECORD = {"employee": "E-1", "salary": 100}

EXPECTED_RESPONSE_KEYS = {
    "request_id", "decision", "reason", "rule", "risk_score", "risk_level",
    "threat_type", "executed", "approval_required", "tool_result",
}


def seed(db):
    """Admin + normal user, one HR agent, a sensitive and a public resource."""
    db.add_all([
        User(user_id=1, name="Admin", email="admin@test.com", role="admin", password_hash="x"),
        User(user_id=2, name="Normal", email="user@test.com", role="user", password_hash="x"),
        Agent(agent_id="hr_agent", name="HR Agent", type="hr"),
        Resource(resource_id=1, name="employee_records", type="database", sensitivity_level="HIGH"),
        Resource(resource_id=2, name="public_research.pdf", type="file", sensitivity_level="LOW"),
        Permission(permission_id=1, action="WRITE_DATABASE", resource="employee_records"),
        Permission(permission_id=2, action="READ_FILE", resource="public_research.pdf"),
        AgentPermission(agent_id="hr_agent", permission_id=1),
        AgentPermission(agent_id="hr_agent", permission_id=2),
    ])
    db.commit()


class ApprovalWorkflowTests(unittest.TestCase):

    def setUp(self):
        # One shared in-memory database for the test and for the API
        self.engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                                    poolclass=StaticPool)
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.db = self.Session()
        seed(self.db)

        def override_get_db():
            session = self.Session()
            try:
                yield session
            finally:
                session.close()

        app.dependency_overrides[get_db] = override_get_db
        self.addCleanup(app.dependency_overrides.clear)

        mock.patch.dict(os.environ, {"AGENTSHIELD_ADMIN_KEY": ADMIN_KEY}).start()
        # Spy on the simulated tool so we can count how many times it really ran
        self.spy = mock.patch("agents.tools.write_database", wraps=tools.write_database).start()
        self.addCleanup(mock.patch.stopall)

        self.client = TestClient(app)

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    # ---- helpers ----
    def submit(self):
        """An HR agent asks to write sensitive records -> held for review."""
        response = self.client.post("/actions/request", json={
            "agent_id": "hr_agent", "action": "WRITE_DATABASE", "resource_id": 1,
            "context": {"payload": {"record": RECORD}},
        })
        body = response.json()
        self.assertEqual(body["decision"], "REVIEW")
        return body["request_id"]

    def approve(self, rid, admin_id=1, reason="OK", headers=HEADERS):
        return self.client.post(f"/approvals/{rid}/approve",
                                json={"admin_id": admin_id, "reason": reason}, headers=headers)

    def reject(self, rid, admin_id=1, reason="No"):
        return self.client.post(f"/approvals/{rid}/reject",
                                json={"admin_id": admin_id, "reason": reason}, headers=HEADERS)

    def status(self, rid):
        self.db.expire_all()
        return self.db.get(ActionRequest, rid).status

    def audit_decisions(self, rid):
        self.db.expire_all()
        rows = (self.db.query(AuditLog).filter(AuditLog.request_id == rid)
                .order_by(AuditLog.log_id).all())
        return [row.decision for row in rows]

    def approval_count(self, rid):
        self.db.expire_all()
        return self.db.query(Approval).filter(Approval.request_id == rid).count()

    # ---- 1. REVIEW is held, never executed immediately ----
    def test_review_request_is_held_and_not_executed(self):
        response = self.client.post("/actions/request", json={
            "agent_id": "hr_agent", "action": "WRITE_DATABASE", "resource_id": 1,
            "context": {"payload": {"record": RECORD}},
        })
        body = response.json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(body), EXPECTED_RESPONSE_KEYS)          # response format unchanged
        self.assertEqual((body["decision"], body["executed"], body["approval_required"]),
                         ("REVIEW", False, True))
        self.assertIsNone(body["tool_result"])
        self.spy.assert_not_called()
        self.assertEqual(self.status(body["request_id"]), "REVIEW")
        self.db.expire_all()
        held = self.db.get(PendingAction, body["request_id"])
        self.assertIsNotNone(held)                                    # parameters are kept
        self.assertIn("salary", held.payload)

    # ---- 2. Pending list ----
    def test_pending_list_shows_held_request_until_decided(self):
        rid = self.submit()
        response = self.client.get("/approvals/pending", headers=HEADERS)
        self.assertEqual(response.status_code, 200)
        items = response.json()
        self.assertEqual(len(items), 1)
        item = items[0]
        self.assertEqual(item["request_id"], rid)
        self.assertEqual((item["agent_id"], item["action"], item["resource"], item["sensitivity"]),
                         ("hr_agent", "WRITE_DATABASE", "employee_records", "HIGH"))
        self.assertEqual(item["risk_level"], "MEDIUM")
        self.assertTrue(item["reason"])

        self.assertEqual(self.approve(rid).status_code, 200)
        self.assertEqual(self.client.get("/approvals/pending", headers=HEADERS).json(), [])

    def test_allowed_and_blocked_requests_are_not_pending(self):
        allowed = self.client.post("/actions/request", json={
            "agent_id": "hr_agent", "action": "READ_FILE", "resource_id": 2}).json()
        blocked = self.client.post("/actions/request", json={
            "agent_id": "hr_agent", "action": "READ_DATABASE", "resource_id": 1}).json()

        self.assertEqual((allowed["decision"], allowed["executed"]), ("ALLOW", True))
        self.assertEqual((blocked["decision"], blocked["executed"]), ("BLOCK", False))
        self.assertEqual(self.client.get("/approvals/pending", headers=HEADERS).json(), [])

    # ---- admin protection ----
    def test_approval_endpoints_need_the_admin_key(self):
        rid = self.submit()

        self.assertEqual(self.client.get("/approvals/pending").status_code, 401)
        self.assertEqual(self.approve(rid, headers={}).status_code, 401)
        self.assertEqual(self.approve(rid, headers={"X-Admin-Key": "wrong"}).status_code, 401)
        self.assertEqual(self.status(rid), "REVIEW")                  # nothing changed
        self.spy.assert_not_called()

        with mock.patch.dict(os.environ):                            # key not configured
            os.environ.pop("AGENTSHIELD_ADMIN_KEY")
            self.assertEqual(self.client.get("/approvals/pending", headers=HEADERS).status_code, 503)

    # ---- 3. Approved: runs once, with the held parameters, and is logged ----
    def test_approved_request_executes_once_and_is_logged(self):
        rid = self.submit()
        response = self.approve(rid, reason="Needed for audit")
        body = response.json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual((body["decision"], body["status"], body["executed"]),
                         ("APPROVED", "EXECUTED", True))
        self.assertEqual(body["tool_result"]["data"], {"record_written": RECORD})
        self.assertTrue(body["tool_result"]["simulated"])
        self.spy.assert_called_once_with("employee_records", RECORD)
        self.assertEqual(self.status(rid), "EXECUTED")

        self.db.expire_all()
        approval = self.db.query(Approval).filter(Approval.request_id == rid).one()
        self.assertEqual((approval.admin_id, approval.decision, approval.reason),
                         (1, "APPROVED", "Needed for audit"))
        self.assertEqual(self.audit_decisions(rid), ["REVIEW", "APPROVED", "EXECUTED"])

    # ---- 4. Rejected: never runs ----
    def test_rejected_request_never_executes(self):
        rid = self.submit()
        response = self.reject(rid)
        body = response.json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual((body["decision"], body["status"], body["executed"], body["tool_result"]),
                         ("REJECTED", "REJECTED", False, None))
        self.assertEqual(self.status(rid), "REJECTED")
        self.assertEqual(self.audit_decisions(rid), ["REVIEW", "REJECTED"])

        # A rejected request cannot be approved or executed later
        self.assertEqual(self.approve(rid).status_code, 409)
        with self.assertRaises(WrongStatus):
            execute_approved_request(self.db, rid)
        self.spy.assert_not_called()
        self.assertEqual(self.status(rid), "REJECTED")

    # ---- 5. Duplicates ----
    def test_duplicate_approval_is_refused_and_tool_runs_once(self):
        rid = self.submit()
        first, second = self.approve(rid), self.approve(rid)

        self.assertEqual((first.status_code, second.status_code), (200, 409))
        self.assertEqual(self.spy.call_count, 1)
        self.assertEqual(self.approval_count(rid), 1)
        self.assertEqual(self.audit_decisions(rid), ["REVIEW", "APPROVED", "EXECUTED"])

    def test_conflicting_or_repeated_decisions_are_refused(self):
        approved = self.submit()
        self.assertEqual(self.approve(approved).status_code, 200)
        self.assertEqual(self.reject(approved).status_code, 409)       # approve then reject
        self.assertEqual(self.status(approved), "EXECUTED")

        rejected = self.submit()
        self.assertEqual(self.reject(rejected).status_code, 200)
        self.assertEqual(self.reject(rejected).status_code, 409)       # reject twice
        self.assertEqual(self.approval_count(rejected), 1)
        self.assertEqual(self.spy.call_count, 1)                        # only the approved one ran

    def test_execute_runs_the_tool_only_once(self):
        rid = self.submit()
        review_request(self.db, rid, 1, "APPROVED")
        self.assertTrue(execute_approved_request(self.db, rid)["executed"])
        with self.assertRaises(WrongStatus):
            execute_approved_request(self.db, rid)
        self.spy.assert_called_once()

    def test_execute_refuses_unapproved_and_unknown_requests(self):
        rid = self.submit()                                            # still REVIEW
        with self.assertRaises(WrongStatus):
            execute_approved_request(self.db, rid)
        with self.assertRaises(ApprovalNotFound):
            execute_approved_request(self.db, "REQ-DOES-NOT-EXIST")
        self.spy.assert_not_called()

    def test_executed_request_cannot_be_reopened(self):
        rid = self.submit()
        self.approve(rid)
        with self.assertRaises(WrongStatus):
            create_approval_request(self.db, rid)
        self.assertEqual(self.status(rid), "EXECUTED")

    def test_failed_tool_is_logged_and_never_retried(self):
        self.spy.side_effect = RuntimeError("boom")
        rid = self.submit()
        body = self.approve(rid).json()

        self.assertEqual((body["status"], body["executed"]), ("EXECUTION_FAILED", False))
        self.assertIn("boom", body["tool_result"]["error"])
        self.assertEqual(self.audit_decisions(rid), ["REVIEW", "APPROVED", "EXECUTION_FAILED"])
        with self.assertRaises(WrongStatus):
            execute_approved_request(self.db, rid)
        self.assertEqual(self.spy.call_count, 1)

    # ---- who may decide / unknown requests ----
    def test_only_admins_can_decide(self):
        rid = self.submit()
        self.assertEqual(self.approve(rid, admin_id=2).status_code, 403)    # normal user
        self.assertEqual(self.approve(rid, admin_id=999).status_code, 403)  # unknown user
        self.assertEqual(self.reject(rid, admin_id=2).status_code, 403)
        self.assertEqual(self.status(rid), "REVIEW")
        self.assertEqual(self.approval_count(rid), 0)
        self.spy.assert_not_called()
        self.assertEqual(self.approve(rid, admin_id=1).status_code, 200)    # a real admin can

    def test_unknown_request_returns_404(self):
        self.assertEqual(self.approve("REQ-NOPE").status_code, 404)
        self.assertEqual(self.reject("REQ-NOPE").status_code, 404)

    # ---- existing behaviour is not disturbed ----
    def test_approval_and_execution_rows_do_not_count_as_agent_actions(self):
        rid = self.submit()
        self.approve(rid)
        self.db.expire_all()
        self.assertEqual(self.db.query(AuditLog).filter(AuditLog.request_id == rid).count(), 3)

        history = load_history(self.db, "hr_agent")                      # used by behavior checks
        self.assertEqual([entry["decision"] for entry in history], ["REVIEW"])


class ConcurrentApprovalTests(unittest.TestCase):
    """Several admins approve the same request at the same moment (real threads, file database)."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.engine = create_engine(f"sqlite:///{os.path.join(tmp.name, 'race.db')}",
                                    connect_args={"timeout": 30})
        self.addCleanup(self.engine.dispose)
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine)
        with self.Session() as db:
            seed(db)
        self.spy = mock.patch("agents.tools.write_database", wraps=tools.write_database).start()
        self.addCleanup(mock.patch.stopall)

    def test_only_one_of_many_simultaneous_approvals_wins(self):
        with self.Session() as db:
            rid = handle_request(db, "hr_agent", "WRITE_DATABASE", "employee_records",
                                 payload={"record": RECORD})["request_id"]

        threads_count = 4
        barrier = threading.Barrier(threads_count)
        results = []

        def worker():
            session = self.Session()
            try:
                barrier.wait()
                review_request(session, rid, 1, "APPROVED")
                execute_approved_request(session, rid)
                results.append("ok")
            except WrongStatus:
                results.append("refused")
            except Exception as error:
                results.append(f"error: {error!r}")
            finally:
                session.close()

        threads = [threading.Thread(target=worker) for _ in range(threads_count)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(sorted(results), ["ok"] + ["refused"] * (threads_count - 1), results)
        self.assertEqual(self.spy.call_count, 1)
        with self.Session() as db:
            self.assertEqual(db.query(Approval).filter(Approval.request_id == rid).count(), 1)
            self.assertEqual(db.get(ActionRequest, rid).status, "EXECUTED")
            decisions = [r.decision for r in db.query(AuditLog)
                         .filter(AuditLog.request_id == rid).order_by(AuditLog.log_id)]
            self.assertEqual(decisions, ["REVIEW", "APPROVED", "EXECUTED"])


if __name__ == "__main__":
    unittest.main()
