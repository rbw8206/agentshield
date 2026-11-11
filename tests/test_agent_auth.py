import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.database import Base
from backend.models import Agent, AgentApiKey
from security.agent_auth import (
    create_agent_key, authenticate_agent, revoke_agent_key, list_agent_keys, hash_key,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def make_database(path):
    """A real (file) SQLite database with two agents, so we can also inspect the raw file."""
    engine = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    session.add_all([
        Agent(agent_id="research_agent", name="Research Agent", type="research"),
        Agent(agent_id="hr_agent", name="HR Agent", type="hr"),
    ])
    session.commit()
    return engine, session


class AgentAuthTests(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = os.path.join(tmp.name, "auth.db")
        self.engine, self.db = make_database(self.path)
        self.addCleanup(self.engine.dispose)
        self.addCleanup(self.db.close)

    def test_a_valid_key_identifies_its_agent(self):
        key = create_agent_key(self.db, "research_agent", "dify")
        self.assertTrue(key.startswith("ask_"))
        self.assertEqual(authenticate_agent(self.db, key), "research_agent")

    def test_a_key_belongs_to_one_agent_only(self):
        research_key = create_agent_key(self.db, "research_agent")
        hr_key = create_agent_key(self.db, "hr_agent")
        self.assertEqual(authenticate_agent(self.db, research_key), "research_agent")
        self.assertEqual(authenticate_agent(self.db, hr_key), "hr_agent")
        self.assertNotEqual(research_key, hr_key)

    def test_the_real_key_is_never_stored(self):
        key = create_agent_key(self.db, "research_agent")
        row = self.db.query(AgentApiKey).one()
        self.assertNotEqual(row.key_hash, key)
        self.assertEqual(row.key_hash, hash_key(key))
        self.db.close()
        self.engine.dispose()
        with open(self.path, "rb") as raw:
            self.assertNotIn(key.encode(), raw.read())              # not even in the raw file

    def test_wrong_missing_or_altered_keys_are_rejected(self):
        key = create_agent_key(self.db, "research_agent")
        for bad in (None, "", "   ", "ask_not-a-real-key", key + "x", key[:-1], key.upper(),
                    " " + key, "x" * 5000):
            with self.subTest(key=bad if bad is None or len(bad) < 40 else "very long"):
                self.assertIsNone(authenticate_agent(self.db, bad))

    def test_a_revoked_key_stops_working_but_other_keys_still_work(self):
        first = create_agent_key(self.db, "research_agent", "old")
        second = create_agent_key(self.db, "research_agent", "new")
        first_id = self.db.query(AgentApiKey).filter_by(label="old").one().key_id

        self.assertTrue(revoke_agent_key(self.db, first_id))
        self.assertIsNone(authenticate_agent(self.db, first))
        self.assertEqual(authenticate_agent(self.db, second), "research_agent")
        self.assertTrue(revoke_agent_key(self.db, first_id))        # revoking twice is harmless
        self.assertFalse(revoke_agent_key(self.db, 9999))           # unknown key id

    def test_cannot_create_a_key_for_an_unknown_agent(self):
        with self.assertRaises(ValueError):
            create_agent_key(self.db, "ghost_agent")
        self.assertEqual(self.db.query(AgentApiKey).count(), 0)

    def test_listing_never_exposes_secrets(self):
        key = create_agent_key(self.db, "hr_agent", "demo")
        rows = list_agent_keys(self.db)
        self.assertEqual([(r.agent_id, r.label, r.revoked) for r in rows], [("hr_agent", "demo", False)])
        self.assertNotIn(key, repr([vars(r) for r in rows]))


class KeyCommandLineTests(unittest.TestCase):
    """Runs the real command-line tool against a temporary database."""

    def run_tool(self, folder, *args):
        env = dict(os.environ, PYTHONPATH=str(PROJECT_ROOT))
        return subprocess.run(
            [sys.executable, "-m", "database.issue_agent_key", *args],
            cwd=folder, env=env, capture_output=True, text=True, timeout=60,
        )

    def test_issue_list_and_revoke(self):
        with tempfile.TemporaryDirectory() as folder:
            engine, db = make_database(os.path.join(folder, "agentshield.db"))   # the tool uses ./agentshield.db
            try:
                issued = self.run_tool(folder, "issue", "research_agent", "dify research")
                self.assertEqual(issued.returncode, 0, issued.stderr)
                key = next(line.strip() for line in issued.stdout.splitlines() if line.strip().startswith("ask_"))
                self.assertEqual(authenticate_agent(db, key), "research_agent")

                listed = self.run_tool(folder, "list")
                self.assertEqual(listed.returncode, 0, listed.stderr)
                self.assertIn("research_agent", listed.stdout)
                self.assertIn("dify research", listed.stdout)
                self.assertNotIn(key, listed.stdout)                    # the secret is never listed

                revoked = self.run_tool(folder, "revoke", "1")
                self.assertEqual(revoked.returncode, 0, revoked.stderr)
                self.assertIsNone(authenticate_agent(db, key))

                missing = self.run_tool(folder, "issue", "ghost_agent")  # unknown agent: clean failure
                self.assertNotEqual(missing.returncode, 0)
                self.assertIn("Unknown agent", missing.stderr)
                self.assertNotIn("Traceback", missing.stderr)
            finally:
                db.close()
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
