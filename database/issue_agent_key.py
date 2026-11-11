"""
Manage agent API keys. Run from the project root (the folder that contains backend/ and security/).

    python -m database.issue_agent_key issue research_agent "dify research agent"
    python -m database.issue_agent_key list
    python -m database.issue_agent_key revoke 1

A new key is shown ONCE. Only its hash is stored, so a lost key cannot be recovered:
revoke it and issue a new one.
"""
import argparse
import sys
from pathlib import Path

# Lets "python database/issue_agent_key.py" find the project packages, as well as "python -m ..."
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.database import Base, SessionLocal, engine
from security.agent_auth import create_agent_key, revoke_agent_key, list_agent_keys


def main(argv=None):
    parser = argparse.ArgumentParser(description="Manage AgentShield agent API keys")
    commands = parser.add_subparsers(dest="command", required=True)

    issue = commands.add_parser("issue", help="create a new key for an agent")
    issue.add_argument("agent_id")
    issue.add_argument("label", nargs="?", default=None, help="what the key is for")

    commands.add_parser("list", help="list keys (the secrets are never shown)")

    revoke = commands.add_parser("revoke", help="disable a key")
    revoke.add_argument("key_id", type=int)

    args = parser.parse_args(argv)

    Base.metadata.create_all(bind=engine)   # makes sure the agent_api_keys table exists
    db = SessionLocal()
    try:
        if args.command == "issue":
            try:
                key = create_agent_key(db, args.agent_id, args.label)
            except ValueError as error:
                sys.exit(str(error))
            print(f"New API key for agent '{args.agent_id}':\n")
            print(f"    {key}\n")
            print("Copy it now. It is stored only as a hash and can never be shown again.")
            print("The agent sends it in the X-Agent-Key header. Never commit it or share it in chat.")

        elif args.command == "list":
            keys = list_agent_keys(db)
            if not keys:
                print("No keys yet.")
            for k in keys:
                status = "REVOKED" if k.revoked else "active"
                print(f"  key_id {k.key_id:<3} {k.agent_id:<16} {status:<8} "
                      f"created {k.created_at:%Y-%m-%d %H:%M}  {k.label or ''}")

        elif args.command == "revoke":
            if revoke_agent_key(db, args.key_id):
                print(f"Key {args.key_id} is revoked.")
            else:
                sys.exit(f"No key with key_id {args.key_id}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
