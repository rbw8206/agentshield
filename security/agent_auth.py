import hashlib
import secrets
from typing import Optional

from sqlalchemy.orm import Session

from backend.models import Agent, AgentApiKey

KEY_PREFIX = "ask_"      # makes a leaked key easy to recognise
MAX_KEY_LENGTH = 200     # anything longer than this is never a real key


def hash_key(key: str) -> str:
    """
    SHA-256 is enough here: our keys are long random values, so unlike a human
    password they cannot be guessed. It also lets us look a key up directly by its hash.
    """
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def create_agent_key(db: Session, agent_id: str, label: str = None) -> str:
    """
    Create a new API key for an agent and return it.
    This is the ONLY time the real key exists: the database keeps just its hash.
    """
    if db.query(Agent).filter(Agent.agent_id == agent_id).first() is None:
        raise ValueError(f"Unknown agent '{agent_id}'")

    key = KEY_PREFIX + secrets.token_urlsafe(32)
    db.add(AgentApiKey(agent_id=agent_id, key_hash=hash_key(key), label=label))
    db.commit()
    return key


def authenticate_agent(db: Session, presented_key: Optional[str]) -> Optional[str]:
    """
    Return the agent_id that owns a valid, un-revoked key, otherwise None.
    The agent's identity comes from the key, never from anything the agent claims.
    """
    if not presented_key or len(presented_key) > MAX_KEY_LENGTH:
        return None

    row = (
        db.query(AgentApiKey)
        .filter(AgentApiKey.key_hash == hash_key(presented_key), AgentApiKey.revoked == False)  # noqa: E712
        .first()
    )
    return row.agent_id if row else None


def revoke_agent_key(db: Session, key_id: int) -> bool:
    """Disable a key. Returns False if there is no such key. Safe to call twice."""
    row = db.query(AgentApiKey).filter(AgentApiKey.key_id == key_id).first()
    if row is None:
        return False
    row.revoked = True
    db.commit()
    return True


def list_agent_keys(db: Session) -> list:
    """All keys (never the secret itself), oldest first."""
    return db.query(AgentApiKey).order_by(AgentApiKey.key_id).all()
