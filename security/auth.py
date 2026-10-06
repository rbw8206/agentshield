import bcrypt

# bcrypt only reads the first 72 bytes of a password
MAX_PASSWORD_BYTES = 72


def hash_password(password: str) -> str:
    """Turn a plain password into a secure hash that is safe to store in the database."""
    password_bytes = password.encode("utf-8")
    if len(password_bytes) > MAX_PASSWORD_BYTES:
        raise ValueError("Password is too long (maximum 72 bytes).")

    # gensalt() creates a random salt, so the same password gives a different hash each time
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    return hashed.decode("utf-8")


def verify_password(plain_password: str, stored_hash: str) -> bool:
    """Check a plain password against a stored hash. Returns True or False."""
    password_bytes = plain_password.encode("utf-8")
    if len(password_bytes) > MAX_PASSWORD_BYTES:
        return False

    try:
        return bcrypt.checkpw(password_bytes, stored_hash.encode("utf-8"))
    except ValueError:
        # stored_hash is not a valid bcrypt hash
        return False