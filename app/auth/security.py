"""Password hashing helpers for local account authentication."""

from __future__ import annotations

import bcrypt


def hash_password(password: str) -> str:
    """Return a bcrypt password hash without retaining the plaintext."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    """Compare a plaintext password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except ValueError:
        return False
