"""Password hashing helpers for local account authentication."""

from __future__ import annotations

import hmac

try:
    import bcrypt
except ImportError:  # pragma: no cover - used only when the runtime lacks bcrypt.
    bcrypt = None
    import crypt


def hash_password(password: str) -> str:
    """Return a bcrypt password hash without retaining the plaintext."""
    if bcrypt is not None:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    return crypt.crypt(password, crypt.mksalt(crypt.METHOD_BLOWFISH))


def verify_password(password: str, password_hash: str) -> bool:
    """Compare a plaintext password against a bcrypt hash."""
    if bcrypt is not None:
        try:
            return bcrypt.checkpw(password.encode(), password_hash.encode())
        except ValueError:
            return False

    candidate = crypt.crypt(password, password_hash)
    return candidate is not None and hmac.compare_digest(candidate, password_hash)
