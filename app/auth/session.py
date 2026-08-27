"""Minimal signed-cookie session support for the server-rendered MVP."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass

from fastapi import Request, Response

from app.config import Settings


SESSION_COOKIE_NAME = "sast_session"
SESSION_MAX_AGE_SECONDS = 8 * 60 * 60


@dataclass(slots=True)
class SessionState:
    user_id: int | None
    csrf_token: str
    expires_at: int
    changed: bool = False


def _encode_payload(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _decode_payload(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _sign(payload: str, secret: str) -> str:
    return _encode_payload(
        hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest()
    )


def _serialize(session: SessionState, secret: str) -> str:
    payload = _encode_payload(
        json.dumps(
            {
                "csrf_token": session.csrf_token,
                "expires_at": session.expires_at,
                "user_id": session.user_id,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    )
    return f"{payload}.{_sign(payload, secret)}"


def _deserialize(value: str | None, secret: str) -> SessionState | None:
    if not value or "." not in value:
        return None
    payload, signature = value.rsplit(".", 1)
    if not hmac.compare_digest(signature, _sign(payload, secret)):
        return None
    try:
        data = json.loads(_decode_payload(payload))
        user_id = data["user_id"]
        expires_at = data["expires_at"]
        csrf_token = data["csrf_token"]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None
    if (
        user_id is not None
        and (not isinstance(user_id, int) or isinstance(user_id, bool))
    ):
        return None
    if (
        not isinstance(expires_at, int)
        or not isinstance(csrf_token, str)
        or not csrf_token
        or expires_at < int(time.time())
    ):
        return None
    return SessionState(user_id=user_id, csrf_token=csrf_token, expires_at=expires_at)


def get_session(request: Request) -> SessionState:
    """Load the request session or create an anonymous CSRF session."""
    existing = getattr(request.state, "sast_session", None)
    if existing is not None:
        return existing

    settings: Settings = request.app.state.settings
    session = _deserialize(request.cookies.get(SESSION_COOKIE_NAME), settings.session_secret)
    if session is None:
        session = SessionState(
            user_id=None,
            csrf_token=secrets.token_urlsafe(32),
            expires_at=int(time.time()) + SESSION_MAX_AGE_SECONDS,
            changed=True,
        )
    request.state.sast_session = session
    return session


def persist_session(response: Response, request: Request) -> None:
    session = get_session(request)
    if not session.changed:
        return
    settings: Settings = request.app.state.settings
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=_serialize(session, settings.session_secret),
        max_age=SESSION_MAX_AGE_SECONDS,
        httponly=True,
        samesite="lax",
        secure=settings.app_env == "production",
        path="/",
    )
    session.changed = False


def log_in(request: Request, user_id: int) -> None:
    session = get_session(request)
    session.user_id = user_id
    session.csrf_token = secrets.token_urlsafe(32)
    session.expires_at = int(time.time()) + SESSION_MAX_AGE_SECONDS
    session.changed = True


def log_out(request: Request, response: Response) -> None:
    get_session(request)
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")


def csrf_token(request: Request) -> str:
    return get_session(request).csrf_token


def csrf_is_valid(request: Request, submitted_token: str) -> bool:
    return hmac.compare_digest(get_session(request).csrf_token, submitted_token)
