"""Authentication and request-scoped database dependencies."""

from __future__ import annotations

from collections.abc import AsyncGenerator

from fastapi import Request
from sqlalchemy.orm import Session

from app.db.models.enums import UserRole
from app.db.models.user import User
from app.auth.session import get_session


async def get_db(request: Request) -> AsyncGenerator[Session, None]:
    """Create one database session per request and clean it up reliably."""
    session: Session = request.app.state.session_factory()
    try:
        yield session
    except BaseException:
        session.rollback()
        raise
    finally:
        session.close()


def current_active_user(request: Request, session: Session) -> User | None:
    user_id = get_session(request).user_id
    if user_id is None:
        return None
    user = session.get(User, user_id)
    if user is None or not user.is_active:
        return None
    return user


def is_super_admin(user: User | None) -> bool:
    return user is not None and user.role is UserRole.SUPER_ADMIN


def is_project_manager(user: User | None) -> bool:
    return user is not None and user.role is UserRole.PROJECT_MANAGER


def can_operate_project(user: User | None) -> bool:
    return is_super_admin(user) or is_project_manager(user)
