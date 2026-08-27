"""Transactional account-management operations."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth.security import hash_password
from app.db.models.enums import UserRole
from app.db.models.user import User


class UserManagementError(ValueError):
    """Raised when an account operation violates the fixed policy."""


def bootstrap_administrator(session: Session) -> None:
    """Create the documented administrator only when no users exist."""
    with session.begin():
        has_users = session.scalar(select(User.id).limit(1)) is not None
        if not has_users:
            session.add(
                User(
                    username="admin",
                    password_hash=hash_password("admin"),
                    role=UserRole.ADMIN,
                    is_active=True,
                )
            )


def create_user(
    session: Session,
    *,
    username: str,
    password: str,
    role: UserRole,
    is_active: bool,
) -> User:
    normalized_username = username.strip()
    if not normalized_username:
        raise UserManagementError("사용자명은 필수입니다.")
    if not password:
        raise UserManagementError("비밀번호는 필수입니다.")

    user = User(
        username=normalized_username,
        password_hash=hash_password(password),
        role=role,
        is_active=is_active,
    )
    try:
        with session.begin():
            session.add(user)
            session.flush()
    except IntegrityError as exc:
        raise UserManagementError("이미 사용 중인 사용자명입니다.") from exc
    return user


def _require_target(session: Session, user_id: int) -> User:
    user = session.get(User, user_id)
    if user is None:
        raise UserManagementError("사용자를 찾을 수 없습니다.")
    return user


def _would_remove_last_active_admin(user: User, role: UserRole, is_active: bool) -> bool:
    return (
        user.is_active
        and user.role is UserRole.ADMIN
        and (role is not UserRole.ADMIN or not is_active)
    )


def update_user(
    session: Session,
    *,
    target_user_id: int,
    actor_user_id: int,
    role: UserRole,
    is_active: bool,
) -> User:
    """Update role/activity in one transaction while protecting administrators."""
    with session.begin():
        user = _require_target(session, target_user_id)
        if actor_user_id == user.id and not is_active:
            raise UserManagementError("자기 자신을 비활성화할 수 없습니다.")
        if _would_remove_last_active_admin(user, role, is_active):
            active_admin_count = session.scalar(
                select(func.count())
                .select_from(User)
                .where(User.is_active.is_(True), User.role == UserRole.ADMIN)
            )
            if active_admin_count <= 1:
                raise UserManagementError("마지막 활성 ADMIN은 변경할 수 없습니다.")
        user.role = role
        user.is_active = is_active
    return user


def toggle_user_active(
    session: Session, *, target_user_id: int, actor_user_id: int
) -> User:
    with session.begin():
        user = _require_target(session, target_user_id)
        new_is_active = not user.is_active
        if actor_user_id == user.id and not new_is_active:
            raise UserManagementError("자기 자신을 비활성화할 수 없습니다.")
        if _would_remove_last_active_admin(user, user.role, new_is_active):
            active_admin_count = session.scalar(
                select(func.count())
                .select_from(User)
                .where(User.is_active.is_(True), User.role == UserRole.ADMIN)
            )
            if active_admin_count <= 1:
                raise UserManagementError("마지막 활성 ADMIN은 비활성화할 수 없습니다.")
        user.is_active = new_is_active
    return user


def reset_password(session: Session, *, target_user_id: int, password: str) -> None:
    if not password:
        raise UserManagementError("새 비밀번호는 필수입니다.")
    with session.begin():
        user = _require_target(session, target_user_id)
        user.password_hash = hash_password(password)
