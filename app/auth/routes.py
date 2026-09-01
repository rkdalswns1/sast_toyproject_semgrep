"""Authentication, self-service password, and SUPER_ADMIN user routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.dependencies import current_active_user, get_db, is_super_admin
from app.auth.identifiers import AccountIdentifierError, normalize_company_email
from app.auth.security import verify_password
from app.auth.services import (
    UserManagementError,
    change_own_password,
    create_user,
    toggle_user_active,
    update_user,
)
from app.auth.session import (
    csrf_is_valid,
    csrf_token,
    get_session,
    log_in,
    log_out,
    persist_session,
)
from app.db.models.enums import UserRole
from app.db.models.user import User


router = APIRouter()


def _render(
    request: Request, template_name: str, context: dict[str, object], status_code: int = 200
) -> HTMLResponse:
    response = request.app.state.templates.TemplateResponse(
        request=request,
        name=template_name,
        context={**context, "csrf_token": csrf_token(request)},
        status_code=status_code,
    )
    persist_session(response, request)
    return response


def _redirect(path: str, request: Request) -> RedirectResponse:
    response = RedirectResponse(path, status_code=status.HTTP_303_SEE_OTHER)
    persist_session(response, request)
    return response


def _csrf_or_403(request: Request, submitted_token: str) -> None:
    if not csrf_is_valid(request, submitted_token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token")


def _require_super_admin(request: Request, session: Session) -> User | RedirectResponse:
    user = current_active_user(request, session)
    if user is None:
        return _redirect("/login", request)
    if user.must_change_password:
        return _redirect("/account/password", request)
    if not is_super_admin(user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    return user


def _parse_role(value: str) -> UserRole:
    try:
        return UserRole(value)
    except ValueError as exc:
        raise UserManagementError("유효하지 않은 역할입니다.") from exc


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, session: Session = Depends(get_db)) -> Response:
    user = current_active_user(request, session)
    if user is not None:
        return _redirect(
            "/account/password" if user.must_change_password else "/projects", request
        )
    return _render(request, "auth/login.html", {"error": None, "username": ""})


@router.post("/login", response_class=HTMLResponse)
async def login(
    request: Request,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    submitted_csrf_token: Annotated[str, Form(alias="csrf_token")] = "",
    session: Session = Depends(get_db),
) -> Response:
    _csrf_or_403(request, submitted_csrf_token)
    try:
        normalized_username = normalize_company_email(
            username, request.app.state.settings.account_email_domain
        )
    except AccountIdentifierError:
        normalized_username = ""
    user = session.scalar(select(User).where(User.username == normalized_username))
    if user is None or not user.is_active or not verify_password(password, user.password_hash):
        return _render(
            request,
            "auth/login.html",
            {"error": "사용자명 또는 비밀번호가 올바르지 않습니다.", "username": username},
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    log_in(request, user.id)
    return _redirect(
        "/account/password" if user.must_change_password else "/projects", request
    )


@router.post("/logout")
async def logout(
    request: Request,
    submitted_csrf_token: Annotated[str, Form(alias="csrf_token")] = "",
) -> RedirectResponse:
    _csrf_or_403(request, submitted_csrf_token)
    response = RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    log_out(request, response)
    return response


@router.get("/account/password", response_class=HTMLResponse)
async def password_page(
    request: Request, session: Session = Depends(get_db)
) -> Response:
    user = current_active_user(request, session)
    if user is None:
        return _redirect("/login", request)
    return _render(
        request,
        "auth/password.html",
        {
            "current_user": user,
            "error": None,
            "password_change_only": user.must_change_password,
        },
    )


@router.post("/account/password", response_class=HTMLResponse)
async def change_password(
    request: Request,
    current_password: Annotated[str, Form()],
    new_password: Annotated[str, Form()],
    new_password_confirmation: Annotated[str, Form()],
    submitted_csrf_token: Annotated[str, Form(alias="csrf_token")] = "",
    session: Session = Depends(get_db),
) -> Response:
    _csrf_or_403(request, submitted_csrf_token)
    user = current_active_user(request, session)
    if user is None:
        return _redirect("/login", request)
    user_id = user.id
    if new_password != new_password_confirmation:
        return _render(
            request,
            "auth/password.html",
            {
                "current_user": user,
                "error": "새 비밀번호 확인이 일치하지 않습니다.",
                "password_change_only": user.must_change_password,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    try:
        session.rollback()
        change_own_password(
            session,
            user_id=user_id,
            current_password=current_password,
            new_password=new_password,
        )
    except UserManagementError as exc:
        user = session.get(User, user_id)
        return _render(
            request,
            "auth/password.html",
            {
                "current_user": user,
                "error": str(exc),
                "password_change_only": bool(user and user.must_change_password),
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    return _redirect("/projects", request)


@router.get("/users", response_class=HTMLResponse)
async def user_list(request: Request, session: Session = Depends(get_db)) -> Response:
    admin = _require_super_admin(request, session)
    if isinstance(admin, RedirectResponse):
        return admin
    users = session.scalars(select(User).order_by(User.username)).all()
    return _render(request, "users/list.html", {"users": users, "current_user": admin})


@router.get("/users/new", response_class=HTMLResponse)
async def new_user_page(request: Request, session: Session = Depends(get_db)) -> Response:
    admin = _require_super_admin(request, session)
    if isinstance(admin, RedirectResponse):
        return admin
    return _render(
        request,
        "users/form.html",
        {
            "mode": "create",
            "user": None,
            "error": None,
            "current_user": admin,
            "roles": list(UserRole),
        },
    )


@router.post("/users", response_class=HTMLResponse)
async def create_user_page(
    request: Request,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    password_confirmation: Annotated[str, Form()],
    role: Annotated[str, Form()],
    is_active: Annotated[bool, Form()] = False,
    submitted_csrf_token: Annotated[str, Form(alias="csrf_token")] = "",
    session: Session = Depends(get_db),
) -> Response:
    _csrf_or_403(request, submitted_csrf_token)
    admin = _require_super_admin(request, session)
    if isinstance(admin, RedirectResponse):
        return admin
    if password != password_confirmation:
        return _render(
            request,
            "users/form.html",
            {
                "mode": "create",
                "user": None,
                "error": "비밀번호 확인이 일치하지 않습니다.",
                "current_user": admin,
                "submitted": {"username": username, "role": role, "is_active": is_active},
                "roles": list(UserRole),
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    try:
        session.rollback()
        create_user(
            session,
            username=username,
            password=password,
            role=_parse_role(role),
            is_active=is_active,
            email_domain=request.app.state.settings.account_email_domain,
        )
    except UserManagementError as exc:
        return _render(
            request,
            "users/form.html",
            {
                "mode": "create",
                "user": None,
                "error": str(exc),
                "current_user": admin,
                "submitted": {"username": username, "role": role, "is_active": is_active},
                "roles": list(UserRole),
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    return _redirect("/users", request)


@router.get("/users/{user_id}/edit", response_class=HTMLResponse)
async def edit_user_page(
    user_id: int, request: Request, session: Session = Depends(get_db)
) -> Response:
    admin = _require_super_admin(request, session)
    if isinstance(admin, RedirectResponse):
        return admin
    user = session.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return _render(
        request,
        "users/form.html",
        {
            "mode": "edit",
            "user": user,
            "error": None,
            "current_user": admin,
            "roles": list(UserRole),
        },
    )


@router.post("/users/{user_id}/edit", response_class=HTMLResponse)
async def edit_user(
    user_id: int,
    request: Request,
    role: Annotated[str, Form()],
    is_active: Annotated[bool, Form()] = False,
    submitted_csrf_token: Annotated[str, Form(alias="csrf_token")] = "",
    session: Session = Depends(get_db),
) -> Response:
    _csrf_or_403(request, submitted_csrf_token)
    admin = _require_super_admin(request, session)
    if isinstance(admin, RedirectResponse):
        return admin
    user = session.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    try:
        actor_user_id = admin.id
        session.rollback()
        update_user(
            session,
            target_user_id=user_id,
            actor_user_id=actor_user_id,
            role=_parse_role(role),
            is_active=is_active,
        )
    except UserManagementError as exc:
        return _render(
            request,
            "users/form.html",
            {
                "mode": "edit",
                "user": user,
                "error": str(exc),
                "current_user": admin,
                "roles": list(UserRole),
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    return _redirect("/users", request)


@router.post("/users/{user_id}/toggle-active")
async def toggle_active(
    user_id: int,
    request: Request,
    submitted_csrf_token: Annotated[str, Form(alias="csrf_token")] = "",
    session: Session = Depends(get_db),
) -> RedirectResponse:
    _csrf_or_403(request, submitted_csrf_token)
    admin = _require_super_admin(request, session)
    if isinstance(admin, RedirectResponse):
        return admin
    try:
        actor_user_id = admin.id
        session.rollback()
        toggle_user_active(session, target_user_id=user_id, actor_user_id=actor_user_id)
    except UserManagementError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return _redirect("/users", request)
