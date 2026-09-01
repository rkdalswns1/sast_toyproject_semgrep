"""Server-rendered project management routes for Phase 4."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.dependencies import (
    can_operate_project,
    current_active_user,
    get_db,
    is_super_admin,
)
from app.auth.session import csrf_is_valid, csrf_token, persist_session
from app.analysis.languages import LANGUAGE_PROFILES
from app.db.models.enums import Language
from app.db.models.project import Project, ProjectUser
from app.db.models.user import User
from app.projects.access import accessible_project_or_404
from app.projects.services import (
    ProjectManagementError,
    create_project,
    replace_project_members,
    update_project,
)


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


def _require_user(request: Request, session: Session) -> User | RedirectResponse:
    user = current_active_user(request, session)
    if user is None:
        return _redirect("/login", request)
    if user.must_change_password:
        return _redirect("/account/password", request)
    return user


def _require_super_admin(request: Request, session: Session) -> User | RedirectResponse:
    user = _require_user(request, session)
    if isinstance(user, RedirectResponse):
        return user
    if not is_super_admin(user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    return user


def _csrf_or_403(request: Request, submitted_token: str) -> None:
    if not csrf_is_valid(request, submitted_token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token")


def _parse_language(value: str) -> Language:
    try:
        return Language(value)
    except ValueError as exc:
        raise ProjectManagementError("유효하지 않은 언어입니다.") from exc


@router.get("/projects", response_class=HTMLResponse)
async def project_list(request: Request, session: Session = Depends(get_db)) -> Response:
    user = _require_user(request, session)
    if isinstance(user, RedirectResponse):
        return user
    statement = select(Project).order_by(Project.name)
    if not is_super_admin(user):
        statement = statement.join(ProjectUser).where(ProjectUser.user_id == user.id)
    projects = session.scalars(statement).all()
    return _render(
        request,
        "projects/list.html",
        {
            "projects": projects,
            "current_user": user,
            "is_super_admin": is_super_admin(user),
        },
    )


@router.get("/projects/new", response_class=HTMLResponse)
async def new_project_page(request: Request, session: Session = Depends(get_db)) -> Response:
    admin = _require_super_admin(request, session)
    if isinstance(admin, RedirectResponse):
        return admin
    return _render(
        request,
        "projects/form.html",
        {
            "mode": "create",
            "project": None,
            "error": None,
            "current_user": admin,
            "language_profiles": LANGUAGE_PROFILES,
        },
    )


@router.post("/projects", response_class=HTMLResponse)
async def create_project_page(
    request: Request,
    name: Annotated[str, Form()],
    description: Annotated[str, Form()] = "",
    language: Annotated[str, Form()] = "",
    submitted_csrf_token: Annotated[str, Form(alias="csrf_token")] = "",
    session: Session = Depends(get_db),
) -> Response:
    _csrf_or_403(request, submitted_csrf_token)
    admin = _require_super_admin(request, session)
    if isinstance(admin, RedirectResponse):
        return admin
    try:
        creator_id = admin.id
        session.rollback()
        project = create_project(
            session,
            name=name,
            description=description,
            language=_parse_language(language),
            created_by=creator_id,
        )
    except ProjectManagementError as exc:
        return _render(
            request,
            "projects/form.html",
            {
                "mode": "create",
                "project": None,
                "error": str(exc),
                "current_user": admin,
                "submitted": {"name": name, "description": description, "language": language},
                "language_profiles": LANGUAGE_PROFILES,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    return _redirect(f"/projects/{project.id}", request)


@router.get("/projects/{project_id}", response_class=HTMLResponse)
async def project_detail(
    project_id: int, request: Request, session: Session = Depends(get_db)
) -> Response:
    user = _require_user(request, session)
    if isinstance(user, RedirectResponse):
        return user
    project = accessible_project_or_404(session, project_id, user)
    return _render(
        request,
        "projects/detail.html",
        {
            "project": project,
            "current_user": user,
            "can_manage_project": can_operate_project(user),
            "upload_error": None,
            "analysis_error": None,
        },
    )


@router.get("/projects/{project_id}/edit", response_class=HTMLResponse)
async def edit_project_page(
    project_id: int, request: Request, session: Session = Depends(get_db)
) -> Response:
    user = _require_user(request, session)
    if isinstance(user, RedirectResponse):
        return user
    project = accessible_project_or_404(session, project_id, user)
    if not can_operate_project(user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    return _render(
        request,
        "projects/form.html",
        {
            "mode": "edit",
            "project": project,
            "error": None,
            "current_user": user,
            "language_profiles": LANGUAGE_PROFILES,
        },
    )


@router.post("/projects/{project_id}/edit", response_class=HTMLResponse)
async def edit_project(
    project_id: int,
    request: Request,
    name: Annotated[str, Form()],
    description: Annotated[str, Form()] = "",
    language: Annotated[str, Form()] = "",
    submitted_csrf_token: Annotated[str, Form(alias="csrf_token")] = "",
    session: Session = Depends(get_db),
) -> Response:
    _csrf_or_403(request, submitted_csrf_token)
    user = _require_user(request, session)
    if isinstance(user, RedirectResponse):
        return user
    accessible_project_or_404(session, project_id, user)
    if not can_operate_project(user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    try:
        session.rollback()
        update_project(
            session,
            project_id=project_id,
            name=name,
            description=description,
            language=_parse_language(language),
        )
    except ProjectManagementError as exc:
        project = session.get(Project, project_id)
        return _render(
            request,
            "projects/form.html",
            {
                "mode": "edit",
                "project": project,
                "error": str(exc),
                "current_user": user,
                "language_profiles": LANGUAGE_PROFILES,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    return _redirect(f"/projects/{project_id}", request)


@router.get("/projects/{project_id}/users", response_class=HTMLResponse)
async def project_users_page(
    project_id: int, request: Request, session: Session = Depends(get_db)
) -> Response:
    user = _require_user(request, session)
    if isinstance(user, RedirectResponse):
        return user
    project = accessible_project_or_404(session, project_id, user)
    if not can_operate_project(user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    assigned_user_ids = set(
        session.scalars(
            select(ProjectUser.user_id).where(ProjectUser.project_id == project.id)
        ).all()
    )
    users = session.scalars(select(User).where(User.is_active.is_(True)).order_by(User.username)).all()
    return _render(
        request,
        "projects/users.html",
        {
            "project": project,
            "users": users,
            "assigned_user_ids": assigned_user_ids,
            "current_user": user,
        },
    )


@router.post("/projects/{project_id}/users")
async def update_project_users(
    project_id: int,
    request: Request,
    user_ids: Annotated[list[int], Form()] = [],
    submitted_csrf_token: Annotated[str, Form(alias="csrf_token")] = "",
    session: Session = Depends(get_db),
) -> RedirectResponse:
    _csrf_or_403(request, submitted_csrf_token)
    user = _require_user(request, session)
    if isinstance(user, RedirectResponse):
        return user
    accessible_project_or_404(session, project_id, user)
    if not can_operate_project(user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    try:
        session.rollback()
        replace_project_members(session, project_id=project_id, user_ids=user_ids)
    except ProjectManagementError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return _redirect(f"/projects/{project_id}/users", request)
