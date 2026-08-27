"""Server-rendered project management routes for Phase 4."""

from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Response, UploadFile, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.dependencies import current_active_user, get_db, is_admin
from app.auth.session import csrf_is_valid, csrf_token, persist_session
from app.analysis.service import AnalysisExecutionError, execute_project_analysis
from app.db.models.analysis_run import AnalysisRun
from app.db.models.enums import Confidence, Language, Severity
from app.db.models.finding import Finding
from app.db.models.project import Project, ProjectUser
from app.db.models.user import User
from app.projects.services import (
    ProjectManagementError,
    create_project,
    replace_project_members,
    update_project_source,
    update_project,
)
from app.projects.upload import SourceUploadError, save_project_source


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
    return user


def _require_admin(request: Request, session: Session) -> User | RedirectResponse:
    user = _require_user(request, session)
    if isinstance(user, RedirectResponse):
        return user
    if not is_admin(user):
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


def _accessible_project_or_404(
    session: Session, project_id: int, user: User
) -> Project:
    statement = select(Project).where(Project.id == project_id)
    if not is_admin(user):
        statement = statement.join(ProjectUser).where(ProjectUser.user_id == user.id)
    project = session.scalar(statement)
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return project


@router.get("/projects", response_class=HTMLResponse)
async def project_list(request: Request, session: Session = Depends(get_db)) -> Response:
    user = _require_user(request, session)
    if isinstance(user, RedirectResponse):
        return user
    statement = select(Project).order_by(Project.name)
    if not is_admin(user):
        statement = statement.join(ProjectUser).where(ProjectUser.user_id == user.id)
    projects = session.scalars(statement).all()
    return _render(
        request,
        "projects/list.html",
        {"projects": projects, "current_user": user, "is_admin": is_admin(user)},
    )


@router.get("/projects/new", response_class=HTMLResponse)
async def new_project_page(request: Request, session: Session = Depends(get_db)) -> Response:
    admin = _require_admin(request, session)
    if isinstance(admin, RedirectResponse):
        return admin
    return _render(
        request,
        "projects/form.html",
        {"mode": "create", "project": None, "error": None, "current_user": admin},
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
    admin = _require_admin(request, session)
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
    project = _accessible_project_or_404(session, project_id, user)
    return _render(
        request,
        "projects/detail.html",
        {
            "project": project,
            "current_user": user,
            "is_admin": is_admin(user),
            "upload_error": None,
            "analysis_error": None,
        },
    )


@router.get("/projects/{project_id}/edit", response_class=HTMLResponse)
async def edit_project_page(
    project_id: int, request: Request, session: Session = Depends(get_db)
) -> Response:
    admin = _require_admin(request, session)
    if isinstance(admin, RedirectResponse):
        return admin
    project = _accessible_project_or_404(session, project_id, admin)
    return _render(
        request,
        "projects/form.html",
        {"mode": "edit", "project": project, "error": None, "current_user": admin},
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
    admin = _require_admin(request, session)
    if isinstance(admin, RedirectResponse):
        return admin
    _accessible_project_or_404(session, project_id, admin)
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
            {"mode": "edit", "project": project, "error": str(exc), "current_user": admin},
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    return _redirect(f"/projects/{project_id}", request)


@router.get("/projects/{project_id}/users", response_class=HTMLResponse)
async def project_users_page(
    project_id: int, request: Request, session: Session = Depends(get_db)
) -> Response:
    admin = _require_admin(request, session)
    if isinstance(admin, RedirectResponse):
        return admin
    project = _accessible_project_or_404(session, project_id, admin)
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
            "current_user": admin,
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
    admin = _require_admin(request, session)
    if isinstance(admin, RedirectResponse):
        return admin
    _accessible_project_or_404(session, project_id, admin)
    try:
        session.rollback()
        replace_project_members(session, project_id=project_id, user_ids=user_ids)
    except ProjectManagementError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return _redirect(f"/projects/{project_id}/users", request)


@router.post("/projects/{project_id}/analysis", response_class=HTMLResponse)
async def upload_project_source_or_run_analysis(
    project_id: int,
    request: Request,
    source_file: Annotated[UploadFile | None, File()] = None,
    submitted_csrf_token: Annotated[str, Form(alias="csrf_token")] = "",
    session: Session = Depends(get_db),
) -> Response:
    """Store a source ZIP when supplied, otherwise execute Semgrep for the project."""
    _csrf_or_403(request, submitted_csrf_token)
    user = _require_user(request, session)
    if isinstance(user, RedirectResponse):
        return user
    project = _accessible_project_or_404(session, project_id, user)
    stored_project_id = project.id
    if source_file is not None:
        try:
            source_path = await save_project_source(
                source_file, project_id=stored_project_id, settings=request.app.state.settings
            )
            session.rollback()
            update_project_source(session, project_id=stored_project_id, source_path=source_path)
        except (ProjectManagementError, SourceUploadError) as exc:
            return _render(
                request,
                "projects/detail.html",
                {
                    "project": project,
                    "current_user": user,
                    "is_admin": is_admin(user),
                    "upload_error": str(exc),
                    "analysis_error": None,
                },
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        return _redirect(f"/projects/{project_id}", request)

    try:
        user_id = user.id
        session.rollback()
        analysis_run = execute_project_analysis(
            session,
            project_id=stored_project_id,
            executed_by=user_id,
            settings=request.app.state.settings,
        )
    except AnalysisExecutionError as exc:
        return _render(
            request,
            "projects/detail.html",
            {
                "project": project,
                "current_user": user,
                "is_admin": is_admin(user),
                "upload_error": None,
                "analysis_error": str(exc),
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    return _redirect(f"/analysis/{analysis_run.id}", request)


@router.get("/projects/{project_id}/analysis", response_class=HTMLResponse)
async def project_analysis_list(
    project_id: int, request: Request, session: Session = Depends(get_db)
) -> Response:
    user = _require_user(request, session)
    if isinstance(user, RedirectResponse):
        return user
    project = _accessible_project_or_404(session, project_id, user)
    analysis_runs = session.scalars(
        select(AnalysisRun)
        .where(AnalysisRun.project_id == project.id)
        .order_by(AnalysisRun.id.desc())
    ).all()
    return _render(
        request,
        "analysis/list.html",
        {"project": project, "analysis_runs": analysis_runs, "current_user": user},
    )


@router.get("/analysis/{analysis_id}", response_class=HTMLResponse)
async def analysis_detail(
    analysis_id: int, request: Request, session: Session = Depends(get_db)
) -> Response:
    user = _require_user(request, session)
    if isinstance(user, RedirectResponse):
        return user
    analysis_run = session.get(AnalysisRun, analysis_id)
    if analysis_run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    _accessible_project_or_404(session, analysis_run.project_id, user)
    return _render(
        request,
        "analysis/detail.html",
        {"analysis_run": analysis_run, "current_user": user},
    )


def _parse_filter_enum(value: str | None, enum_type: type[Severity] | type[Confidence]):
    if value is None or value == "":
        return None
    try:
        return enum_type(value)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST) from exc


@router.get("/analysis/{analysis_id}/findings", response_class=HTMLResponse)
async def finding_list(
    analysis_id: int,
    request: Request,
    severity: str | None = None,
    confidence: str | None = None,
    session: Session = Depends(get_db),
) -> Response:
    user = _require_user(request, session)
    if isinstance(user, RedirectResponse):
        return user
    analysis_run = session.get(AnalysisRun, analysis_id)
    if analysis_run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    _accessible_project_or_404(session, analysis_run.project_id, user)
    selected_severity = _parse_filter_enum(severity, Severity)
    selected_confidence = _parse_filter_enum(confidence, Confidence)
    statement = select(Finding).where(Finding.analysis_run_id == analysis_run.id)
    if selected_severity is not None:
        statement = statement.where(Finding.severity == selected_severity)
    if selected_confidence is not None:
        statement = statement.where(Finding.confidence == selected_confidence)
    findings = session.scalars(
        statement.order_by(Finding.severity.desc(), Finding.file_path, Finding.start_line)
    ).all()
    return _render(
        request,
        "findings/list.html",
        {
            "analysis_run": analysis_run,
            "findings": findings,
            "severity_values": list(Severity),
            "confidence_values": list(Confidence),
            "selected_severity": selected_severity,
            "selected_confidence": selected_confidence,
            "current_user": user,
        },
    )


@router.get("/findings/{finding_id}", response_class=HTMLResponse)
async def finding_detail(
    finding_id: int, request: Request, session: Session = Depends(get_db)
) -> Response:
    user = _require_user(request, session)
    if isinstance(user, RedirectResponse):
        return user
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    analysis_run = session.get(AnalysisRun, finding.analysis_run_id)
    if analysis_run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    _accessible_project_or_404(session, analysis_run.project_id, user)
    raw_result = dict(finding.raw_result)
    raw_result["path"] = finding.file_path
    return _render(
        request,
        "findings/detail.html",
        {
            "finding": finding,
            "analysis_run": analysis_run,
            "raw_result_json": json.dumps(raw_result, ensure_ascii=False, indent=2),
            "current_user": user,
        },
    )
