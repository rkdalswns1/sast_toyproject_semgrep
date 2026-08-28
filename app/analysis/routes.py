"""Source intake, analysis execution, and analysis history routes."""

from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Response, UploadFile, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.service import AnalysisExecutionError, execute_project_analysis
from app.auth.dependencies import current_active_user, get_db, is_admin
from app.auth.session import csrf_is_valid, csrf_token, persist_session
from app.db.models.analysis_run import AnalysisRun
from app.db.models.user import User
from app.projects.access import accessible_project_or_404
from app.projects.services import ProjectManagementError, update_project_source
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


def _csrf_or_403(request: Request, submitted_token: str) -> None:
    if not csrf_is_valid(request, submitted_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token"
        )


@router.post("/projects/{project_id}/analysis", response_class=HTMLResponse)
async def upload_project_source_or_run_analysis(
    project_id: int,
    request: Request,
    source_file: Annotated[UploadFile | None, File()] = None,
    submitted_csrf_token: Annotated[str, Form(alias="csrf_token")] = "",
    session: Session = Depends(get_db),
) -> Response:
    """Store a source ZIP when supplied, otherwise execute Semgrep."""
    _csrf_or_403(request, submitted_csrf_token)
    user = _require_user(request, session)
    if isinstance(user, RedirectResponse):
        return user
    project = accessible_project_or_404(session, project_id, user)
    if not is_admin(user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    stored_project_id = project.id

    if source_file is not None:
        try:
            source_path = await save_project_source(
                source_file,
                project_id=stored_project_id,
                settings=request.app.state.settings,
            )
            session.rollback()
            update_project_source(
                session, project_id=stored_project_id, source_path=source_path
            )
        except (ProjectManagementError, SourceUploadError) as exc:
            return _render(
                request,
                "projects/detail.html",
                {
                    "project": project,
                    "current_user": user,
                    "is_admin": True,
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
                "is_admin": True,
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
    project = accessible_project_or_404(session, project_id, user)
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
    accessible_project_or_404(session, analysis_run.project_id, user)
    return _render(
        request,
        "analysis/detail.html",
        {
            "analysis_run": analysis_run,
            "current_user": user,
            "is_admin": is_admin(user),
        },
    )
