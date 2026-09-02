"""Source intake, analysis execution, and analysis history routes."""

from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Response, UploadFile, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.service import AnalysisExecutionError, execute_project_analysis
from app.analysis.reports import (
    build_analysis_report,
    render_csv_report,
    render_pdf_report,
)
from app.auth.dependencies import can_operate_project, current_active_user, get_db
from app.auth.session import csrf_is_valid, csrf_token, persist_session
from app.db.models.analysis_run import AnalysisRun
from app.db.models.finding import Finding
from app.db.models.user import User
from app.projects.access import accessible_project_or_404
from app.projects.services import (
    ProjectManagementError,
    normalize_source_metadata,
    update_project_source,
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
    if user.must_change_password:
        return _redirect("/account/password", request)
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
    source_version: Annotated[str, Form()] = "",
    deployment_version: Annotated[str, Form()] = "",
    source_description: Annotated[str, Form()] = "",
    submitted_csrf_token: Annotated[str, Form(alias="csrf_token")] = "",
    session: Session = Depends(get_db),
) -> Response:
    """Store a source ZIP when supplied, otherwise execute Semgrep."""
    _csrf_or_403(request, submitted_csrf_token)
    user = _require_user(request, session)
    if isinstance(user, RedirectResponse):
        return user
    project = accessible_project_or_404(session, project_id, user)
    if not can_operate_project(user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    stored_project_id = project.id

    if source_file is not None:
        try:
            normalized_metadata = normalize_source_metadata(
                source_version=source_version,
                deployment_version=deployment_version,
                source_description=source_description,
            )
            stored_source = await save_project_source(
                source_file,
                project_id=stored_project_id,
                settings=request.app.state.settings,
            )
            session.rollback()
            update_project_source(
                session,
                project_id=stored_project_id,
                source_path=stored_source.path,
                source_version=normalized_metadata[0],
                deployment_version=normalized_metadata[1],
                source_description=normalized_metadata[2],
                source_summary=stored_source.summary,
            )
        except (ProjectManagementError, SourceUploadError) as exc:
            return _render(
                request,
                "projects/detail.html",
                {
                    "project": project,
                    "current_user": user,
                    "can_manage_project": True,
                    "upload_error": str(exc),
                    "analysis_error": None,
                    "submitted_source_metadata": {
                        "source_version": source_version,
                        "deployment_version": deployment_version,
                        "source_description": source_description,
                    },
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
                "can_manage_project": True,
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
            "can_view_error": can_operate_project(user),
        },
    )


def _analysis_report_data(
    *, analysis_id: int, request: Request, session: Session
):
    user = _require_user(request, session)
    if isinstance(user, RedirectResponse):
        return user
    analysis_run = session.get(AnalysisRun, analysis_id)
    if analysis_run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    project = accessible_project_or_404(session, analysis_run.project_id, user)
    findings = session.scalars(
        select(Finding)
        .where(Finding.analysis_run_id == analysis_run.id)
        .order_by(Finding.id)
    ).all()
    return build_analysis_report(
        analysis_run=analysis_run,
        project=project,
        findings=list(findings),
    )


@router.get("/analysis/{analysis_id}/report.csv")
async def analysis_csv_report(
    analysis_id: int, request: Request, session: Session = Depends(get_db)
) -> Response:
    report = _analysis_report_data(
        analysis_id=analysis_id, request=request, session=session
    )
    if isinstance(report, RedirectResponse):
        return report
    response = Response(
        content=render_csv_report(report),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": (
                f'attachment; filename="analysis-{analysis_id}-report.csv"'
            ),
            "X-Content-Type-Options": "nosniff",
        },
    )
    persist_session(response, request)
    return response


@router.get("/analysis/{analysis_id}/report.pdf")
async def analysis_pdf_report(
    analysis_id: int, request: Request, session: Session = Depends(get_db)
) -> Response:
    report = _analysis_report_data(
        analysis_id=analysis_id, request=request, session=session
    )
    if isinstance(report, RedirectResponse):
        return report
    response = Response(
        content=render_pdf_report(report),
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="analysis-{analysis_id}-report.pdf"'
            ),
            "X-Content-Type-Options": "nosniff",
        },
    )
    persist_session(response, request)
    return response
