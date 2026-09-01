"""Normalized Finding list, filter, and detail routes."""

import json

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.dependencies import can_operate_project, current_active_user, get_db
from app.auth.session import csrf_is_valid, csrf_token, persist_session
from app.db.models.analysis_run import AnalysisRun
from app.db.models.enums import Confidence, FindingStatus, Severity
from app.db.models.finding import Finding
from app.db.models.finding_workflow import FindingWorkflow
from app.db.models.user import User
from app.projects.access import accessible_project_or_404
from app.findings.services import FindingWorkflowError, update_finding_workflow


router = APIRouter()

FINDING_STATUS_LABELS = {
    FindingStatus.OPEN: "미조치",
    FindingStatus.IN_PROGRESS: "조치 중",
    FindingStatus.RESOLVED: "조치 완료",
    FindingStatus.FALSE_POSITIVE: "오탐",
    FindingStatus.ACCEPTED_RISK: "위험 수용",
}


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


def _parse_filter_enum(
    value: str | None,
    enum_type: type[Severity] | type[Confidence] | type[FindingStatus],
):
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
    status: str | None = None,
    session: Session = Depends(get_db),
) -> Response:
    user = _require_user(request, session)
    if isinstance(user, RedirectResponse):
        return user
    analysis_run = session.get(AnalysisRun, analysis_id)
    if analysis_run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    accessible_project_or_404(session, analysis_run.project_id, user)
    selected_severity = _parse_filter_enum(severity, Severity)
    selected_confidence = _parse_filter_enum(confidence, Confidence)
    selected_status = _parse_filter_enum(status, FindingStatus)
    statement = (
        select(Finding)
        .join(FindingWorkflow, FindingWorkflow.finding_id == Finding.id)
        .where(Finding.analysis_run_id == analysis_run.id)
    )
    if selected_severity is not None:
        statement = statement.where(Finding.severity == selected_severity)
    if selected_confidence is not None:
        statement = statement.where(Finding.confidence == selected_confidence)
    if selected_status is not None:
        statement = statement.where(FindingWorkflow.status == selected_status)
    findings = session.scalars(
        statement.order_by(
            Finding.severity.desc(), Finding.file_path, Finding.start_line
        )
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
            "status_values": list(FindingStatus),
            "status_labels": FINDING_STATUS_LABELS,
            "selected_status": selected_status,
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
    accessible_project_or_404(session, analysis_run.project_id, user)
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
            "can_manage_finding": can_operate_project(user),
            "status_values": list(FindingStatus),
            "status_labels": FINDING_STATUS_LABELS,
            "workflow_error": None,
        },
    )


@router.post("/findings/{finding_id}/status", response_class=HTMLResponse)
async def update_finding_status(
    finding_id: int,
    request: Request,
    workflow_status: str = "",
    note: str = "",
    submitted_csrf_token: str = "",
    session: Session = Depends(get_db),
) -> Response:
    form = await request.form()
    workflow_status = str(form.get("workflow_status", workflow_status))
    note = str(form.get("note", note))
    submitted_csrf_token = str(form.get("csrf_token", submitted_csrf_token))
    if not csrf_is_valid(request, submitted_csrf_token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    user = _require_user(request, session)
    if isinstance(user, RedirectResponse):
        return user
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    analysis_run = session.get(AnalysisRun, finding.analysis_run_id)
    if analysis_run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    accessible_project_or_404(session, analysis_run.project_id, user)
    if not can_operate_project(user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    try:
        parsed_status = FindingStatus(workflow_status)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST) from exc
    user_id = user.id
    session.rollback()
    try:
        update_finding_workflow(
            session,
            finding_id=finding_id,
            workflow_status=parsed_status,
            note=note,
            updated_by=user_id,
        )
    except FindingWorkflowError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    return _redirect(f"/findings/{finding_id}", request)
