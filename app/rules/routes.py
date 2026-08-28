"""KISA catalog query and ADMIN diagnostic-rule mapping routes."""
from typing import Annotated
from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload
from app.auth.dependencies import current_active_user, get_db, is_admin
from app.auth.session import csrf_is_valid, csrf_token, persist_session
from app.db.models.enums import ImplementationStatus, Language
from app.db.models.finding import Finding
from app.db.models.rule import Rule
from app.db.models.user import User
from app.rules.services import DiagnosticRuleManagementError, save_diagnostic_rule_mappings, toggle_catalog_rule_active

router = APIRouter()
def _render(request: Request, name: str, context: dict[str, object], status_code: int = 200) -> HTMLResponse:
    response = request.app.state.templates.TemplateResponse(request=request, name=name, context={**context, "csrf_token": csrf_token(request)}, status_code=status_code); persist_session(response, request); return response
def _redirect(path: str, request: Request) -> RedirectResponse:
    response = RedirectResponse(path, status_code=status.HTTP_303_SEE_OTHER); persist_session(response, request); return response
def _user(request: Request, session: Session) -> User | RedirectResponse:
    user = current_active_user(request, session); return user if user is not None else _redirect("/login", request)
def _admin(request: Request, session: Session) -> User | RedirectResponse:
    user = _user(request, session)
    if not isinstance(user, RedirectResponse) and not is_admin(user): raise HTTPException(status_code=403)
    return user
def _csrf(request: Request, token: str) -> None:
    if not csrf_is_valid(request, token): raise HTTPException(status_code=403)
def _rules(session: Session) -> list[Rule]:
    return session.scalars(select(Rule).options(selectinload(Rule.diagnostic_rules)).order_by(Rule.standard_id)).all()
def _language(value: str) -> Language:
    try: return Language(value)
    except ValueError as exc: raise DiagnosticRuleManagementError("유효하지 않은 지원 언어입니다.") from exc

@router.get("/rules", response_class=HTMLResponse)
async def rule_list(request: Request, q: str = "", category: str = "", implementation_status: str = "", language: str = "", active: str = "", session: Session = Depends(get_db)) -> Response:
    user = _user(request, session)
    if isinstance(user, RedirectResponse): return user
    rules = _rules(session)
    if q: rules = [r for r in rules if q.lower() in r.standard_id.lower() or q.lower() in r.name.lower()]
    if category: rules = [r for r in rules if r.category == category]
    if implementation_status: rules = [r for r in rules if r.implementation_status.value == implementation_status]
    if language: rules = [r for r in rules if language in r.supported_languages]
    if active in {"true", "false"}: rules = [r for r in rules if r.is_active is (active == "true")]
    all_rules = _rules(session)
    return _render(request, "rules/list.html", {"rules": rules, "categories": sorted({r.category for r in all_rules}), "statuses": list(ImplementationStatus), "languages": list(Language), "filters": {"q":q,"category":category,"implementation_status":implementation_status,"language":language,"active":active}, "counts": {s: sum(r.implementation_status is s for r in all_rules) for s in ImplementationStatus}, "current_user": user, "is_admin": is_admin(user)})

@router.get("/rules/{rule_id:int}", response_class=HTMLResponse)
async def rule_detail(rule_id: int, request: Request, session: Session = Depends(get_db)) -> Response:
    user = _user(request, session)
    if isinstance(user, RedirectResponse): return user
    rule = session.scalar(select(Rule).options(selectinload(Rule.diagnostic_rules)).where(Rule.id == rule_id))
    if rule is None: raise HTTPException(status_code=404)
    return _render(request, "rules/detail.html", {"rule": rule, "finding_count": session.scalar(select(func.count()).select_from(Finding).where(Finding.rule_id == rule.id)) or 0, "current_user": user, "is_admin": is_admin(user)})

@router.get("/rules/new", response_class=HTMLResponse)
async def rule_new(request: Request, session: Session = Depends(get_db)) -> Response:
    user = _admin(request, session)
    if isinstance(user, RedirectResponse): return user
    return _render(request, "rules/form.html", {"rule": None, "catalog_rules": _rules(session), "languages": list(Language), "error": None, "current_user": user})

@router.get("/rules/{rule_id:int}/edit", response_class=HTMLResponse)
async def rule_edit(rule_id: int, request: Request, session: Session = Depends(get_db)) -> Response:
    user = _admin(request, session)
    if isinstance(user, RedirectResponse): return user
    rule = session.scalar(select(Rule).options(selectinload(Rule.diagnostic_rules)).where(Rule.id == rule_id))
    if rule is None: raise HTTPException(status_code=404)
    return _render(request, "rules/form.html", {"rule": rule, "catalog_rules": _rules(session), "languages": list(Language), "error": None, "current_user": user})

async def _save(request: Request, session: Session, catalog_rule_id: int, languages: list[str], java_rule_id: str, javascript_rule_id: str, python_rule_id: str, token: str) -> Response:
    _csrf(request, token); user = _admin(request, session)
    if isinstance(user, RedirectResponse): return user
    try:
        selected = [_language(value) for value in languages]
        session.rollback(); rule = save_diagnostic_rule_mappings(session, catalog_rule_id=catalog_rule_id, selected_languages=selected, semgrep_rule_ids={Language.JAVA: java_rule_id, Language.JAVASCRIPT: javascript_rule_id, Language.PYTHON: python_rule_id})
    except DiagnosticRuleManagementError as exc:
        return _render(request, "rules/form.html", {"rule": session.get(Rule, catalog_rule_id), "catalog_rules": _rules(session), "languages": list(Language), "error": str(exc), "current_user": user}, 400)
    return _redirect(f"/rules/{rule.id}", request)

@router.post("/rules", response_class=HTMLResponse)
async def rule_create(request: Request, catalog_rule_id: Annotated[int, Form()], languages: Annotated[list[str], Form()], java_rule_id: Annotated[str, Form()] = "", javascript_rule_id: Annotated[str, Form()] = "", python_rule_id: Annotated[str, Form()] = "", submitted_csrf_token: Annotated[str, Form(alias="csrf_token")] = "", session: Session = Depends(get_db)) -> Response:
    return await _save(request, session, catalog_rule_id, languages, java_rule_id, javascript_rule_id, python_rule_id, submitted_csrf_token)

@router.post("/rules/{rule_id:int}/edit", response_class=HTMLResponse)
async def rule_update(rule_id: int, request: Request, languages: Annotated[list[str], Form()], java_rule_id: Annotated[str, Form()] = "", javascript_rule_id: Annotated[str, Form()] = "", python_rule_id: Annotated[str, Form()] = "", submitted_csrf_token: Annotated[str, Form(alias="csrf_token")] = "", session: Session = Depends(get_db)) -> Response:
    return await _save(request, session, rule_id, languages, java_rule_id, javascript_rule_id, python_rule_id, submitted_csrf_token)

@router.post("/rules/{rule_id:int}/toggle-active")
async def rule_toggle(rule_id: int, request: Request, submitted_csrf_token: Annotated[str, Form(alias="csrf_token")] = "", session: Session = Depends(get_db)) -> Response:
    _csrf(request, submitted_csrf_token); user = _admin(request, session)
    if isinstance(user, RedirectResponse): return user
    try: session.rollback(); toggle_catalog_rule_active(session, catalog_rule_id=rule_id)
    except DiagnosticRuleManagementError as exc: raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _redirect(f"/rules/{rule_id}", request)
