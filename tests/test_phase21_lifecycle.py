"""Phase 21 project expiration and false-positive suppression tests."""

import asyncio
import re
from datetime import date, timedelta
from pathlib import Path

from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.security import hash_password
from app.config import Settings
from app.db.models.analysis_run import AnalysisRun
from app.db.models.diagnostic_rule import DiagnosticRule
from app.db.models.enums import (
    AnalysisStatus,
    FindingStatus,
    ImplementationStatus,
    Language,
    Severity,
    UserRole,
)
from app.db.models.finding import Finding
from app.db.models.finding_suppression import FindingSuppression
from app.db.models.finding_suppression_hit import FindingSuppressionHit
from app.db.models.project import Project, ProjectUser
from app.db.models.rule import Rule
from app.db.models.user import User
from app.findings.services import (
    FindingPersistenceMetrics,
    persist_normalized_findings,
    update_finding_workflow,
)
from app.main import create_app
from app.projects import services as project_services
from app.projects.services import create_project, delete_expired_projects


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        app_env="test",
        database_url=f"sqlite:///{tmp_path / 'phase21.db'}",
        session_secret="test-session-secret-at-least-32-characters",
        upload_dir=tmp_path / "uploads",
        max_upload_bytes=20 * 1024 * 1024,
        max_extracted_bytes=100 * 1024 * 1024,
        max_archive_files=2_000,
        max_single_file_bytes=10 * 1024 * 1024,
        semgrep_timeout_seconds=60,
        template_dir=Path("app/templates").resolve(),
        static_dir=Path("app/static").resolve(),
        project_expiry_sweep_seconds=3_600,
    )


def _csrf_token(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


async def _login(client: AsyncClient, username: str, password: str) -> None:
    page = await client.get("/login")
    response = await client.post(
        "/login",
        data={
            "username": username,
            "password": password,
            "csrf_token": _csrf_token(page.text),
        },
    )
    assert response.status_code == 303


def test_expired_project_is_hidden_and_cleanup_removes_db_and_source(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    application = create_app(settings)

    async def exercise() -> int:
        async with application.router.lifespan_context(application):
            with Session(application.state.db_engine) as session:
                admin = session.scalar(
                    select(User).where(User.username == "admin@company.com")
                )
                assert admin is not None
                admin_id = admin.id
                session.rollback()
                project = create_project(
                    session,
                    name="Expired customer project",
                    description=None,
                    language=Language.PYTHON,
                    created_by=admin_id,
                    expires_on=date.today(),
                )
                project_id = project.id

            source_dir = (
                settings.upload_dir
                / "projects"
                / str(project_id)
                / "sources"
                / "source-1"
            )
            source_dir.mkdir(parents=True)
            (source_dir / "app.py").write_text("print('expired')")

            transport = ASGITransport(app=application)
            async with AsyncClient(
                transport=transport,
                base_url="http://test",
                follow_redirects=False,
            ) as client:
                await _login(client, "admin@company.com", "admin")
                listing = await client.get("/projects")
                assert "Expired customer project" not in listing.text
                assert (await client.get(f"/projects/{project_id}")).status_code == 404

            deleted = delete_expired_projects(
                application.state.session_factory,
                upload_dir=settings.upload_dir,
                today=date.today(),
            )
            assert deleted == [project_id]
            assert not (settings.upload_dir / "projects" / str(project_id)).exists()
            return project_id

    project_id = asyncio.run(exercise())
    with Session(application.state.db_engine) as session:
        assert session.get(Project, project_id) is None


def test_expiry_cleanup_continues_after_one_project_fails(
    tmp_path: Path, monkeypatch
) -> None:
    application = create_app(_settings(tmp_path))

    async def prepare() -> tuple[int, int]:
        async with application.router.lifespan_context(application):
            with Session(application.state.db_engine) as session:
                admin = session.scalar(
                    select(User).where(User.username == "admin@company.com")
                )
                assert admin is not None
                admin_id = admin.id
                session.rollback()
                first = create_project(
                    session,
                    name="Cleanup failure",
                    description=None,
                    language=Language.PYTHON,
                    created_by=admin_id,
                    expires_on=date.today(),
                )
                first_id = first.id
                session.rollback()
                second = create_project(
                    session,
                    name="Cleanup succeeds",
                    description=None,
                    language=Language.PYTHON,
                    created_by=admin_id,
                    expires_on=date.today(),
                )
                return first_id, second.id

    first_id, second_id = asyncio.run(prepare())
    original_delete = project_services.delete_project

    def fail_one_project(session, *, project_id: int, upload_dir: Path) -> None:
        if project_id == first_id:
            raise OSError("simulated cleanup failure")
        original_delete(session, project_id=project_id, upload_dir=upload_dir)

    monkeypatch.setattr(project_services, "delete_project", fail_one_project)
    deleted = delete_expired_projects(
        application.state.session_factory,
        upload_dir=application.state.settings.upload_dir,
    )

    assert deleted == [second_id]
    with Session(application.state.db_engine) as session:
        assert session.get(Project, first_id) is not None
        assert session.get(Project, second_id) is None


def test_only_super_admin_can_change_project_expiration(tmp_path: Path) -> None:
    application = create_app(_settings(tmp_path))
    future_date = date.today() + timedelta(days=30)

    async def exercise() -> int:
        async with application.router.lifespan_context(application):
            with Session(application.state.db_engine) as session:
                admin = session.scalar(
                    select(User).where(User.username == "admin@company.com")
                )
                assert admin is not None
                admin_id = admin.id
                session.rollback()
                project = create_project(
                    session,
                    name="Lifecycle project",
                    description=None,
                    language=Language.PYTHON,
                    created_by=admin_id,
                    expires_on=future_date,
                )
                project_id = project.id
                session.rollback()
                with session.begin():
                    manager = User(
                        username="manager@company.com",
                        password_hash=hash_password("manager-password"),
                        role=UserRole.PROJECT_MANAGER,
                        must_change_password=False,
                    )
                    session.add(manager)
                    session.flush()
                    session.add(
                        ProjectUser(project_id=project_id, user_id=manager.id)
                    )

            transport = ASGITransport(app=application)
            async with AsyncClient(
                transport=transport,
                base_url="http://test",
                follow_redirects=False,
            ) as manager_client:
                await _login(
                    manager_client, "manager@company.com", "manager-password"
                )
                edit_page = await manager_client.get(f"/projects/{project_id}/edit")
                assert "프로젝트 만료일" not in edit_page.text
                response = await manager_client.post(
                    f"/projects/{project_id}/edit",
                    data={
                        "name": "Lifecycle project updated",
                        "language": "PYTHON",
                        "expires_on": date.today().isoformat(),
                        "csrf_token": _csrf_token(edit_page.text),
                    },
                )
                assert response.status_code == 303
            return project_id

    project_id = asyncio.run(exercise())
    with Session(application.state.db_engine) as session:
        project = session.get(Project, project_id)
        assert project is not None
        assert project.name == "Lifecycle project updated"
        assert project.expires_on == future_date


def test_project_creation_rejects_immediately_expired_date(tmp_path: Path) -> None:
    application = create_app(_settings(tmp_path))
    tomorrow = (date.today() + timedelta(days=1)).isoformat()

    async def exercise() -> None:
        async with application.router.lifespan_context(application):
            transport = ASGITransport(app=application)
            async with AsyncClient(
                transport=transport,
                base_url="http://test",
                follow_redirects=False,
            ) as client:
                await _login(client, "admin@company.com", "admin")
                form = await client.get("/projects/new")
                assert form.status_code == 200
                assert f'min="{tomorrow}"' in form.text
                response = await client.post(
                    "/projects",
                    data={
                        "name": "Must not disappear",
                        "language": "PYTHON",
                        "expires_on": date.today().isoformat(),
                        "csrf_token": _csrf_token(form.text),
                    },
                )
                assert response.status_code == 400
                assert "만료일은 내일 이후 날짜로 지정해야 합니다." in response.text

    asyncio.run(exercise())
    with Session(application.state.db_engine) as session:
        assert session.scalar(
            select(Project).where(Project.name == "Must not disappear")
        ) is None


def _semgrep_result(*, lines: str, line_number: int = 3, path: str = "src/app.py"):
    return {
        "results": [
            {
                "check_id": "phase21.python.rule",
                "path": path,
                "start": {"line": line_number, "col": 1},
                "end": {"line": line_number, "col": 10},
                "extra": {
                    "message": "Potential issue",
                    "severity": "ERROR",
                    "lines": lines,
                    "metadata": {
                        "kisa_standard_id": "PHASE21-1",
                        "confidence": "HIGH",
                    },
                },
            }
        ],
        "errors": [],
    }


def test_false_positive_suppression_is_exact_scoped_and_reversible(tmp_path: Path) -> None:
    application = create_app(_settings(tmp_path))

    async def exercise() -> tuple[int, int, int, int]:
        async with application.router.lifespan_context(application):
            with Session(application.state.db_engine) as session:
                admin = session.scalar(
                    select(User).where(User.username == "admin@company.com")
                )
                assert admin is not None
                admin_id = admin.id
                session.rollback()
                first_project = create_project(
                    session,
                    name="Suppression target",
                    description=None,
                    language=Language.PYTHON,
                    created_by=admin_id,
                )
                first_project_id = first_project.id
                session.rollback()
                second_project = create_project(
                    session,
                    name="Other project",
                    description=None,
                    language=Language.PYTHON,
                    created_by=admin_id,
                )
                second_project_id = second_project.id
                session.rollback()
                with session.begin():
                    viewer = User(
                        username="suppression-viewer@company.com",
                        password_hash=hash_password("viewer-password"),
                        role=UserRole.USER,
                        must_change_password=False,
                    )
                    manager = User(
                        username="suppression-manager@company.com",
                        password_hash=hash_password("viewer-password"),
                        role=UserRole.PROJECT_MANAGER,
                        must_change_password=False,
                    )
                    outsider = User(
                        username="suppression-outsider@company.com",
                        password_hash=hash_password("viewer-password"),
                        role=UserRole.USER,
                        must_change_password=False,
                    )
                    session.add_all([viewer, manager, outsider])
                    session.flush()
                    session.add_all(
                        [
                            ProjectUser(
                                project_id=first_project_id, user_id=viewer.id
                            ),
                            ProjectUser(
                                project_id=first_project_id, user_id=manager.id
                            ),
                        ]
                    )
                    rule = Rule(
                        name="Phase 21 rule",
                        description="Suppression test",
                        standard_id="PHASE21-1",
                        category="TEST",
                        item_number=1,
                        is_active=True,
                        severity=Severity.HIGH,
                        supported_languages=[Language.PYTHON.value],
                        implementation_status=ImplementationStatus.PARTIAL,
                        semgrep_rule_id="phase21.python.rule",
                    )
                    session.add(rule)
                    session.flush()
                    session.add(
                        DiagnosticRule(
                            catalog_rule_id=rule.id,
                            language=Language.PYTHON,
                            semgrep_rule_id="phase21.python.rule",
                            is_active=True,
                        )
                    )

            source_root = tmp_path / "source"
            source_root.mkdir()

            def create_run(project_id: int) -> int:
                with Session(application.state.db_engine) as session:
                    with session.begin():
                        run = AnalysisRun(
                            project_id=project_id,
                            engine="Semgrep",
                            language=Language.PYTHON,
                            status=AnalysisStatus.RUNNING,
                            executed_by=admin_id,
                        )
                        session.add(run)
                        session.flush()
                        return run.id

            first_run_id = create_run(first_project_id)
            with Session(application.state.db_engine) as session:
                with session.begin():
                    assert persist_normalized_findings(
                        session,
                        analysis_run_id=first_run_id,
                        semgrep_result=_semgrep_result(lines="dangerous(value)"),
                        source_root=source_root,
                    ) == 1
                finding = session.scalar(
                    select(Finding).where(Finding.analysis_run_id == first_run_id)
                )
                assert finding is not None
                finding_id = finding.id
                session.rollback()
                update_finding_workflow(
                    session,
                    finding_id=finding_id,
                    workflow_status=FindingStatus.FALSE_POSITIVE,
                    note="검토 결과 안전한 내부 입력",
                    assignee_id=None,
                    due_date=None,
                    updated_by=admin_id,
                )

            same_run_id = create_run(first_project_id)
            same_metrics = FindingPersistenceMetrics()
            with Session(application.state.db_engine) as session:
                with session.begin():
                    stored = persist_normalized_findings(
                        session,
                        analysis_run_id=same_run_id,
                        semgrep_result=_semgrep_result(
                            lines="dangerous(value)   ", line_number=99
                        ),
                        source_root=source_root,
                        metrics=same_metrics,
                    )
                    same_run = session.get(AnalysisRun, same_run_id)
                    assert same_run is not None
                    same_run.summary = {
                        "finding_count": 1,
                        "stored_finding_count": 0,
                        "suppressed_finding_count": same_metrics.suppressed_count,
                        "error_count": 0,
                    }
                assert stored == 0
                assert same_metrics.suppressed_count == 1

            transport = ASGITransport(app=application)
            for username, password in (
                ("admin@company.com", "admin"),
                ("suppression-manager@company.com", "viewer-password"),
                ("suppression-viewer@company.com", "viewer-password"),
            ):
                async with AsyncClient(
                    transport=transport,
                    base_url="http://test",
                    follow_redirects=False,
                ) as client:
                    await _login(client, username, password)
                    detail = await client.get(f"/analysis/{same_run_id}")
                    assert detail.status_code == 200
                    assert f"/analysis/{same_run_id}/suppressions" in detail.text
                    history = await client.get(
                        f"/analysis/{same_run_id}/suppressions"
                    )
                    assert history.status_code == 200
                    assert "PHASE21-1" in history.text
                    assert "src/app.py:99" in history.text
                    assert "검토 결과 안전한 내부 입력" in history.text
                    assert "dangerous(value)" not in history.text

            async with AsyncClient(
                transport=transport,
                base_url="http://test",
                follow_redirects=False,
            ) as outsider_client:
                await _login(
                    outsider_client,
                    "suppression-outsider@company.com",
                    "viewer-password",
                )
                assert (
                    await outsider_client.get(
                        f"/analysis/{same_run_id}/suppressions"
                    )
                ).status_code == 404

            changed_run_id = create_run(first_project_id)
            with Session(application.state.db_engine) as session:
                with session.begin():
                    assert persist_normalized_findings(
                        session,
                        analysis_run_id=changed_run_id,
                        semgrep_result=_semgrep_result(lines="dangerous(other_value)"),
                        source_root=source_root,
                    ) == 1

            other_run_id = create_run(second_project_id)
            with Session(application.state.db_engine) as session:
                with session.begin():
                    assert persist_normalized_findings(
                        session,
                        analysis_run_id=other_run_id,
                        semgrep_result=_semgrep_result(lines="dangerous(value)"),
                        source_root=source_root,
                    ) == 1

            with Session(application.state.db_engine) as session:
                update_finding_workflow(
                    session,
                    finding_id=finding_id,
                    workflow_status=FindingStatus.OPEN,
                    note="오탐 판단 해제",
                    assignee_id=None,
                    due_date=None,
                    updated_by=admin_id,
                )
            restored_run_id = create_run(first_project_id)
            with Session(application.state.db_engine) as session:
                with session.begin():
                    assert persist_normalized_findings(
                        session,
                        analysis_run_id=restored_run_id,
                        semgrep_result=_semgrep_result(lines="dangerous(value)"),
                        source_root=source_root,
                    ) == 1
                assert session.scalar(
                    select(func.count())
                    .select_from(FindingSuppression)
                    .where(FindingSuppression.is_active.is_(True))
                ) == 0
            return first_project_id, finding_id, same_run_id, restored_run_id

    first_project_id, finding_id, same_run_id, restored_run_id = asyncio.run(exercise())
    with Session(application.state.db_engine) as session:
        suppression = session.scalar(
            select(FindingSuppression).where(
                FindingSuppression.project_id == first_project_id
            )
        )
        assert suppression is not None
        assert suppression.source_finding_id == finding_id
        assert suppression.is_active is False
        assert session.scalar(
            select(func.count(Finding.id)).where(
                Finding.analysis_run_id == same_run_id
            )
        ) == 0
        assert session.scalar(
            select(func.count(Finding.id)).where(
                Finding.analysis_run_id == restored_run_id
            )
        ) == 1
        hit = session.scalar(
            select(FindingSuppressionHit).where(
                FindingSuppressionHit.analysis_run_id == same_run_id
            )
        )
        assert hit is not None
        assert hit.source_finding_id == finding_id
        assert hit.kisa_id == "PHASE21-1"
        assert hit.semgrep_rule_id == "phase21.python.rule"
        assert hit.file_path == "src/app.py"
        assert hit.start_line == 99
        assert hit.review_note == "검토 결과 안전한 내부 입력"
        assert hit.reviewed_at is not None
