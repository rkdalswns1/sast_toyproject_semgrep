import asyncio
import re
from pathlib import Path

from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.security import hash_password
from app.config import Settings
from app.db.models.analysis_run import AnalysisRun
from app.db.models.enums import (
    AnalysisStatus,
    Confidence,
    FindingStatus,
    ImplementationStatus,
    Language,
    RevalidationResult,
    Severity,
    SourceType,
    UserRole,
)
from app.db.models.finding import Finding
from app.db.models.finding_revalidation import FindingRevalidation
from app.db.models.finding_workflow import FindingWorkflow
from app.db.models.project import Project, ProjectUser
from app.db.models.rule import Rule
from app.db.models.user import User
from app.findings import revalidation as revalidation_service
from app.main import create_app


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        app_env="test",
        database_url=f"sqlite:///{tmp_path / 'revalidation.db'}",
        session_secret="test-session-secret-at-least-32-characters",
        upload_dir=tmp_path / "uploads",
        max_upload_bytes=20 * 1024 * 1024,
        max_extracted_bytes=100 * 1024 * 1024,
        max_archive_files=2_000,
        max_single_file_bytes=10 * 1024 * 1024,
        semgrep_timeout_seconds=60,
        template_dir=Path("app/templates").resolve(),
        static_dir=Path("app/static").resolve(),
    )


def _csrf_token(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


async def _login(client: AsyncClient, username: str, password: str) -> None:
    login_page = await client.get("/login")
    response = await client.post(
        "/login",
        data={
            "username": username,
            "password": password,
            "csrf_token": _csrf_token(login_page.text),
        },
    )
    assert response.status_code == 303


def _seed(application) -> tuple[int, int, int, int]:
    with Session(application.state.db_engine) as session:
        admin = session.scalar(
            select(User).where(User.username == "admin@company.com")
        )
        assert admin is not None
        viewer = User(
            username="viewer@company.com",
            password_hash=hash_password("viewer-password"),
            role=UserRole.USER,
            must_change_password=False,
        )
        manager = User(
            username="manager@company.com",
            password_hash=hash_password("manager-password"),
            role=UserRole.PROJECT_MANAGER,
            must_change_password=False,
        )
        outsider = User(
            username="outsider@company.com",
            password_hash=hash_password("outsider-password"),
            role=UserRole.USER,
            must_change_password=False,
        )
        session.add_all([viewer, manager, outsider])
        session.flush()
        project = Project(
            name="Revalidation project",
            source_type=SourceType.ZIP,
            language=Language.PYTHON,
            source_path="unused-by-fake",
            created_by=admin.id,
        )
        session.add(project)
        session.flush()
        session.add_all(
            [
                ProjectUser(project_id=project.id, user_id=admin.id),
                ProjectUser(project_id=project.id, user_id=manager.id),
                ProjectUser(project_id=project.id, user_id=viewer.id),
            ]
        )
        source_rule = session.scalar(
            select(Rule).where(Rule.standard_id == "제1절-1")
        )
        assert source_rule is not None
        other_rule = Rule(
            name="다른 취약점",
            description="test",
            standard_id="TEST-OTHER",
            category="test",
            severity=Severity.MEDIUM,
            supported_languages=[Language.PYTHON.value],
            implementation_status=ImplementationStatus.PARTIAL,
            semgrep_rule_id="test.other",
        )
        session.add(other_rule)
        session.flush()
        source_run = AnalysisRun(
            project_id=project.id,
            engine="Semgrep",
            language=Language.PYTHON,
            status=AnalysisStatus.COMPLETED,
            executed_by=admin.id,
        )
        session.add(source_run)
        session.flush()
        source_finding = Finding(
            analysis_run_id=source_run.id,
            rule_id=source_rule.id,
            rule_name=source_rule.name,
            kisa_id=source_rule.standard_id,
            language=Language.PYTHON,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            file_path="src/vulnerable.py",
            start_line=10,
            message="unsafe query",
            raw_result={
                "check_id": "test.sql-injection",
                "path": "src/vulnerable.py",
            },
        )
        session.add(source_finding)
        session.flush()
        session.add(
            FindingWorkflow(
                finding_id=source_finding.id,
                status=FindingStatus.IN_PROGRESS,
            )
        )
        session.commit()
        return source_finding.id, project.id, viewer.id, other_rule.id


def test_revalidation_outcomes_history_and_read_only_access(
    tmp_path: Path, monkeypatch
) -> None:
    application = create_app(_settings(tmp_path))
    mode = {"value": "exact"}
    ids: dict[str, int] = {}

    def fake_analysis(session, *, project_id, executed_by, settings):
        with session.begin():
            run = AnalysisRun(
                project_id=project_id,
                engine="Semgrep",
                language=Language.PYTHON,
                status=(
                    AnalysisStatus.FAILED
                    if mode["value"] == "failed"
                    else AnalysisStatus.COMPLETED
                ),
                executed_by=executed_by,
                summary={},
            )
            session.add(run)
            session.flush()
            source = session.get(Finding, ids["source_finding_id"])
            assert source is not None
            if mode["value"] in {"exact", "moved"}:
                candidate = Finding(
                    analysis_run_id=run.id,
                    rule_id=source.rule_id,
                    rule_name=source.rule_name,
                    kisa_id=source.kisa_id,
                    language=source.language,
                    severity=source.severity,
                    confidence=source.confidence,
                    file_path=(
                        source.file_path
                        if mode["value"] == "exact"
                        else "src/moved.py"
                    ),
                    start_line=99,
                    message=source.message,
                    raw_result={
                        "check_id": "test.sql-injection",
                        "path": (
                            source.file_path
                            if mode["value"] == "exact"
                            else "src/moved.py"
                        ),
                    },
                )
                session.add(candidate)
                session.flush()
                session.add(FindingWorkflow(finding_id=candidate.id))
            elif mode["value"] == "resolved":
                other_rule = session.get(Rule, ids["other_rule_id"])
                assert other_rule is not None
                new_finding = Finding(
                    analysis_run_id=run.id,
                    rule_id=other_rule.id,
                    rule_name=other_rule.name,
                    kisa_id=other_rule.standard_id,
                    language=Language.PYTHON,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    file_path="src/new_issue.py",
                    start_line=1,
                    message="new issue",
                    raw_result={"check_id": "test.other", "path": "src/new_issue.py"},
                )
                session.add(new_finding)
                session.flush()
                session.add(FindingWorkflow(finding_id=new_finding.id))
        return run

    monkeypatch.setattr(
        revalidation_service, "execute_project_analysis", fake_analysis
    )

    async def exercise() -> tuple[int, int]:
        async with application.router.lifespan_context(application):
            source_finding_id, project_id, viewer_id, other_rule_id = _seed(
                application
            )
            ids.update(
                source_finding_id=source_finding_id,
                other_rule_id=other_rule_id,
            )
            transport = ASGITransport(app=application)
            async with AsyncClient(
                transport=transport,
                base_url="http://testserver",
                follow_redirects=False,
            ) as admin_client:
                await _login(
                    admin_client, "manager@company.com", "manager-password"
                )
                detail = await admin_client.get(f"/findings/{source_finding_id}")
                assert "아직 재검증 이력이 없습니다." in detail.text
                assert (
                    await admin_client.post(
                        f"/findings/{source_finding_id}/revalidate"
                    )
                ).status_code == 403
                token = _csrf_token(detail.text)
                for selected_mode, expected_text in (
                    ("exact", "여전히 탐지됨"),
                    ("moved", "확인 필요"),
                    ("resolved", "해결 추정"),
                    ("failed", "확인 필요"),
                ):
                    mode["value"] = selected_mode
                    response = await admin_client.post(
                        f"/findings/{source_finding_id}/revalidate",
                        data={"csrf_token": token},
                    )
                    assert response.status_code == 303
                    detail = await admin_client.get(
                        f"/findings/{source_finding_id}"
                    )
                    assert expected_text in detail.text

            async with AsyncClient(
                transport=transport,
                base_url="http://testserver",
                follow_redirects=False,
            ) as viewer_client:
                await _login(
                    viewer_client, "viewer@company.com", "viewer-password"
                )
                detail = await viewer_client.get(f"/findings/{source_finding_id}")
                assert detail.status_code == 200
                assert "여전히 탐지됨" in detail.text
                assert "해결 추정" in detail.text
                assert "최신 소스로 재검증" not in detail.text
                projects_page = await viewer_client.get("/projects")
                forbidden = await viewer_client.post(
                    f"/findings/{source_finding_id}/revalidate",
                    data={"csrf_token": _csrf_token(projects_page.text)},
                )
                assert forbidden.status_code == 403

            async with AsyncClient(
                transport=transport,
                base_url="http://testserver",
                follow_redirects=False,
            ) as outsider_client:
                await _login(
                    outsider_client, "outsider@company.com", "outsider-password"
                )
                assert (
                    await outsider_client.get(f"/findings/{source_finding_id}")
                ).status_code == 404
            return source_finding_id, project_id

    source_finding_id, project_id = asyncio.run(exercise())

    with Session(application.state.db_engine) as session:
        history = session.scalars(
            select(FindingRevalidation)
            .where(FindingRevalidation.source_finding_id == source_finding_id)
            .order_by(FindingRevalidation.id)
        ).all()
        assert [item.result for item in history] == [
            RevalidationResult.STILL_DETECTED,
            RevalidationResult.REVIEW_REQUIRED,
            RevalidationResult.LIKELY_RESOLVED,
            RevalidationResult.REVIEW_REQUIRED,
        ]
        assert history[0].matched_finding_id is not None
        assert all(item.executed_by == history[0].executed_by for item in history)
        assert all(item.created_at is not None for item in history)
        workflow = session.get(FindingWorkflow, source_finding_id)
        assert workflow is not None
        assert workflow.status is FindingStatus.IN_PROGRESS
        assert session.scalar(
            select(func.count())
            .select_from(Finding)
            .join(AnalysisRun, AnalysisRun.id == Finding.analysis_run_id)
            .where(
                AnalysisRun.project_id == project_id,
                Finding.kisa_id == "TEST-OTHER",
            )
        ) == 1
