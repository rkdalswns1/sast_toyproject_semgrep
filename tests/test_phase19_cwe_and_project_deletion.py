"""Phase 19 CWE snapshots, migration, UI, and project deletion tests."""

import asyncio
import re
from pathlib import Path

from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.auth.security import hash_password
from app.config import Settings
from app.db.database import initialize_database
from app.db.models import (
    AnalysisRun,
    DiagnosticRule,
    Finding,
    FindingWorkflow,
    Project,
    ProjectUser,
    Rule,
    SchemaVersion,
    User,
)
from app.db.models.enums import (
    AnalysisStatus,
    Confidence,
    FindingStatus,
    Language,
    Severity,
    SourceType,
    UserRole,
)
from app.findings.services import persist_normalized_findings
from app.main import create_app
from app.rules.cwe import APPROVED_CWE_MAPPINGS


def _settings(tmp_path: Path, name: str) -> Settings:
    return Settings(
        app_env="test",
        database_url=f"sqlite:///{tmp_path / name}",
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


def _csrf(html: str) -> str:
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
            "csrf_token": _csrf(page.text),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303


def _seed_run(session: Session, *, project: Project, user: User) -> AnalysisRun:
    run = AnalysisRun(
        project_id=project.id,
        engine="Semgrep",
        language=Language.PYTHON,
        status=AnalysisStatus.COMPLETED,
        executed_by=user.id,
    )
    session.add(run)
    session.flush()
    return run


def test_approved_29_rule_ids_have_exact_cwe_mapping(tmp_path: Path) -> None:
    application = create_app(_settings(tmp_path, "mapping.db"))

    async def exercise() -> None:
        async with application.router.lifespan_context(application):
            with Session(application.state.db_engine) as session:
                mappings = session.scalars(
                    select(DiagnosticRule).order_by(DiagnosticRule.semgrep_rule_id)
                ).all()
                assert len(mappings) == 29
                assert {mapping.semgrep_rule_id for mapping in mappings} == set(
                    APPROVED_CWE_MAPPINGS
                )
                by_id = {mapping.semgrep_rule_id: mapping for mapping in mappings}
                assert by_id["kisa-2021-sql-injection-python"].primary_cwe_id == "CWE-89"
                assert by_id["kisa-2021-improper-certificate-validation-java"].primary_cwe_id == "CWE-296"
                assert by_id["kisa-2021-improper-certificate-validation-python"].primary_cwe_id == "CWE-295"
                assert by_id["kisa-2021-unsafe-deserialization-java"].primary_cwe_id == "CWE-502"
                assert sum(
                    mapping.cwe_mapping_confidence is Confidence.MEDIUM
                    for mapping in mappings
                ) == 6
                assert all(mapping.related_cwe_ids == [] for mapping in mappings)
                assert all(mapping.remediation_guidance for mapping in mappings)

    asyncio.run(exercise())


def test_finding_snapshots_cwe_and_guidance_and_detail_uses_mitre(tmp_path: Path) -> None:
    application = create_app(_settings(tmp_path, "snapshot.db"))
    source_root = tmp_path / "source"
    source_root.mkdir()
    source_file = source_root / "vulnerable.py"
    source_file.write_text("cursor.execute(query + value)\n", encoding="utf-8")

    async def exercise() -> None:
        async with application.router.lifespan_context(application):
            with Session(application.state.db_engine) as session:
                admin = session.scalar(
                    select(User).where(User.username == "admin@company.com")
                )
                rule = session.scalar(select(Rule).where(Rule.standard_id == "제1절-1"))
                assert admin is not None and rule is not None
                project = Project(
                    name="CWE snapshot",
                    source_type=SourceType.ZIP,
                    language=Language.PYTHON,
                    source_path="",
                    created_by=admin.id,
                )
                session.add(project)
                session.flush()
                session.add(ProjectUser(project_id=project.id, user_id=admin.id))
                run = _seed_run(session, project=project, user=admin)
                count = persist_normalized_findings(
                    session,
                    analysis_run_id=run.id,
                    source_root=source_root,
                    semgrep_result={
                        "results": [
                            {
                                "check_id": "local.kisa-2021-sql-injection-python",
                                "path": str(source_file),
                                "start": {"line": 1, "col": 1},
                                "end": {"line": 1, "col": 30},
                                "extra": {
                                    "message": "SQL query is constructed.",
                                    "severity": "ERROR",
                                    "lines": "cursor.execute(query + value)",
                                    "metadata": {
                                        "kisa_standard_id": "제1절-1",
                                        "confidence": "HIGH",
                                        "recommendation": "YAML value must not win",
                                    },
                                },
                            }
                        ]
                    },
                )
                assert count == 1
                session.commit()
                finding = session.scalar(select(Finding).where(Finding.analysis_run_id == run.id))
                assert finding is not None
                finding_id = finding.id
                original_guidance = finding.recommendation
                assert finding.primary_cwe_id == "CWE-89"
                assert finding.cwe_mapping_confidence is Confidence.HIGH
                assert original_guidance and "매개변수화" in original_guidance

                mapping = session.scalar(
                    select(DiagnosticRule).where(
                        DiagnosticRule.semgrep_rule_id
                        == "kisa-2021-sql-injection-python"
                    )
                )
                assert mapping is not None
                mapping.primary_cwe_id = "CWE-999"
                mapping.remediation_guidance = "새 규칙 권고"
                session.commit()
                session.refresh(finding)
                assert finding.primary_cwe_id == "CWE-89"
                assert finding.recommendation == original_guidance

            async with AsyncClient(
                transport=ASGITransport(app=application), base_url="http://test"
            ) as client:
                await _login(client, "admin@company.com", "admin")
                detail = await client.get(f"/findings/{finding_id}")
                assert detail.status_code == 200
                assert "CWE-89" in detail.text
                assert "https://cwe.mitre.org/data/definitions/89.html" in detail.text
                assert "매개변수화" in detail.text

    asyncio.run(exercise())


def test_migration_14_backfills_only_exact_known_rule_ids(tmp_path: Path) -> None:
    application = create_app(_settings(tmp_path, "migration.db"))

    async def exercise() -> None:
        async with application.router.lifespan_context(application):
            with Session(application.state.db_engine) as session:
                admin = session.scalar(select(User).where(User.username == "admin@company.com"))
                rule = session.scalar(select(Rule).where(Rule.standard_id == "제1절-1"))
                assert admin is not None and rule is not None
                project = Project(name="legacy", source_type=SourceType.ZIP, language=Language.PYTHON, source_path="", created_by=admin.id)
                session.add(project)
                session.flush()
                run = _seed_run(session, project=project, user=admin)
                known = Finding(
                    analysis_run_id=run.id, rule_id=rule.id, rule_name=rule.name,
                    kisa_id=rule.standard_id, language=Language.PYTHON,
                    severity=Severity.HIGH, confidence=Confidence.HIGH,
                    file_path="known.py", start_line=1, message="known",
                    raw_result={"check_id": "prefix.kisa-2021-sql-injection-python"},
                )
                unknown = Finding(
                    analysis_run_id=run.id, rule_id=rule.id, rule_name=rule.name,
                    kisa_id=rule.standard_id, language=Language.PYTHON,
                    severity=Severity.HIGH, confidence=Confidence.HIGH,
                    file_path="unknown.py", start_line=1, message="unknown",
                    raw_result={"check_id": "custom-unknown-rule"},
                )
                session.add_all([known, unknown])
                session.flush()
                known_id, unknown_id = known.id, unknown.id
                session.execute(text("UPDATE diagnostic_rules SET primary_cwe_id = NULL, related_cwe_ids = '[]', cwe_mapping_confidence = NULL, remediation_guidance = NULL"))
                session.delete(session.get(SchemaVersion, 14))
                session.commit()

            initialize_database(application.state.db_engine)
            with Session(application.state.db_engine) as session:
                assert session.get(SchemaVersion, 14) is not None
                assert session.get(Finding, known_id).primary_cwe_id == "CWE-89"
                assert session.get(Finding, unknown_id).primary_cwe_id is None
                assert session.scalar(select(DiagnosticRule).where(DiagnosticRule.semgrep_rule_id == "kisa-2021-sql-injection-python")).primary_cwe_id == "CWE-89"

    asyncio.run(exercise())


def test_super_admin_project_delete_removes_db_tree_and_computed_workspace(
    tmp_path: Path,
) -> None:
    application = create_app(_settings(tmp_path, "delete.db"))

    async def exercise() -> None:
        async with application.router.lifespan_context(application):
            with Session(application.state.db_engine) as session:
                admin = session.scalar(select(User).where(User.username == "admin@company.com"))
                rule = session.scalar(select(Rule).where(Rule.standard_id == "제1절-1"))
                assert admin is not None and rule is not None
                manager = User(
                    username="delete-manager@company.com",
                    password_hash=hash_password("manager-password"),
                    role=UserRole.PROJECT_MANAGER,
                    must_change_password=False,
                )
                session.add(manager)
                session.flush()
                project = Project(
                    name="Delete me", source_type=SourceType.ZIP,
                    language=Language.PYTHON, source_path="untrusted/outside/path",
                    created_by=admin.id,
                )
                session.add(project)
                session.flush()
                project_id = project.id
                session.add_all([
                    ProjectUser(project_id=project_id, user_id=admin.id),
                    ProjectUser(project_id=project_id, user_id=manager.id),
                ])
                run = _seed_run(session, project=project, user=admin)
                finding = Finding(
                    analysis_run_id=run.id, rule_id=rule.id, rule_name=rule.name,
                    kisa_id=rule.standard_id, language=Language.PYTHON,
                    severity=Severity.HIGH, confidence=Confidence.HIGH,
                    file_path="app.py", start_line=1, message="test", raw_result={},
                )
                session.add(finding)
                session.flush()
                session.add(FindingWorkflow(finding_id=finding.id, status=FindingStatus.OPEN))
                run_id, finding_id, manager_id = run.id, finding.id, manager.id
                session.commit()

            project_directory = application.state.settings.upload_dir / "projects" / str(project_id)
            source_directory = project_directory / "sources" / "upload" / "extracted"
            source_directory.mkdir(parents=True)
            (source_directory / "app.py").write_text("secret", encoding="utf-8")

            transport = ASGITransport(app=application)
            async with AsyncClient(transport=transport, base_url="http://test") as manager_client:
                await _login(manager_client, "delete-manager@company.com", "manager-password")
                manager_detail = await manager_client.get(f"/projects/{project_id}")
                assert "프로젝트 삭제" not in manager_detail.text
                assert (await manager_client.post(f"/projects/{project_id}/delete", data={"csrf_token": _csrf(manager_detail.text)})).status_code == 403

            async with AsyncClient(transport=transport, base_url="http://test") as admin_client:
                await _login(admin_client, "admin@company.com", "admin")
                detail = await admin_client.get(f"/projects/{project_id}")
                assert 'class="danger"' in detail.text
                assert "return confirm(" in detail.text
                assert (await admin_client.post(f"/projects/{project_id}/delete")).status_code == 403
                deleted = await admin_client.post(
                    f"/projects/{project_id}/delete",
                    data={"csrf_token": _csrf(detail.text)},
                    follow_redirects=False,
                )
                assert deleted.status_code == 303
                assert deleted.headers["location"] == "/projects"

            with Session(application.state.db_engine) as session:
                assert session.get(Project, project_id) is None
                assert session.get(AnalysisRun, run_id) is None
                assert session.get(Finding, finding_id) is None
                assert session.get(User, manager_id) is not None
            assert not project_directory.exists()
            assert not (tmp_path / "outside").exists()

    asyncio.run(exercise())
