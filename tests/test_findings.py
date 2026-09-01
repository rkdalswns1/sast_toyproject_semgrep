import asyncio
import io
import re
import subprocess
import zipfile
from pathlib import Path

from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis import service as analysis_service
from app.config import Settings
from app.db.models.analysis_run import AnalysisRun
from app.db.models.diagnostic_rule import DiagnosticRule
from app.db.models.enums import (
    Confidence,
    FindingStatus,
    ImplementationStatus,
    Language,
    Severity,
)
from app.db.models.finding import Finding
from app.db.models.finding_workflow import FindingWorkflow
from app.db.models.rule import Rule
from app.db.models.user import User
from app.main import create_app
from app.projects.services import create_project


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        app_env="test", database_url=f"sqlite:///{tmp_path / 'findings.db'}",
        session_secret="test-session-secret-at-least-32-characters", upload_dir=tmp_path / "uploads",
        max_upload_bytes=20 * 1024 * 1024, max_extracted_bytes=100 * 1024 * 1024,
        max_archive_files=2_000, max_single_file_bytes=10 * 1024 * 1024,
        semgrep_timeout_seconds=60, template_dir=Path("app/templates").resolve(),
        static_dir=Path("app/static").resolve(),
    )


def _csrf_token(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


def _zip_bytes() -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("src/vulnerable.py", "dangerous_call(user_input)\n")
    return output.getvalue()


def _seed_project_and_rule(application) -> int:
    with Session(application.state.db_engine) as session:
        admin = session.scalar(select(User).where(User.username == "admin@company.com"))
        assert admin is not None
        admin_id = admin.id
    with Session(application.state.db_engine) as session:
        project = create_project(
            session, name="Finding target", description=None,
            language=Language.PYTHON, created_by=admin_id,
        )
        with session.begin():
            rule = Rule(
                    name="Test mapped rule", description="test-only catalog mapping",
                    standard_id="TEST-001", category="test", severity=Severity.HIGH,
                    supported_languages=[Language.PYTHON.value],
                    implementation_status=ImplementationStatus.PARTIAL,
                    semgrep_rule_id="test.python.dangerous-call",
            )
            session.add(rule)
            session.flush()
            session.add(
                DiagnosticRule(
                    catalog_rule_id=rule.id,
                    language=Language.PYTHON,
                    semgrep_rule_id="test.python.dangerous-call",
                    is_active=True,
                )
            )
        return project.id


def test_semgrep_result_is_normalized_persisted_and_filterable(tmp_path: Path, monkeypatch) -> None:
    application = create_app(_settings(tmp_path))
    raw_result = {
        "check_id": "test.python.dangerous-call",
        "path": "src/vulnerable.py",
        "start": {"line": 1, "col": 1},
        "end": {"line": 1, "col": 26},
        "extra": {
            "message": "Unsafe call", "severity": "ERROR",
            "lines": "dangerous_call(user_input)",
            "metadata": {"confidence": "HIGH", "recommendation": "Validate input."},
        },
    }

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command, 0, __import__("json").dumps({"results": [raw_result], "errors": []}), ""
        )

    monkeypatch.setattr(analysis_service, "_run_semgrep_process", fake_run)

    async def exercise() -> tuple[int, int, int]:
        async with application.router.lifespan_context(application):
            project_id = _seed_project_and_rule(application)
            transport = ASGITransport(app=application)
            async with AsyncClient(transport=transport, base_url="http://testserver", follow_redirects=False) as client:
                login = await client.get("/login")
                await client.post("/login", data={"username": "admin@company.com", "password": "admin", "csrf_token": _csrf_token(login.text)})
                detail = await client.get(f"/projects/{project_id}")
                token = _csrf_token(detail.text)
                upload = await client.post(
                    f"/projects/{project_id}/analysis", data={"csrf_token": token},
                    files={"source_file": ("source.zip", _zip_bytes(), "application/zip")},
                )
                assert upload.status_code == 303
                run_response = await client.post(
                    f"/projects/{project_id}/analysis", data={"csrf_token": token}
                )
                assert run_response.status_code == 303
                analysis_id = int(run_response.headers["location"].rsplit("/", 1)[1])
                listing = await client.get(
                    f"/analysis/{analysis_id}/findings?severity=HIGH&confidence=HIGH"
                )
                assert listing.status_code == 200
                assert "Test mapped rule" in listing.text
                finding_id_match = re.search(r"/findings/(\d+)", listing.text)
                assert finding_id_match is not None
                detail_response = await client.get(
                    f"/findings/{finding_id_match.group(1)}"
                )
                assert detail_response.status_code == 200
                assert "원본 Semgrep 결과" in detail_response.text
                assert "dangerous_call(user_input)" in detail_response.text
                assert "TEST-001" in detail_response.text
                assert "미조치" in detail_response.text
                assert "admin@company.com" in (
                    await client.get(f"/analysis/{analysis_id}")
                ).text
                assert (
                    await client.post(
                        f"/findings/{finding_id_match.group(1)}/status",
                        data={"workflow_status": "IN_PROGRESS", "note": "review"},
                    )
                ).status_code == 403
                token = _csrf_token(detail_response.text)
                missing_reason = await client.post(
                    f"/findings/{finding_id_match.group(1)}/status",
                    data={
                        "workflow_status": "FALSE_POSITIVE",
                        "note": "",
                        "csrf_token": token,
                    },
                )
                assert missing_reason.status_code == 400
                updated = await client.post(
                    f"/findings/{finding_id_match.group(1)}/status",
                    data={
                        "workflow_status": "IN_PROGRESS",
                        "note": "담당자가 원인을 확인하고 있습니다.",
                        "csrf_token": token,
                    },
                )
                assert updated.status_code == 303
                filtered = await client.get(
                    f"/analysis/{analysis_id}/findings?status=IN_PROGRESS"
                )
                assert "조치 중" in filtered.text
                return project_id, analysis_id, int(finding_id_match.group(1))

    _, analysis_id, finding_id = asyncio.run(exercise())

    with Session(application.state.db_engine) as session:
        analysis_run = session.get(AnalysisRun, analysis_id)
        finding = session.scalar(select(Finding).where(Finding.analysis_run_id == analysis_id))
        assert analysis_run is not None and finding is not None
        linked_rule = session.get(Rule, finding.rule_id)
        assert linked_rule is not None
        assert linked_rule.standard_id == finding.kisa_id
        assert analysis_run.summary is not None
        assert {
            key: analysis_run.summary[key]
            for key in ("finding_count", "error_count", "stored_finding_count")
        } == {
            "finding_count": 1,
            "error_count": 0,
            "stored_finding_count": 1,
        }
        assert finding.rule_name == "Test mapped rule"
        assert finding.kisa_id == "TEST-001"
        assert finding.language is Language.PYTHON
        assert finding.severity is Severity.HIGH
        assert finding.confidence is Confidence.HIGH
        assert finding.file_path == "src/vulnerable.py"
        assert (finding.start_line, finding.start_column) == (1, 1)
        assert (finding.end_line, finding.end_column) == (1, 26)
        assert finding.evidence == {"lines": "dangerous_call(user_input)"}
        assert finding.recommendation == "Validate input."
        assert finding.raw_result == raw_result
        assert not Path(finding.raw_result["path"]).is_absolute()
        assert ".." not in Path(finding.raw_result["path"]).parts
        workflow = session.get(FindingWorkflow, finding_id)
        assert workflow is not None
        assert workflow.status is FindingStatus.IN_PROGRESS
        assert workflow.note == "담당자가 원인을 확인하고 있습니다."
        assert workflow.updater is not None
        assert workflow.updater.username == "admin@company.com"
        assert workflow.updated_at is not None


def test_unknown_semgrep_rule_is_not_saved_without_a_catalog_mapping(tmp_path: Path, monkeypatch) -> None:
    application = create_app(_settings(tmp_path))

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command, 0,
            '{"results": [{"check_id": "unknown.rule"}], "errors": []}', "",
        )

    monkeypatch.setattr(analysis_service, "_run_semgrep_process", fake_run)

    async def exercise() -> int:
        async with application.router.lifespan_context(application):
            project_id = _seed_project_and_rule(application)
            transport = ASGITransport(app=application)
            async with AsyncClient(transport=transport, base_url="http://testserver", follow_redirects=False) as client:
                login = await client.get("/login")
                await client.post("/login", data={"username": "admin@company.com", "password": "admin", "csrf_token": _csrf_token(login.text)})
                detail = await client.get(f"/projects/{project_id}")
                token = _csrf_token(detail.text)
                await client.post(f"/projects/{project_id}/analysis", data={"csrf_token": token}, files={"source_file": ("source.zip", _zip_bytes(), "application/zip")})
                response = await client.post(f"/projects/{project_id}/analysis", data={"csrf_token": token})
                return int(response.headers["location"].rsplit("/", 1)[1])

    analysis_id = asyncio.run(exercise())
    with Session(application.state.db_engine) as session:
        assert session.scalar(select(Finding).where(Finding.analysis_run_id == analysis_id)) is None
        run = session.get(AnalysisRun, analysis_id)
        assert run is not None
        assert run.summary["finding_count"] == 1
        assert run.summary["stored_finding_count"] == 0


def test_inactive_diagnostic_mapping_does_not_persist_new_findings(
    tmp_path: Path, monkeypatch
) -> None:
    application = create_app(_settings(tmp_path))

    def fake_run(command, **kwargs):
        result = {
            "results": [
                {
                    "check_id": "test.python.dangerous-call",
                    "path": "src/vulnerable.py",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 26},
                    "extra": {
                        "message": "Unsafe call",
                        "severity": "ERROR",
                        "metadata": {"confidence": "HIGH"},
                    },
                }
            ],
            "errors": [],
        }
        return subprocess.CompletedProcess(
            command, 0, __import__("json").dumps(result), ""
        )

    monkeypatch.setattr(analysis_service, "_run_semgrep_process", fake_run)

    async def exercise() -> int:
        async with application.router.lifespan_context(application):
            project_id = _seed_project_and_rule(application)
            with Session(application.state.db_engine) as session:
                rule = session.scalar(
                    select(Rule).where(Rule.standard_id == "TEST-001")
                )
                assert rule is not None
                mapping = session.scalar(
                    select(DiagnosticRule).where(
                        DiagnosticRule.catalog_rule_id == rule.id,
                        DiagnosticRule.language == Language.PYTHON,
                    )
                )
                assert mapping is not None
                mapping.is_active = False
                session.commit()

            transport = ASGITransport(app=application)
            async with AsyncClient(
                transport=transport,
                base_url="http://testserver",
                follow_redirects=False,
            ) as client:
                login = await client.get("/login")
                await client.post(
                    "/login",
                    data={
                        "username": "admin@company.com",
                        "password": "admin",
                        "csrf_token": _csrf_token(login.text),
                    },
                )
                detail = await client.get(f"/projects/{project_id}")
                token = _csrf_token(detail.text)
                await client.post(
                    f"/projects/{project_id}/analysis",
                    data={"csrf_token": token},
                    files={
                        "source_file": (
                            "source.zip",
                            _zip_bytes(),
                            "application/zip",
                        )
                    },
                )
                response = await client.post(
                    f"/projects/{project_id}/analysis",
                    data={"csrf_token": token},
                )
                return int(response.headers["location"].rsplit("/", 1)[1])

    analysis_id = asyncio.run(exercise())
    with Session(application.state.db_engine) as session:
        assert session.scalar(
            select(Finding).where(Finding.analysis_run_id == analysis_id)
        ) is None
        run = session.get(AnalysisRun, analysis_id)
        assert run is not None
        assert run.summary["finding_count"] == 1
        assert run.summary["stored_finding_count"] == 0
