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
from app.db.models.enums import AnalysisStatus, Language
from app.db.models.project import Project
from app.db.models.user import User
from app.main import create_app
from app.projects.services import create_project


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        app_env="test", database_url=f"sqlite:///{tmp_path / 'analysis.db'}",
        session_secret="test-session-secret", upload_dir=tmp_path / "uploads",
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
        archive.writestr("sample.py", "print('safe')")
    return output.getvalue()


def _create_project(application) -> int:
    with Session(application.state.db_engine) as session:
        admin = session.scalar(select(User).where(User.username == "admin"))
        assert admin is not None
        admin_id = admin.id
    with Session(application.state.db_engine) as session:
        return create_project(
            session, name="Analysis target", description=None,
            language=Language.PYTHON, created_by=admin_id,
        ).id


async def _login_and_upload(client: AsyncClient, project_id: int) -> str:
    login = await client.get("/login")
    await client.post("/login", data={"username": "admin", "password": "admin", "csrf_token": _csrf_token(login.text)})
    detail = await client.get(f"/projects/{project_id}")
    token = _csrf_token(detail.text)
    upload = await client.post(
        f"/projects/{project_id}/analysis", data={"csrf_token": token},
        files={"source_file": ("source.zip", _zip_bytes(), "application/zip")},
    )
    assert upload.status_code == 303
    return token


def _run_scenario(tmp_path: Path, monkeypatch, fake_run):
    settings = _settings(tmp_path)
    application = create_app(settings)
    if fake_run is not None:
        monkeypatch.setattr(analysis_service.subprocess, "run", fake_run)

    async def exercise() -> int:
        async with application.router.lifespan_context(application):
            project_id = _create_project(application)
            transport = ASGITransport(app=application)
            async with AsyncClient(transport=transport, base_url="http://testserver", follow_redirects=False) as client:
                token = await _login_and_upload(client, project_id)
                response = await client.post(f"/projects/{project_id}/analysis", data={"csrf_token": token})
                assert response.status_code == 303
                return int(response.headers["location"].rsplit("/", 1)[1])

    run_id = asyncio.run(exercise())
    with Session(application.state.db_engine) as session:
        run = session.get(AnalysisRun, run_id)
        assert run is not None
        return run, settings


def test_successful_semgrep_run_collects_json_and_cleans_workspace(tmp_path: Path, monkeypatch) -> None:
    def fake_run(command, **kwargs):
        assert isinstance(command, list)
        assert kwargs["timeout"] == 60
        assert "--no-git-ignore" in command
        assert kwargs["env"]["SEMGREP_SETTINGS_FILE"].startswith(str(tmp_path / "uploads"))
        return subprocess.CompletedProcess(command, 0, '{"results": [{"x": 1}], "errors": []}', "")

    run, settings = _run_scenario(tmp_path, monkeypatch, fake_run)
    assert run.status is AnalysisStatus.COMPLETED
    assert run.started_at is not None and run.finished_at is not None
    assert run.summary == {
        "finding_count": 1,
        "error_count": 0,
        "stored_finding_count": 0,
    }
    assert not list((settings.upload_dir / ".analysis-workspaces").iterdir())


def test_real_semgrep_process_completes_with_local_configuration(tmp_path: Path, monkeypatch) -> None:
    run, _ = _run_scenario(tmp_path, monkeypatch, None)
    assert run.status is AnalysisStatus.COMPLETED
    assert run.summary == {
        "finding_count": 0,
        "error_count": 0,
        "stored_finding_count": 0,
    }


def test_nonzero_semgrep_run_is_recorded_as_failed(tmp_path: Path, monkeypatch) -> None:
    run, _ = _run_scenario(
        tmp_path, monkeypatch,
        lambda command, **kwargs: subprocess.CompletedProcess(command, 2, "", "private stderr"),
    )
    assert run.status is AnalysisStatus.FAILED
    assert run.finished_at is not None
    assert run.error_message == "Semgrep 분석이 정상적으로 완료되지 않았습니다."
    assert "private stderr" not in run.error_message


def test_semgrep_timeout_is_recorded_as_failed(tmp_path: Path, monkeypatch) -> None:
    def fake_run(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    run, _ = _run_scenario(tmp_path, monkeypatch, fake_run)
    assert run.status is AnalysisStatus.FAILED
    assert run.finished_at is not None
    assert run.error_message == "분석 실행 시간이 제한을 초과했습니다."
