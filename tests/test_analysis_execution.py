import asyncio
import io
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis import service as analysis_service
from app.analysis.service import AnalysisExecutionError, execute_project_analysis
from app.config import Settings
from app.db.models.analysis_run import AnalysisRun
from app.db.models.enums import AnalysisStatus, Language
from app.db.models.project import Project
from app.db.models.user import User
from app.main import create_app
from app.projects.services import create_project, update_project_source


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        app_env="test", database_url=f"sqlite:///{tmp_path / 'analysis.db'}",
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
        archive.writestr("sample.py", "print('safe')")
    return output.getvalue()


def _create_project(application) -> int:
    with Session(application.state.db_engine) as session:
        admin = session.scalar(select(User).where(User.username == "admin@company.com"))
        assert admin is not None
        admin_id = admin.id
    with Session(application.state.db_engine) as session:
        return create_project(
            session, name="Analysis target", description=None,
            language=Language.PYTHON, created_by=admin_id,
        ).id


async def _login_and_upload(client: AsyncClient, project_id: int) -> str:
    login = await client.get("/login")
    await client.post("/login", data={"username": "admin@company.com", "password": "admin", "csrf_token": _csrf_token(login.text)})
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
        monkeypatch.setattr(analysis_service, "_run_semgrep_process", fake_run)

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
        assert kwargs["timeout_seconds"] == 60
        assert kwargs["max_output_bytes"] == 20 * 1024 * 1024
        assert "--no-git-ignore" in command
        assert command[command.index("--jobs") + 1] == "2"
        assert command[command.index("--max-memory") + 1] == "1024"
        assert command[command.index("--max-target-bytes") + 1] == "1000000"
        assert kwargs["env"]["SEMGREP_SETTINGS_FILE"].startswith(str(tmp_path / "uploads"))
        return subprocess.CompletedProcess(command, 0, '{"results": [{"x": 1}], "errors": []}', "")

    run, settings = _run_scenario(tmp_path, monkeypatch, fake_run)
    assert run.status is AnalysisStatus.COMPLETED
    assert run.started_at is not None and run.finished_at is not None
    assert run.summary is not None
    assert {key: run.summary[key] for key in ("finding_count", "error_count", "stored_finding_count")} == {
        "finding_count": 1,
        "error_count": 0,
        "stored_finding_count": 0,
    }
    provenance = run.summary["provenance"]
    assert provenance["selected_language"] == "PYTHON"
    assert provenance["detected_languages"] == ["PYTHON"]
    assert len(provenance["source_sha256"]) == 64
    assert len(provenance["ruleset_sha256"]) == 64
    assert provenance["semgrep_version"] == "1.175.0"
    assert not list((settings.upload_dir / ".analysis-workspaces").iterdir())


def test_real_semgrep_process_completes_with_local_configuration(tmp_path: Path, monkeypatch) -> None:
    run, _ = _run_scenario(tmp_path, monkeypatch, None)
    assert run.status is AnalysisStatus.COMPLETED
    assert run.summary is not None
    assert {key: run.summary[key] for key in ("finding_count", "error_count", "stored_finding_count")} == {
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
        raise AnalysisExecutionError("분석 실행 시간이 제한을 초과했습니다.")

    run, _ = _run_scenario(tmp_path, monkeypatch, fake_run)
    assert run.status is AnalysisStatus.FAILED
    assert run.finished_at is not None
    assert run.error_message == "분석 실행 시간이 제한을 초과했습니다."


def test_invalid_target_can_be_corrected_and_rechecked_with_history_preserved(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    application = create_app(settings)

    async def exercise() -> tuple[int, int, int]:
        async with application.router.lifespan_context(application):
            project_id = _create_project(application)
            source_path = (
                settings.upload_dir
                / "projects"
                / str(project_id)
                / "sources"
                / "language-mismatch"
                / "extracted"
            )
            source_path.mkdir(parents=True)
            (source_path / "Main.java").write_text("class Main {}", encoding="utf-8")
            with Session(application.state.db_engine) as session:
                admin = session.scalar(
                    select(User).where(User.username == "admin@company.com")
                )
                assert admin is not None
                admin_id = admin.id
                session.rollback()
                update_project_source(
                    session, project_id=project_id, source_path=source_path
                )
                failed_run = execute_project_analysis(
                    session,
                    project_id=project_id,
                    executed_by=admin_id,
                    settings=settings,
                )
                (source_path / "Main.java").unlink()
                (source_path / "sample.py").write_text(
                    "print('safe')", encoding="utf-8"
                )
                completed_run = execute_project_analysis(
                    session,
                    project_id=project_id,
                    executed_by=admin_id,
                    settings=settings,
                )
                return project_id, failed_run.id, completed_run.id

    project_id, failed_run_id, completed_run_id = asyncio.run(exercise())
    with Session(application.state.db_engine) as session:
        failed_run = session.get(AnalysisRun, failed_run_id)
        completed_run = session.get(AnalysisRun, completed_run_id)
        assert failed_run is not None and completed_run is not None
        assert failed_run.status is AnalysisStatus.FAILED
        assert failed_run.error_message is not None
        assert "Python 소스 파일" in failed_run.error_message
        assert completed_run.status is AnalysisStatus.COMPLETED
        assert completed_run.error_message is None
        history = session.scalars(
            select(AnalysisRun)
            .where(AnalysisRun.project_id == project_id)
            .order_by(AnalysisRun.id)
        ).all()
        assert [run.id for run in history] == [failed_run_id, completed_run_id]


def test_semgrep_process_output_and_wall_time_are_bounded(tmp_path: Path) -> None:
    output_workspace = tmp_path / "large-output"
    output_workspace.mkdir()
    with pytest.raises(AnalysisExecutionError, match="결과가 크기 제한"):
        analysis_service._run_semgrep_process(
            [
                sys.executable,
                "-c",
                "import sys,time; sys.stdout.write('x' * 200000); sys.stdout.flush(); time.sleep(5)",
            ],
            cwd=output_workspace,
            env=dict(os.environ),
            timeout_seconds=5,
            max_output_bytes=1_000,
        )

    timeout_workspace = tmp_path / "timeout"
    timeout_workspace.mkdir()
    with pytest.raises(AnalysisExecutionError, match="실행 시간이 제한"):
        analysis_service._run_semgrep_process(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            cwd=timeout_workspace,
            env=dict(os.environ),
            timeout_seconds=1,
            max_output_bytes=1_000,
        )


def test_analysis_rejects_another_projects_source_workspace(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    application = create_app(settings)

    async def exercise() -> None:
        async with application.router.lifespan_context(application):
            first_project_id = _create_project(application)
            second_project_id = _create_project(application)
            foreign_source = (
                settings.upload_dir
                / "projects"
                / str(second_project_id)
                / "sources"
                / "foreign"
                / "extracted"
            )
            foreign_source.mkdir(parents=True)
            (foreign_source / "sample.py").write_text("print('safe')", encoding="utf-8")
            with Session(application.state.db_engine) as session:
                admin = session.scalar(
                    select(User).where(User.username == "admin@company.com")
                )
                assert admin is not None
                admin_id = admin.id
                session.rollback()
                update_project_source(
                    session,
                    project_id=first_project_id,
                    source_path=foreign_source,
                )
                with pytest.raises(AnalysisExecutionError, match="작업공간"):
                    execute_project_analysis(
                        session,
                        project_id=first_project_id,
                        executed_by=admin_id,
                        settings=settings,
                    )

    asyncio.run(exercise())
