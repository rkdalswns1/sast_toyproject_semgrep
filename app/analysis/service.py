"""Isolated Semgrep execution and analysis-run state transitions."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.config import Settings
from app.db.models.analysis_run import AnalysisRun
from app.db.models.enums import AnalysisStatus
from app.db.models.project import Project
from app.findings.services import FindingNormalizationError, persist_normalized_findings


class AnalysisExecutionError(ValueError):
    """A safe, user-facing analysis execution failure."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _safe_source_path(project: Project, settings: Settings) -> Path:
    if not project.source_path:
        raise AnalysisExecutionError("먼저 분석할 ZIP 소스를 업로드하세요.")

    upload_root = settings.upload_dir.resolve()
    source_path = Path(project.source_path).resolve()
    try:
        source_path.relative_to(upload_root)
    except ValueError as exc:
        raise AnalysisExecutionError("저장된 소스 작업공간을 사용할 수 없습니다.") from exc
    if not source_path.is_dir():
        raise AnalysisExecutionError("저장된 소스 작업공간을 찾을 수 없습니다.")
    return source_path


def _copy_source_tree(source_path: Path, destination: Path) -> None:
    """Copy only regular source files into a fresh, per-run workspace."""
    destination.mkdir(parents=True)
    for item in source_path.rglob("*"):
        if item.is_symlink():
            raise AnalysisExecutionError("저장된 소스에 허용되지 않는 링크가 있습니다.")
        relative_path = item.relative_to(source_path)
        target = destination / relative_path
        if item.is_dir():
            target.mkdir(exist_ok=True)
        elif item.is_file():
            shutil.copy2(item, target)
        else:
            raise AnalysisExecutionError("저장된 소스에 허용되지 않는 파일 유형이 있습니다.")


def _semgrep_command() -> str:
    virtualenv_command = Path(sys.executable).with_name("semgrep")
    if virtualenv_command.is_file():
        return str(virtualenv_command)
    command = shutil.which("semgrep")
    if command is None:
        raise AnalysisExecutionError("Semgrep 실행 환경을 찾을 수 없습니다.")
    return command


def _execute_semgrep(source_path: Path, workspace: Path, timeout_seconds: int) -> dict[str, Any]:
    """Run Semgrep without a shell and return its JSON object."""
    config_path = Path(__file__).resolve().parents[1] / "rules" / "semgrep" / "kisa-2021.yml"
    environment = os.environ.copy()
    environment["SEMGREP_SETTINGS_FILE"] = str(workspace / "semgrep-settings.yml")
    environment["SEMGREP_LOG_FILE"] = str(workspace / "semgrep.log")
    environment["SEMGREP_SEND_METRICS"] = "off"
    environment["SEMGREP_ENABLE_VERSION_CHECK"] = "0"

    try:
        completed = subprocess.run(
            [
                _semgrep_command(),
                "scan",
                "--config",
                str(config_path),
                "--json",
                "--quiet",
                "--metrics",
                "off",
                "--disable-version-check",
                "--no-git-ignore",
                str(source_path),
            ],
            cwd=workspace,
            env=environment,
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise AnalysisExecutionError("분석 실행 시간이 제한을 초과했습니다.") from exc
    except OSError as exc:
        raise AnalysisExecutionError("Semgrep을 실행하지 못했습니다.") from exc

    if completed.returncode != 0:
        raise AnalysisExecutionError("Semgrep 분석이 정상적으로 완료되지 않았습니다.")
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise AnalysisExecutionError("Semgrep 결과를 처리하지 못했습니다.") from exc
    if not isinstance(result, dict):
        raise AnalysisExecutionError("Semgrep 결과를 처리하지 못했습니다.")
    return result


def _result_summary(result: dict[str, Any]) -> dict[str, Any]:
    findings = result.get("results")
    errors = result.get("errors")
    return {
        "finding_count": len(findings) if isinstance(findings, list) else 0,
        "error_count": len(errors) if isinstance(errors, list) else 0,
    }


def execute_project_analysis(
    session: Session, *, project_id: int, executed_by: int, settings: Settings
) -> AnalysisRun:
    """Persist the run lifecycle around one isolated Semgrep process."""
    project = session.get(Project, project_id)
    if project is None:
        raise AnalysisExecutionError("프로젝트를 찾을 수 없습니다.")
    source_path = _safe_source_path(project, settings)
    # The read above starts SQLAlchemy's implicit transaction. Close it before
    # each explicit write transaction that records the lifecycle.
    stored_project_id = project.id
    project_language = project.language
    session.rollback()

    with session.begin():
        analysis_run = AnalysisRun(
            project_id=stored_project_id,
            engine="Semgrep",
            language=project_language,
            status=AnalysisStatus.PENDING,
            executed_by=executed_by,
        )
        session.add(analysis_run)
        session.flush()
        run_id = analysis_run.id

    with session.begin():
        analysis_run = session.get(AnalysisRun, run_id)
        assert analysis_run is not None
        analysis_run.status = AnalysisStatus.RUNNING
        analysis_run.started_at = _utcnow()

    workspace: Path | None = None
    error_message: str | None = None
    try:
        workspace_root = settings.upload_dir / ".analysis-workspaces"
        workspace_root.mkdir(parents=True, exist_ok=True)
        workspace = Path(tempfile.mkdtemp(prefix=f"analysis-{run_id}-", dir=workspace_root))
        isolated_source = workspace / "source"
        _copy_source_tree(source_path, isolated_source)
        semgrep_result = _execute_semgrep(
            isolated_source, workspace, settings.semgrep_timeout_seconds
        )
        summary = _result_summary(semgrep_result)
        with session.begin():
            analysis_run = session.get(AnalysisRun, run_id)
            assert analysis_run is not None
            stored_count = persist_normalized_findings(
                session,
                analysis_run_id=analysis_run.id,
                language=analysis_run.language,
                semgrep_result=semgrep_result,
                source_root=isolated_source,
            )
            analysis_run.status = AnalysisStatus.COMPLETED
            analysis_run.finished_at = _utcnow()
            analysis_run.error_message = None
            analysis_run.summary = {**summary, "stored_finding_count": stored_count}
    except (AnalysisExecutionError, FindingNormalizationError) as exc:
        error_message = str(exc)
    except OSError:
        error_message = "분석 작업공간을 준비하거나 Semgrep을 실행하지 못했습니다."
    finally:
        if workspace is not None:
            shutil.rmtree(workspace, ignore_errors=True)

    if error_message is not None:
        with session.begin():
            analysis_run = session.get(AnalysisRun, run_id)
            assert analysis_run is not None
            analysis_run.status = AnalysisStatus.FAILED
            analysis_run.finished_at = _utcnow()
            analysis_run.error_message = error_message
            analysis_run.summary = None
        return analysis_run

    return analysis_run
