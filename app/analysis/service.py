"""Isolated Semgrep execution and analysis-run state transitions."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import signal
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import Settings
from app.analysis.languages import (
    LANGUAGE_PROFILES,
    LanguageDetectionError,
    resolve_analysis_languages,
)
from app.db.models.analysis_run import AnalysisRun
from app.db.models.diagnostic_rule import DiagnosticRule
from app.db.models.enums import AnalysisStatus, Language
from app.db.models.project import Project
from app.db.models.rule import Rule
from app.db.models.finding import Finding
from app.findings.services import (
    FindingNormalizationError,
    FindingPersistenceMetrics,
    persist_normalized_findings,
)


class AnalysisExecutionError(ValueError):
    """A safe, user-facing analysis execution failure."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _safe_source_path(project: Project, settings: Settings) -> Path:
    if not project.source_path:
        raise AnalysisExecutionError("먼저 분석할 ZIP 소스를 업로드하세요.")

    upload_root = settings.upload_dir.resolve()
    stored_path = Path(project.source_path)
    if stored_path.is_symlink():
        raise AnalysisExecutionError("저장된 소스 작업공간을 사용할 수 없습니다.")
    source_path = stored_path.resolve()
    project_source_root = (
        upload_root / "projects" / str(project.id) / "sources"
    ).resolve()
    try:
        source_path.relative_to(project_source_root)
    except ValueError as exc:
        raise AnalysisExecutionError("저장된 소스 작업공간을 사용할 수 없습니다.") from exc
    if not source_path.is_dir():
        raise AnalysisExecutionError("저장된 소스 작업공간을 찾을 수 없습니다.")
    return source_path


def _copy_source_tree(source_path: Path, destination: Path) -> None:
    """Copy only regular source files into a fresh, per-run workspace."""
    destination.mkdir(mode=0o700, parents=True)
    for item in source_path.rglob("*"):
        if item.is_symlink():
            raise AnalysisExecutionError("저장된 소스에 허용되지 않는 링크가 있습니다.")
        relative_path = item.relative_to(source_path)
        target = destination / relative_path
        if item.is_dir():
            target.mkdir(mode=0o700, exist_ok=True)
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


def _semgrep_environment(workspace: Path) -> dict[str, str]:
    """Build an allowlisted environment without application secrets."""
    for directory in ("home", "tmp", "cache"):
        target = workspace / directory
        target.mkdir(mode=0o700, exist_ok=True)

    return {
        "PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin",
        "HOME": str(workspace / "home"),
        "TMPDIR": str(workspace / "tmp"),
        "XDG_CACHE_HOME": str(workspace / "cache"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "SEMGREP_SETTINGS_FILE": str(
            workspace / "semgrep-settings.yml"
        ),
        "SEMGREP_LOG_FILE": str(workspace / "semgrep.log"),
        "SEMGREP_SEND_METRICS": "off",
        "SEMGREP_ENABLE_VERSION_CHECK": "0",
    }


def _semgrep_scan_arguments(
    *,
    config_path: Path,
    source_path: Path,
    settings: Settings,
    scan_languages: set[Language],
) -> list[str]:
    arguments = [
        "scan",
        "--config",
        str(config_path),
        "--json",
        "--quiet",
        "--metrics",
        "off",
        "--disable-version-check",
        "--no-git-ignore",
        "--jobs",
        str(settings.semgrep_jobs),
        "--max-memory",
        str(settings.semgrep_max_memory_mb),
        "--max-target-bytes",
        str(settings.semgrep_max_target_bytes),
    ]
    for profile in LANGUAGE_PROFILES:
        if profile.language not in scan_languages:
            continue
        for extension in profile.extensions:
            arguments.extend(["--include", f"*{extension}"])
    arguments.append(str(source_path))
    return arguments


def _ruleset_path() -> Path:
    return Path(__file__).resolve().parents[1] / "rules" / "semgrep" / "kisa-2021"


def _sha256_ruleset(ruleset_root: Path) -> str:
    """Hash each rule path and its bytes in a stable order."""
    rule_files = sorted(ruleset_root.glob("*.yml"), key=lambda path: path.name)
    if not rule_files:
        raise AnalysisExecutionError("Semgrep 규칙 세트를 찾을 수 없습니다.")

    digest = hashlib.sha256()
    for rule_file in rule_files:
        relative_path = rule_file.relative_to(ruleset_root).as_posix().encode()
        digest.update(len(relative_path).to_bytes(8, "big"))
        digest.update(relative_path)
        digest.update(rule_file.stat().st_size.to_bytes(8, "big"))
        with rule_file.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
    return digest.hexdigest()


def _sha256_source_tree(source_root: Path) -> str:
    """Hash relative paths and bytes in a stable order for run reproducibility."""
    digest = hashlib.sha256()
    for source_file in sorted(source_root.rglob("*"), key=lambda path: path.as_posix()):
        if source_file.is_symlink():
            raise AnalysisExecutionError("저장된 소스에 허용되지 않는 링크가 있습니다.")
        if not source_file.is_file():
            continue
        relative_path = source_file.relative_to(source_root).as_posix().encode()
        digest.update(len(relative_path).to_bytes(8, "big"))
        digest.update(relative_path)
        digest.update(source_file.stat().st_size.to_bytes(8, "big"))
        with source_file.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
    return digest.hexdigest()


def _active_rule_snapshot(
    session: Session, scan_languages: Language | set[Language]
) -> list[dict[str, str | None]]:
    """Return the effective catalog-to-Semgrep mappings for this run."""
    if isinstance(scan_languages, Language):
        scan_languages = {scan_languages}
    rows = session.execute(
        select(
            Rule.standard_id,
            Rule.name,
            Rule.severity,
            DiagnosticRule.language,
            DiagnosticRule.semgrep_rule_id,
            DiagnosticRule.primary_cwe_id,
            DiagnosticRule.cwe_mapping_confidence,
        )
        .join(DiagnosticRule, DiagnosticRule.catalog_rule_id == Rule.id)
        .where(
            Rule.is_active.is_(True),
            DiagnosticRule.is_active.is_(True),
            DiagnosticRule.language.in_(scan_languages),
        )
        .order_by(Rule.standard_id, DiagnosticRule.semgrep_rule_id)
    ).all()
    return [
        {
            "kisa_standard_id": standard_id,
            "rule_name": rule_name,
            "severity": severity.value,
            "language": language.value,
            "semgrep_rule_id": semgrep_rule_id,
            "primary_cwe_id": primary_cwe_id,
            "cwe_mapping_confidence": (
                cwe_mapping_confidence.value if cwe_mapping_confidence else None
            ),
        }
        for (
            standard_id,
            rule_name,
            severity,
            language,
            semgrep_rule_id,
            primary_cwe_id,
            cwe_mapping_confidence,
        ) in rows
    ]


def _active_rule_snapshot_sha256(
    active_rules: list[dict[str, str | None]],
) -> str:
    serialized = json.dumps(
        active_rules, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def _analysis_provenance(
    source_path: Path,
    project_language,
    settings: Settings,
    active_rules: list[dict[str, str | None]],
    *,
    detected_languages: set[Language],
    scan_languages: set[Language],
    scan_all_languages: bool,
    source_metadata: dict[str, str | None],
) -> dict[str, Any]:
    try:
        source_snapshot = source_path.resolve().relative_to(
            settings.upload_dir.resolve()
        ).as_posix()
    except ValueError as exc:  # pragma: no cover - guarded by _safe_source_path.
        raise AnalysisExecutionError("저장된 소스 작업공간을 사용할 수 없습니다.") from exc
    try:
        semgrep_version = importlib.metadata.version("semgrep")
    except importlib.metadata.PackageNotFoundError:
        semgrep_version = "unknown"
    return {
        "source_snapshot": source_snapshot,
        "source_sha256": _sha256_source_tree(source_path),
        "semgrep_version": semgrep_version,
        "ruleset_sha256": _sha256_ruleset(_ruleset_path()),
        "active_rules": active_rules,
        "active_rules_sha256": _active_rule_snapshot_sha256(active_rules),
        "selected_language": project_language.value,
        "detected_languages": sorted(language.value for language in detected_languages),
        "scanned_languages": sorted(language.value for language in scan_languages),
        "scan_mode": "MULTI" if scan_all_languages else "SINGLE",
        "source_metadata": dict(source_metadata),
    }


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:  # pragma: no cover - the project runtime is Linux.
            process.kill()
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:  # pragma: no cover - SIGKILL should be final.
        process.kill()
        process.wait()


def _run_semgrep_process(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: int,
    max_output_bytes: int,
    max_error_bytes: int = 64 * 1024,
) -> subprocess.CompletedProcess[str]:
    """Run one process group while bounding wall time, JSON, and error output."""
    output_path = cwd / "semgrep-result.json"
    error_path = cwd / "semgrep-error.log"
    process: subprocess.Popen[bytes] | None = None
    try:
        with output_path.open("xb") as output, error_path.open("xb") as error_output:
            process = subprocess.Popen(
                command,
                cwd=cwd,
                env=env,
                stdout=output,
                stderr=error_output,
                start_new_session=os.name == "posix",
            )
            deadline = time.monotonic() + timeout_seconds
            while process.poll() is None:
                if output_path.stat().st_size > max_output_bytes:
                    _terminate_process_group(process)
                    raise AnalysisExecutionError(
                        "Semgrep 분석 결과가 크기 제한을 초과했습니다."
                    )
                if error_path.stat().st_size > max_error_bytes:
                    _terminate_process_group(process)
                    raise AnalysisExecutionError(
                        "Semgrep 오류 로그가 크기 제한을 초과했습니다."
                    )
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    _terminate_process_group(process)
                    raise AnalysisExecutionError(
                        "분석 실행 시간이 제한을 초과했습니다."
                    )
                time.sleep(min(0.05, remaining))
    except AnalysisExecutionError:
        raise
    except OSError as exc:
        if process is not None:
            _terminate_process_group(process)
        raise AnalysisExecutionError("Semgrep을 실행하지 못했습니다.") from exc

    if output_path.stat().st_size > max_output_bytes:
        raise AnalysisExecutionError("Semgrep 분석 결과가 크기 제한을 초과했습니다.")
    if error_path.stat().st_size > max_error_bytes:
        raise AnalysisExecutionError("Semgrep 오류 로그가 크기 제한을 초과했습니다.")
    try:
        stdout = output_path.read_text(encoding="utf-8")
        stderr = error_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise AnalysisExecutionError("Semgrep 결과를 처리하지 못했습니다.") from exc
    assert process is not None and process.returncode is not None
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _execute_semgrep(
    source_path: Path,
    workspace: Path,
    settings: Settings,
    scan_languages: set[Language],
) -> dict[str, Any]:
    """Run Semgrep without a shell and return its JSON object."""
    command = [_semgrep_command()]
    command.extend(
        _semgrep_scan_arguments(
            config_path=_ruleset_path(),
            source_path=source_path,
            settings=settings,
            scan_languages=scan_languages,
        )
    )
    environment = _semgrep_environment(workspace)
    completed = _run_semgrep_process(
        command,
        cwd=workspace,
        env=environment,
        timeout_seconds=settings.semgrep_timeout_seconds,
        max_output_bytes=settings.max_semgrep_output_bytes,
        max_error_bytes=settings.max_semgrep_error_bytes,
    )

    if completed.returncode != 0:
        error_detail = completed.stderr.strip()
        if error_detail:
            raise AnalysisExecutionError(
                f"Semgrep 종료 코드 {completed.returncode}\n{error_detail}"
            )
        raise AnalysisExecutionError(
            f"Semgrep 종료 코드 {completed.returncode}: 오류 출력이 없습니다."
        )
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
    scan_all_languages = project.scan_all_languages
    source_metadata = {
        "source_version": project.source_version,
        "deployment_version": project.deployment_version,
        "description": project.source_description,
        "source_origin": project.source_origin.value,
        "repository_url": project.repository_url,
        "repository_ref": project.repository_ref,
        "repository_commit": project.repository_commit,
    }
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
    provenance: dict[str, Any] | None = None
    try:
        try:
            detected_languages, scan_languages = resolve_analysis_languages(
                source_path,
                project_language,
                scan_all_languages=scan_all_languages,
            )
        except LanguageDetectionError as exc:
            raise AnalysisExecutionError(str(exc)) from exc
        active_rules = _active_rule_snapshot(session, scan_languages)
        session.rollback()
        provenance = _analysis_provenance(
            source_path,
            project_language,
            settings,
            active_rules,
            detected_languages=detected_languages,
            scan_languages=scan_languages,
            scan_all_languages=scan_all_languages,
            source_metadata=source_metadata,
        )
        workspace_root = settings.upload_dir / ".analysis-workspaces"
        workspace_root.mkdir(parents=True, exist_ok=True)
        workspace = Path(tempfile.mkdtemp(prefix=f"analysis-{run_id}-", dir=workspace_root))
        if os.name == "posix":
            workspace.chmod(0o700)
        isolated_source = workspace / "source"
        _copy_source_tree(source_path, isolated_source)
        semgrep_result = _execute_semgrep(
            isolated_source,
            workspace,
            settings,
            scan_languages,
        )
        summary = _result_summary(semgrep_result)
        with session.begin():
            analysis_run = session.get(AnalysisRun, run_id)
            assert analysis_run is not None
            persistence_metrics = FindingPersistenceMetrics()
            stored_count = persist_normalized_findings(
                session,
                analysis_run_id=analysis_run.id,
                semgrep_result=semgrep_result,
                source_root=isolated_source,
                scan_languages=scan_languages,
                metrics=persistence_metrics,
            )
            session.flush()
            language_counts = session.execute(
                select(
                    Finding.language,
                    func.count(Finding.id),
                    func.count(func.distinct(Finding.kisa_id)),
                )
                .where(Finding.analysis_run_id == analysis_run.id)
                .group_by(Finding.language)
                .order_by(Finding.language)
            ).all()
            distinct_kisa_count = session.scalar(
                select(func.count(func.distinct(Finding.kisa_id))).where(
                    Finding.analysis_run_id == analysis_run.id
                )
            ) or 0
            analysis_run.status = AnalysisStatus.COMPLETED
            analysis_run.finished_at = _utcnow()
            analysis_run.error_message = None
            analysis_run.summary = {
                **summary,
                "stored_finding_count": stored_count,
                "suppressed_finding_count": persistence_metrics.suppressed_count,
                "stored_finding_count_by_language": {
                    language.value: finding_count
                    for language, finding_count, _ in language_counts
                },
                "stored_distinct_kisa_count": distinct_kisa_count,
                "stored_distinct_kisa_count_by_language": {
                    language.value: distinct_count
                    for language, _, distinct_count in language_counts
                },
                "provenance": provenance,
            }
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
            analysis_run.summary = (
                {"provenance": provenance} if provenance is not None else None
            )
        return analysis_run

    return analysis_run
