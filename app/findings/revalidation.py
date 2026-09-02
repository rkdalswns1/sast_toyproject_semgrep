"""Finding revalidation by comparing it with a fresh project analysis."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.service import execute_project_analysis
from app.config import Settings
from app.db.models.analysis_run import AnalysisRun
from app.db.models.enums import AnalysisStatus, RevalidationResult
from app.db.models.finding import Finding
from app.db.models.finding_revalidation import FindingRevalidation


class FindingRevalidationError(ValueError):
    """Raised when a Finding cannot be revalidated safely."""


def _semgrep_rule_id(finding: Finding) -> str | None:
    check_id = finding.raw_result.get("check_id")
    return check_id if isinstance(check_id, str) and check_id else None


def _is_exact_match(source: Finding, candidate: Finding) -> bool:
    source_rule_id = _semgrep_rule_id(source)
    return (
        source_rule_id is not None
        and source.kisa_id == candidate.kisa_id
        and source.language == candidate.language
        and source_rule_id == _semgrep_rule_id(candidate)
        and source.file_path == candidate.file_path
    )


def execute_finding_revalidation(
    session: Session,
    *,
    source_finding_id: int,
    executed_by: int,
    settings: Settings,
) -> FindingRevalidation:
    """Run the latest project source and record a conservative comparison."""
    source_finding = session.get(Finding, source_finding_id)
    if source_finding is None:
        raise FindingRevalidationError("Finding을 찾을 수 없습니다.")
    source_run = session.get(AnalysisRun, source_finding.analysis_run_id)
    if source_run is None:
        raise FindingRevalidationError("원본 분석 실행을 찾을 수 없습니다.")
    project_id = source_run.project_id
    session.rollback()

    analysis_run = execute_project_analysis(
        session,
        project_id=project_id,
        executed_by=executed_by,
        settings=settings,
    )
    analysis_run_id = analysis_run.id
    session.rollback()

    with session.begin():
        source_finding = session.get(Finding, source_finding_id)
        analysis_run = session.get(AnalysisRun, analysis_run_id)
        if source_finding is None or analysis_run is None:
            raise FindingRevalidationError("재검증 결과를 연결하지 못했습니다.")
        if analysis_run.project_id != project_id:
            raise FindingRevalidationError("재검증 프로젝트가 일치하지 않습니다.")

        matched_finding: Finding | None = None
        if analysis_run.status is AnalysisStatus.COMPLETED:
            new_findings = session.scalars(
                select(Finding)
                .where(Finding.analysis_run_id == analysis_run.id)
                .order_by(Finding.id)
            ).all()
            matched_finding = next(
                (
                    candidate
                    for candidate in new_findings
                    if _is_exact_match(source_finding, candidate)
                ),
                None,
            )
            if matched_finding is not None:
                result = RevalidationResult.STILL_DETECTED
            elif any(
                candidate.kisa_id == source_finding.kisa_id
                for candidate in new_findings
            ):
                result = RevalidationResult.REVIEW_REQUIRED
            else:
                result = RevalidationResult.LIKELY_RESOLVED
        else:
            result = RevalidationResult.REVIEW_REQUIRED

        revalidation = FindingRevalidation(
            source_finding_id=source_finding.id,
            analysis_run_id=analysis_run.id,
            matched_finding_id=(
                matched_finding.id if matched_finding is not None else None
            ),
            result=result,
            executed_by=executed_by,
        )
        session.add(revalidation)
        session.flush()
        revalidation_id = revalidation.id

    persisted = session.get(FindingRevalidation, revalidation_id)
    assert persisted is not None
    return persisted
