"""Semgrep-result normalization and Finding persistence."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.analysis_run import AnalysisRun
from app.db.models.diagnostic_rule import DiagnosticRule
from app.db.models.enums import Confidence, FindingStatus, Language, Severity
from app.db.models.finding import Finding
from app.db.models.finding_suppression import FindingSuppression
from app.db.models.finding_suppression_hit import FindingSuppressionHit
from app.db.models.finding_workflow import FindingWorkflow
from app.db.models.project import ProjectUser
from app.db.models.rule import Rule
from app.db.models.user import User


class FindingNormalizationError(ValueError):
    """Raised when Semgrep output cannot be normalized safely."""


class FindingWorkflowError(ValueError):
    """Raised when a remediation workflow update is invalid."""


@dataclass(slots=True)
class FindingPersistenceMetrics:
    suppressed_count: int = 0


_SEMGREP_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.INFO,
}

OPEN_WORKFLOW_STATUSES = {
    FindingStatus.OPEN,
    FindingStatus.IN_PROGRESS,
}


def _enum_or_default(enum_type: type[Severity] | type[Confidence], value: object, default):
    if isinstance(value, str):
        try:
            return enum_type(value.upper())
        except ValueError:
            pass
    return default


def _normalized_path(value: object, source_root: Path) -> str:
    if not isinstance(value, str) or not value:
        raise FindingNormalizationError("Semgrep 결과에 파일 경로가 없습니다.")
    raw_path = Path(value)
    try:
        return raw_path.resolve().relative_to(source_root.resolve()).as_posix()
    except ValueError:
        # Semgrep can emit a relative path. Do not let a result persist an
        # absolute workspace path or path traversal sequence for display.
        if raw_path.is_absolute() or ".." in raw_path.parts:
            raise FindingNormalizationError("Semgrep 결과의 파일 경로를 처리하지 못했습니다.")
        return raw_path.as_posix()


def _required_line(position: object, field_name: str) -> int:
    if not isinstance(position, dict) or not isinstance(position.get("line"), int):
        raise FindingNormalizationError(f"Semgrep 결과에 {field_name} 위치가 없습니다.")
    return position["line"]


def _optional_column(position: object) -> int | None:
    if isinstance(position, dict) and isinstance(position.get("col"), int):
        return position["col"]
    return None


def evidence_sha256(value: object) -> str | None:
    """Return a stable exact-code fingerprint without storing source content."""
    if not isinstance(value, str):
        return None
    normalized = "\n".join(
        line.rstrip() for line in value.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    ).strip()
    if not normalized:
        return None
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _matches_semgrep_rule_id(raw_check_id: object, configured_rule_id: str) -> bool:
    """Match a configured ID against Semgrep's optional config-path prefix."""
    return isinstance(raw_check_id, str) and (
        raw_check_id == configured_rule_id
        or raw_check_id.endswith(f".{configured_rule_id}")
    )


def persist_normalized_findings(
    session: Session,
    *,
    analysis_run_id: int,
    semgrep_result: dict[str, Any],
    source_root: Path,
    scan_languages: set[Language] | None = None,
    metrics: FindingPersistenceMetrics | None = None,
) -> int:
    """Persist results mapped to a compatible catalog rule; never invent one."""
    analysis_run = session.get(AnalysisRun, analysis_run_id)
    if analysis_run is None:
        raise FindingNormalizationError("분석 실행을 찾을 수 없습니다.")
    allowed_languages = scan_languages or {analysis_run.language}

    results = semgrep_result.get("results")
    if not isinstance(results, list):
        raise FindingNormalizationError("Semgrep 결과를 처리하지 못했습니다.")

    check_ids: set[str] = set()
    standard_ids: set[str] = set()
    for item in results:
        if isinstance(item, dict) and isinstance(item.get("check_id"), str):
            check_id = item["check_id"]
            check_ids.add(check_id)
            check_ids.add(check_id.rsplit(".", 1)[-1])
            extra = item.get("extra")
            metadata = extra.get("metadata") if isinstance(extra, dict) else None
            if isinstance(metadata, dict) and isinstance(
                metadata.get("kisa_standard_id"), str
            ):
                standard_ids.add(metadata["kisa_standard_id"])
    if not check_ids and not standard_ids:
        return 0
    rules = session.scalars(
        select(Rule).where(
            Rule.is_active.is_(True),
            (Rule.semgrep_rule_id.in_(check_ids))
            | (Rule.standard_id.in_(standard_ids)),
        )
    ).all()
    rules_by_semgrep_id = {
        rule.semgrep_rule_id: rule for rule in rules if rule.semgrep_rule_id is not None
    }
    rules_by_standard_id = {rule.standard_id: rule for rule in rules}
    active_mappings = {
        (mapping.catalog_rule_id, mapping.semgrep_rule_id): mapping
        for mapping in session.scalars(
            select(DiagnosticRule).where(
                DiagnosticRule.catalog_rule_id.in_([rule.id for rule in rules]),
                DiagnosticRule.language.in_(allowed_languages),
                DiagnosticRule.is_active.is_(True),
            )
        ).all()
    }
    active_suppressions = session.scalars(
        select(FindingSuppression).where(
            FindingSuppression.project_id == analysis_run.project_id,
            FindingSuppression.is_active.is_(True),
            FindingSuppression.language.in_(allowed_languages),
        )
    ).all()
    suppressions_by_key = {
        (
            suppression.language,
            suppression.semgrep_rule_id,
            suppression.file_path,
            suppression.evidence_sha256,
        ): suppression
        for suppression in active_suppressions
    }

    findings: list[Finding] = []
    for item in results:
        if not isinstance(item, dict):
            raise FindingNormalizationError("Semgrep 결과를 처리하지 못했습니다.")
        check_id = item.get("check_id")
        rule = rules_by_semgrep_id.get(check_id)
        if rule is None and isinstance(check_id, str):
            # Semgrep prefixes local YAML rule IDs with the configuration path.
            rule = rules_by_semgrep_id.get(check_id.rsplit(".", 1)[-1])
        extra = item.get("extra")
        metadata = extra.get("metadata") if isinstance(extra, dict) else None
        metadata = metadata if isinstance(metadata, dict) else {}
        if rule is None and isinstance(metadata.get("kisa_standard_id"), str):
            rule = rules_by_standard_id.get(metadata["kisa_standard_id"])
        if rule is None:
            # Rule catalog ownership starts in Phase 8. Until then an unmapped
            # engine result must not produce a fabricated KISA association.
            continue
        diagnostic_mapping = next(
            (
                mapping
                for (catalog_rule_id, _), mapping in active_mappings.items()
                if catalog_rule_id == rule.id
                and _matches_semgrep_rule_id(check_id, mapping.semgrep_rule_id)
            ),
            None,
        )
        if diagnostic_mapping is None:
            continue
        mapping_language = diagnostic_mapping.language
        if mapping_language.value not in rule.supported_languages:
            continue

        if not isinstance(extra, dict):
            raise FindingNormalizationError("Semgrep 결과의 메타데이터를 처리하지 못했습니다.")
        message = extra.get("message")
        if not isinstance(message, str) or not message.strip():
            raise FindingNormalizationError("Semgrep 결과에 메시지가 없습니다.")

        raw_severity = extra.get("severity")
        severity = _enum_or_default(
            Severity,
            raw_severity,
            _SEMGREP_SEVERITY_MAP.get(str(raw_severity).upper(), rule.severity),
        )
        confidence = _enum_or_default(
            Confidence, metadata.get("confidence"), Confidence.MEDIUM
        )
        recommendation = diagnostic_mapping.remediation_guidance
        if recommendation is None:
            recommendation = metadata.get("recommendation")
            if not isinstance(recommendation, str):
                recommendation = None
        evidence_lines = extra.get("lines")
        evidence = {"lines": evidence_lines} if isinstance(evidence_lines, str) else None
        normalized_file_path = _normalized_path(item.get("path"), source_root)
        fingerprint = evidence_sha256(evidence_lines)
        suppression = suppressions_by_key.get((
            mapping_language,
            diagnostic_mapping.semgrep_rule_id,
            normalized_file_path,
            fingerprint,
        )) if fingerprint is not None else None
        if suppression is not None:
            source_workflow = (
                session.get(FindingWorkflow, suppression.source_finding_id)
                if suppression.source_finding_id is not None
                else None
            )
            session.add(
                FindingSuppressionHit(
                    analysis_run_id=analysis_run.id,
                    suppression_id=suppression.id,
                    source_finding_id=suppression.source_finding_id,
                    reviewed_by=suppression.created_by,
                    kisa_id=rule.standard_id,
                    rule_name=rule.name,
                    language=mapping_language,
                    semgrep_rule_id=diagnostic_mapping.semgrep_rule_id,
                    file_path=normalized_file_path,
                    start_line=_required_line(item.get("start"), "시작"),
                    start_column=_optional_column(item.get("start")),
                    end_line=_required_line(item.get("end"), "종료"),
                    end_column=_optional_column(item.get("end")),
                    message=message.strip(),
                    review_note=source_workflow.note if source_workflow else None,
                    reviewed_at=(
                        source_workflow.updated_at if source_workflow else None
                    ),
                )
            )
            if metrics is not None:
                metrics.suppressed_count += 1
            continue
        normalized_raw_result = dict(item)
        normalized_raw_result["path"] = normalized_file_path

        findings.append(
            Finding(
                analysis_run_id=analysis_run_id,
                rule_id=rule.id,
                rule_name=rule.name,
                kisa_id=rule.standard_id,
                language=mapping_language,
                severity=severity,
                confidence=confidence,
                primary_cwe_id=diagnostic_mapping.primary_cwe_id,
                related_cwe_ids=list(diagnostic_mapping.related_cwe_ids),
                cwe_mapping_confidence=diagnostic_mapping.cwe_mapping_confidence,
                file_path=normalized_file_path,
                start_line=_required_line(item.get("start"), "시작"),
                start_column=_optional_column(item.get("start")),
                end_line=_required_line(item.get("end"), "종료"),
                end_column=_optional_column(item.get("end")),
                message=message.strip(),
                evidence=evidence,
                recommendation=recommendation,
                raw_result=normalized_raw_result,
            )
        )
    session.add_all(findings)
    session.flush()
    session.add_all(
        FindingWorkflow(finding_id=finding.id, status=FindingStatus.OPEN)
        for finding in findings
    )
    return len(findings)


def update_finding_workflow(
    session: Session,
    *,
    finding_id: int,
    workflow_status: FindingStatus,
    note: str | None,
    assignee_id: int | None,
    due_date: date | None,
    updated_by: int,
) -> FindingWorkflow:
    """Replace the latest remediation state without changing scan evidence."""
    normalized_note = note.strip() if note else None
    if normalized_note and len(normalized_note) > 2_000:
        raise FindingWorkflowError("검토 의견은 2,000자 이하로 입력하세요.")
    if workflow_status in {
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.ACCEPTED_RISK,
    } and not normalized_note:
        raise FindingWorkflowError("오탐 또는 위험 수용에는 검토 의견이 필요합니다.")

    with session.begin():
        finding = session.get(Finding, finding_id)
        if finding is None:
            raise FindingWorkflowError("Finding을 찾을 수 없습니다.")
        if assignee_id is not None:
            assignee = session.scalar(
                select(User)
                .join(ProjectUser, ProjectUser.user_id == User.id)
                .join(
                    AnalysisRun,
                    AnalysisRun.project_id == ProjectUser.project_id,
                )
                .where(
                    AnalysisRun.id == finding.analysis_run_id,
                    User.id == assignee_id,
                    User.is_active.is_(True),
                )
            )
            if assignee is None:
                raise FindingWorkflowError(
                    "담당자는 이 프로젝트에 할당된 활성 사용자만 선택할 수 있습니다."
                )
        workflow = session.get(FindingWorkflow, finding_id)
        if workflow is None:
            workflow = FindingWorkflow(finding_id=finding_id)
            session.add(workflow)
        workflow.status = workflow_status
        workflow.note = normalized_note
        workflow.assignee_id = assignee_id
        workflow.due_date = due_date
        workflow.updated_by = updated_by
        workflow.updated_at = datetime.now(timezone.utc)

        if workflow_status is FindingStatus.FALSE_POSITIVE:
            raw_result = finding.raw_result if isinstance(finding.raw_result, dict) else {}
            raw_check_id = raw_result.get("check_id")
            diagnostic_mappings = session.scalars(
                select(DiagnosticRule).where(
                    DiagnosticRule.catalog_rule_id == finding.rule_id,
                    DiagnosticRule.language == finding.language,
                )
            ).all()
            diagnostic_mapping = next(
                (
                    mapping
                    for mapping in diagnostic_mappings
                    if _matches_semgrep_rule_id(
                        raw_check_id, mapping.semgrep_rule_id
                    )
                ),
                None,
            )
            semgrep_rule_id = (
                diagnostic_mapping.semgrep_rule_id
                if diagnostic_mapping is not None
                else None
            )
            evidence_lines = (
                finding.evidence.get("lines")
                if isinstance(finding.evidence, dict)
                else None
            )
            fingerprint = evidence_sha256(evidence_lines)
            analysis_run = session.get(AnalysisRun, finding.analysis_run_id)
            if (
                analysis_run is not None
                and semgrep_rule_id is not None
                and fingerprint is not None
            ):
                suppression = session.scalar(
                    select(FindingSuppression).where(
                        FindingSuppression.project_id == analysis_run.project_id,
                        FindingSuppression.language == finding.language,
                        FindingSuppression.semgrep_rule_id == semgrep_rule_id,
                        FindingSuppression.file_path == finding.file_path,
                        FindingSuppression.evidence_sha256 == fingerprint,
                    )
                )
                if suppression is None:
                    suppression = FindingSuppression(
                        project_id=analysis_run.project_id,
                        language=finding.language,
                        semgrep_rule_id=semgrep_rule_id,
                        file_path=finding.file_path,
                        evidence_sha256=fingerprint,
                        source_finding_id=finding.id,
                        created_by=updated_by,
                        is_active=True,
                    )
                    session.add(suppression)
                else:
                    suppression.source_finding_id = finding.id
                    suppression.created_by = updated_by
                    suppression.is_active = True
        else:
            suppressions = session.scalars(
                select(FindingSuppression).where(
                    FindingSuppression.source_finding_id == finding.id,
                    FindingSuppression.is_active.is_(True),
                )
            ).all()
            for suppression in suppressions:
                suppression.is_active = False
    return workflow


def is_workflow_overdue(
    workflow: FindingWorkflow, *, today: date | None = None
) -> bool:
    """Return the current display state without persisting derived data."""
    reference_date = today or date.today()
    return (
        workflow.due_date is not None
        and workflow.due_date < reference_date
        and workflow.status in OPEN_WORKFLOW_STATUSES
    )
