"""KISA catalog seeding and diagnostic-rule mapping management."""

from __future__ import annotations

import re
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.db.models.diagnostic_rule import DiagnosticRule
from app.db.models.enums import Confidence, ImplementationStatus, Language
from app.db.models.rule import Rule
from app.rules.catalog import KISA_2021_CATALOG
from app.rules.cwe import APPROVED_CWE_MAPPINGS


class DiagnosticRuleManagementError(ValueError):
    """A safe validation error for diagnostic-rule management."""


@dataclass(frozen=True, slots=True)
class DiagnosticRuleMetadataInput:
    primary_cwe_id: str = ""
    related_cwe_ids: str = ""
    cwe_mapping_confidence: str = ""
    remediation_guidance: str = ""


_CWE_ID_PATTERN = re.compile(r"^CWE-[1-9][0-9]*$")


def _normalized_metadata(
    value: DiagnosticRuleMetadataInput,
) -> tuple[str | None, list[str], Confidence | None, str | None]:
    primary = value.primary_cwe_id.strip().upper()
    related = [
        item.strip().upper()
        for item in value.related_cwe_ids.split(",")
        if item.strip()
    ]
    guidance = value.remediation_guidance.strip() or None
    if primary and not _CWE_ID_PATTERN.fullmatch(primary):
        raise DiagnosticRuleManagementError("주요 CWE는 CWE-숫자 형식이어야 합니다.")
    if any(not _CWE_ID_PATTERN.fullmatch(item) for item in related):
        raise DiagnosticRuleManagementError("관련 CWE는 쉼표로 구분한 CWE-숫자 형식이어야 합니다.")
    if len(set(related)) != len(related) or (primary and primary in related):
        raise DiagnosticRuleManagementError("주요·관련 CWE를 중복해서 입력할 수 없습니다.")
    try:
        confidence = (
            Confidence(value.cwe_mapping_confidence.strip().upper())
            if value.cwe_mapping_confidence.strip()
            else None
        )
    except ValueError as exc:
        raise DiagnosticRuleManagementError("유효하지 않은 CWE 매핑 확신 수준입니다.") from exc
    if not primary and (related or confidence):
        raise DiagnosticRuleManagementError("주요 CWE 없이 관련 CWE나 확신 수준을 입력할 수 없습니다.")
    if primary and confidence is None:
        raise DiagnosticRuleManagementError("CWE 매핑 확신 수준을 선택하세요.")
    if guidance and len(guidance) > 2_000:
        raise DiagnosticRuleManagementError("조치 권고는 2,000자 이하여야 합니다.")
    return primary or None, related, confidence, guidance


def _built_in_rule_ids() -> dict[str, dict[Language, str]]:
    """Return fixed mappings for the repository-owned diagnostic rules."""
    mappings: dict[str, dict[Language, str]] = {}
    for entry in KISA_2021_CATALOG:
        if entry.semgrep_rule_id is None:
            continue
        base_rule_id = entry.semgrep_rule_id.removesuffix("-python")
        mappings[entry.standard_id] = {
            language: f"{base_rule_id}-{language.value.lower()}"
            for language in entry.supported_languages
        }
    return mappings


def seed_kisa_2021_catalog(session: Session) -> None:
    """Synchronize official catalog fields and seed built-in mappings once."""
    built_in_rule_ids = _built_in_rule_ids()
    built_in_standard_ids = {
        entry.standard_id
        for entry in KISA_2021_CATALOG
        if entry.implementation_status is ImplementationStatus.PARTIAL
    }

    with session.begin():
        existing = {
            rule.standard_id: rule for rule in session.scalars(select(Rule)).all()
        }
        for entry in KISA_2021_CATALOG:
            rule = existing.get(entry.standard_id)
            if rule is None:
                session.add(
                    Rule(
                        name=entry.name,
                        description=entry.description,
                        standard_id=entry.standard_id,
                        category=entry.category,
                        item_number=entry.item_number,
                        reference_info=entry.reference_info,
                        is_active=True,
                        severity=entry.severity,
                        supported_languages=[
                            language.value for language in entry.supported_languages
                        ],
                        implementation_status=entry.implementation_status,
                        semgrep_rule_id=entry.semgrep_rule_id,
                    )
                )
            else:
                rule.name = entry.name
                rule.description = entry.description
                rule.category = entry.category
                rule.item_number = entry.item_number
                rule.reference_info = entry.reference_info
                rule.severity = entry.severity

    with session.begin():
        rules = {
            rule.standard_id: rule
            for rule in session.scalars(
                select(Rule).options(selectinload(Rule.diagnostic_rules))
            ).all()
        }
        for standard_id in sorted(built_in_standard_ids):
            rule = rules[standard_id]
            # Seed each built-in mapping set only once. Administrator changes
            # made after that point must survive application restarts.
            if rule.diagnostic_rules:
                continue
            for language, semgrep_rule_id in built_in_rule_ids[standard_id].items():
                cwe_mapping = APPROVED_CWE_MAPPINGS[semgrep_rule_id]
                session.add(
                    DiagnosticRule(
                        catalog_rule_id=rule.id,
                        language=language,
                        semgrep_rule_id=semgrep_rule_id,
                        primary_cwe_id=cwe_mapping.primary_cwe_id,
                        related_cwe_ids=list(cwe_mapping.related_cwe_ids),
                        cwe_mapping_confidence=cwe_mapping.confidence,
                        remediation_guidance=cwe_mapping.remediation_guidance,
                        is_active=True,
                    )
                )

def save_diagnostic_rule_mappings(
    session: Session,
    *,
    catalog_rule_id: int,
    rule_ids: dict[Language, str],
    mapping_metadata: dict[Language, DiagnosticRuleMetadataInput] | None = None,
) -> Rule:
    normalized_rule_ids = {
        language: rule_id.strip()
        for language, rule_id in rule_ids.items()
        if rule_id.strip()
    }
    if not normalized_rule_ids:
        raise DiagnosticRuleManagementError("지원 언어를 하나 이상 선택하세요.")
    if len(set(normalized_rule_ids.values())) != len(normalized_rule_ids):
        raise DiagnosticRuleManagementError("Semgrep Rule ID가 중복되었습니다.")
    normalized_metadata = {
        language: _normalized_metadata(
            (mapping_metadata or {}).get(language, DiagnosticRuleMetadataInput())
        )
        for language in normalized_rule_ids
    }
    try:
        with session.begin():
            rule = session.scalar(
                select(Rule)
                .options(selectinload(Rule.diagnostic_rules))
                .where(Rule.id == catalog_rule_id)
            )
            if rule is None:
                raise DiagnosticRuleManagementError(
                    "KISA 카탈로그 항목을 찾을 수 없습니다."
                )
            existing = {
                mapping.language: mapping for mapping in rule.diagnostic_rules
            }
            for language, mapping in existing.items():
                if language not in normalized_rule_ids:
                    session.delete(mapping)
            for language, semgrep_rule_id in normalized_rule_ids.items():
                mapping = existing.get(language)
                if mapping is None:
                    metadata = normalized_metadata[language]
                    session.add(
                        DiagnosticRule(
                            catalog_rule_id=rule.id,
                            language=language,
                            semgrep_rule_id=semgrep_rule_id,
                            primary_cwe_id=metadata[0],
                            related_cwe_ids=metadata[1],
                            cwe_mapping_confidence=metadata[2],
                            remediation_guidance=metadata[3],
                            is_active=True,
                        )
                    )
                else:
                    mapping.semgrep_rule_id = semgrep_rule_id
                    mapping.is_active = True
                    if mapping_metadata is not None and language in mapping_metadata:
                        metadata = normalized_metadata[language]
                        mapping.primary_cwe_id = metadata[0]
                        mapping.related_cwe_ids = metadata[1]
                        mapping.cwe_mapping_confidence = metadata[2]
                        mapping.remediation_guidance = metadata[3]
            rule.supported_languages = [
                language.value
                for language in Language
                if language in normalized_rule_ids
            ]
            rule.implementation_status = ImplementationStatus.PARTIAL
            preferred_language = (
                Language.PYTHON
                if Language.PYTHON in normalized_rule_ids
                else next(iter(normalized_rule_ids))
            )
            rule.semgrep_rule_id = normalized_rule_ids[preferred_language]
        return rule
    except IntegrityError as exc:
        raise DiagnosticRuleManagementError(
            "이미 사용 중인 Semgrep Rule ID입니다."
        ) from exc


def toggle_catalog_rule_active(session: Session, *, catalog_rule_id: int) -> Rule:
    with session.begin():
        rule = session.get(Rule, catalog_rule_id)
        if rule is None:
            raise DiagnosticRuleManagementError(
                "KISA 카탈로그 항목을 찾을 수 없습니다."
            )
        rule.is_active = not rule.is_active
    return rule
