"""KISA catalog seeding and diagnostic-rule mapping management."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.db.models.diagnostic_rule import DiagnosticRule
from app.db.models.enums import ImplementationStatus, Language
from app.db.models.rule import Rule
from app.rules.catalog import KISA_2021_CATALOG


class DiagnosticRuleManagementError(ValueError):
    """A safe validation error for diagnostic-rule management."""


def _built_in_rule_ids() -> dict[str, dict[Language, str]]:
    """Return fixed mappings for the eight built-in, repository-owned rules."""
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
                session.add(
                    DiagnosticRule(
                        catalog_rule_id=rule.id,
                        language=language,
                        semgrep_rule_id=semgrep_rule_id,
                        is_active=True,
                    )
                )

def save_diagnostic_rule_mappings(
    session: Session,
    *,
    catalog_rule_id: int,
    rule_ids: dict[Language, str],
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
                    session.add(
                        DiagnosticRule(
                            catalog_rule_id=rule.id,
                            language=language,
                            semgrep_rule_id=semgrep_rule_id,
                            is_active=True,
                        )
                    )
                else:
                    mapping.semgrep_rule_id = semgrep_rule_id
                    mapping.is_active = True
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
