"""KISA catalog seeding and language-specific diagnostic-rule management."""

from __future__ import annotations

import re

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.db.models.diagnostic_rule import DiagnosticRule
from app.db.models.enums import Language
from app.db.models.rule import Rule
from app.rules.catalog import KISA_2021_CATALOG

_INITIAL_DIAGNOSTIC_RULE_IDS = {
    "제1절-1": {Language.JAVA: "kisa-2021-sql-injection-java", Language.JAVASCRIPT: "kisa-2021-sql-injection-javascript", Language.PYTHON: "kisa-2021-sql-injection-python"},
    "제1절-5": {Language.JAVA: "kisa-2021-os-command-injection-java", Language.JAVASCRIPT: "kisa-2021-os-command-injection-javascript", Language.PYTHON: "kisa-2021-os-command-injection-python"},
    "제2절-4": {Language.JAVA: "kisa-2021-weak-crypto-java", Language.JAVASCRIPT: "kisa-2021-weak-crypto-javascript", Language.PYTHON: "kisa-2021-weak-crypto-python"},
    "제2절-6": {Language.JAVA: "kisa-2021-hardcoded-sensitive-information-java", Language.JAVASCRIPT: "kisa-2021-hardcoded-sensitive-information-javascript", Language.PYTHON: "kisa-2021-hardcoded-sensitive-information-python"},
}
_RULE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,254}$")


class DiagnosticRuleManagementError(ValueError):
    """A safe validation error for diagnostic-rule management."""


def seed_kisa_2021_catalog(session: Session) -> None:
    """Synchronize official catalog fields and add missing built-in mappings."""
    with session.begin():
        existing = {rule.standard_id: rule for rule in session.scalars(select(Rule)).all()}
        for entry in KISA_2021_CATALOG:
            rule = existing.get(entry.standard_id)
            if rule is None:
                session.add(Rule(name=entry.name, description=entry.description, standard_id=entry.standard_id, category=entry.category, item_number=entry.item_number, reference_info=entry.reference_info, is_active=True, severity=entry.severity, supported_languages=[language.value for language in entry.supported_languages], implementation_status=entry.implementation_status, semgrep_rule_id=entry.semgrep_rule_id))
            else:
                rule.name, rule.description, rule.category = entry.name, entry.description, entry.category
                rule.item_number, rule.reference_info, rule.severity = entry.item_number, entry.reference_info, entry.severity
                rule.supported_languages = [language.value for language in entry.supported_languages]
                rule.implementation_status, rule.semgrep_rule_id = entry.implementation_status, entry.semgrep_rule_id
    with session.begin():
        rules = {rule.standard_id: rule for rule in session.scalars(select(Rule).options(selectinload(Rule.diagnostic_rules))).all()}
        for standard_id, mappings in _INITIAL_DIAGNOSTIC_RULE_IDS.items():
            rule = rules[standard_id]
            existing_languages = {mapping.language for mapping in rule.diagnostic_rules}
            for language, semgrep_rule_id in mappings.items():
                if language not in existing_languages:
                    session.add(DiagnosticRule(catalog_rule_id=rule.id, language=language, semgrep_rule_id=semgrep_rule_id, is_active=True))


def save_diagnostic_rule_mappings(session: Session, *, catalog_rule_id: int, selected_languages: list[Language], semgrep_rule_ids: dict[Language, str]) -> Rule:
    if not selected_languages:
        raise DiagnosticRuleManagementError("지원 언어를 하나 이상 선택하세요.")
    if len(set(selected_languages)) != len(selected_languages):
        raise DiagnosticRuleManagementError("지원 언어가 중복되었습니다.")
    normalized = {}
    for language in selected_languages:
        value = semgrep_rule_ids.get(language, "").strip()
        if not value:
            raise DiagnosticRuleManagementError(f"{language.value} Semgrep Rule ID를 입력하세요.")
        if not _RULE_ID_PATTERN.fullmatch(value):
            raise DiagnosticRuleManagementError("Semgrep Rule ID 형식이 올바르지 않습니다.")
        normalized[language] = value
    if len(set(normalized.values())) != len(normalized):
        raise DiagnosticRuleManagementError("같은 Semgrep Rule ID를 여러 언어에 사용할 수 없습니다.")
    try:
        with session.begin():
            rule = session.scalar(select(Rule).options(selectinload(Rule.diagnostic_rules)).where(Rule.id == catalog_rule_id))
            if rule is None:
                raise DiagnosticRuleManagementError("KISA 카탈로그 항목을 찾을 수 없습니다.")
            existing = {mapping.language: mapping for mapping in rule.diagnostic_rules}
            for language, mapping in existing.items():
                if language not in normalized:
                    session.delete(mapping)
            for language, semgrep_rule_id in normalized.items():
                mapping = existing.get(language)
                if mapping is None:
                    session.add(DiagnosticRule(catalog_rule_id=rule.id, language=language, semgrep_rule_id=semgrep_rule_id, is_active=True))
                else:
                    mapping.semgrep_rule_id, mapping.is_active = semgrep_rule_id, True
        return rule
    except IntegrityError as exc:
        raise DiagnosticRuleManagementError("이미 사용 중인 Semgrep Rule ID입니다.") from exc


def toggle_catalog_rule_active(session: Session, *, catalog_rule_id: int) -> Rule:
    with session.begin():
        rule = session.get(Rule, catalog_rule_id)
        if rule is None:
            raise DiagnosticRuleManagementError("KISA 카탈로그 항목을 찾을 수 없습니다.")
        rule.is_active = not rule.is_active
    return rule
