"""Rule-catalog seed operations."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.rule import Rule
from app.rules.catalog import KISA_2021_CATALOG


def seed_kisa_2021_catalog(session: Session) -> None:
    """Synchronize the supplied official catalog without duplicating rules."""
    with session.begin():
        existing_rules = {
            rule.standard_id: rule for rule in session.scalars(select(Rule)).all()
        }
        for entry in KISA_2021_CATALOG:
            rule = existing_rules.get(entry.standard_id)
            if rule is None:
                session.add(
                    Rule(
                        name=entry.name,
                        description=entry.description,
                        standard_id=entry.standard_id,
                        category=entry.category,
                        severity=entry.severity,
                        supported_languages=[language.value for language in entry.supported_languages],
                        implementation_status=entry.implementation_status,
                        semgrep_rule_id=entry.semgrep_rule_id,
                    )
                )
                continue
            rule.name = entry.name
            rule.description = entry.description
            rule.category = entry.category
            rule.severity = entry.severity
            rule.supported_languages = [language.value for language in entry.supported_languages]
            rule.implementation_status = entry.implementation_status
            rule.semgrep_rule_id = entry.semgrep_rule_id
