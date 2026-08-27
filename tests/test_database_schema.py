from pathlib import Path

import pytest
from sqlalchemy import func, inspect, select, text
from sqlalchemy.exc import StatementError
from sqlalchemy.orm import Session

from app.db.database import create_db_engine, initialize_database
from app.db.models import AnalysisRun, Finding, Project, ProjectUser, Rule, User
from app.db.models.enums import (
    AnalysisStatus,
    Confidence,
    ImplementationStatus,
    Language,
    Severity,
    SourceType,
    UserRole,
)


EXPECTED_TABLES = {
    "users",
    "projects",
    "project_users",
    "analysis_runs",
    "rules",
    "findings",
}

EXPECTED_FOREIGN_KEYS = {
    "projects": {("created_by", "users", "id", "RESTRICT")},
    "project_users": {
        ("project_id", "projects", "id", "CASCADE"),
        ("user_id", "users", "id", "CASCADE"),
    },
    "analysis_runs": {
        ("project_id", "projects", "id", "CASCADE"),
        ("executed_by", "users", "id", "RESTRICT"),
    },
    "findings": {
        ("analysis_run_id", "analysis_runs", "id", "CASCADE"),
        ("rule_id", "rules", "id", "RESTRICT"),
    },
}


def _foreign_keys(inspector, table_name: str) -> set[tuple[str, str, str, str]]:
    result = set()
    for foreign_key in inspector.get_foreign_keys(table_name):
        result.add(
            (
                foreign_key["constrained_columns"][0],
                foreign_key["referred_table"],
                foreign_key["referred_columns"][0],
                foreign_key["options"]["ondelete"],
            )
        )
    return result


def test_create_all_builds_six_tables_and_foreign_keys(tmp_path: Path) -> None:
    database_path = tmp_path / "schema.db"
    engine = create_db_engine(f"sqlite:///{database_path}")

    initialize_database(engine)
    inspector = inspect(engine)

    assert set(inspector.get_table_names()) == EXPECTED_TABLES
    for table_name, expected in EXPECTED_FOREIGN_KEYS.items():
        assert _foreign_keys(inspector, table_name) == expected

    with engine.connect() as connection:
        assert connection.execute(text("PRAGMA foreign_keys")).scalar_one() == 1

    engine.dispose()


def test_documented_enum_constraints_are_created(tmp_path: Path) -> None:
    engine = create_db_engine(f"sqlite:///{tmp_path / 'enums.db'}")
    initialize_database(engine)
    inspector = inspect(engine)

    constraint_names = {
        constraint["name"]
        for table_name in EXPECTED_TABLES
        for constraint in inspector.get_check_constraints(table_name)
    }

    assert {
        "user_role",
        "source_type",
        "project_language",
        "analysis_language",
        "analysis_status",
        "rule_severity",
        "implementation_status",
        "finding_language",
        "finding_severity",
        "finding_confidence",
    } <= constraint_names

    engine.dispose()


def test_models_persist_and_project_deletion_cascades(tmp_path: Path) -> None:
    engine = create_db_engine(f"sqlite:///{tmp_path / 'relationships.db'}")
    initialize_database(engine)

    with Session(engine) as session:
        user = User(
            username="owner",
            password_hash="hashed-password",
            role=UserRole.ADMIN,
        )
        session.add(user)
        session.flush()

        project = Project(
            name="sample",
            source_type=SourceType.ZIP,
            language=Language.PYTHON,
            source_path="uploads/sample.zip",
            created_by=user.id,
        )
        session.add(project)
        session.flush()
        session.add(ProjectUser(project_id=project.id, user_id=user.id))

        rule = Rule(
            name="Sample rule",
            description="Test-only rule",
            standard_id="TEST-001",
            category="TEST",
            severity=Severity.HIGH,
            supported_languages=[Language.PYTHON.value],
            implementation_status=ImplementationStatus.IMPLEMENTED,
            semgrep_rule_id="test.sample-rule",
        )
        session.add(rule)
        session.flush()

        analysis_run = AnalysisRun(
            project_id=project.id,
            engine="semgrep",
            language=Language.PYTHON,
            status=AnalysisStatus.COMPLETED,
            executed_by=user.id,
        )
        session.add(analysis_run)
        session.flush()

        session.add(
            Finding(
                analysis_run_id=analysis_run.id,
                rule_id=rule.id,
                rule_name=rule.name,
                kisa_id=rule.standard_id,
                language=Language.PYTHON,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                file_path="app.py",
                start_line=1,
                message="Sample finding",
                raw_result={"check_id": rule.semgrep_rule_id},
            )
        )
        session.commit()

        assert session.scalar(select(func.count()).select_from(Finding)) == 1

        session.delete(project)
        session.commit()

        assert session.scalar(select(func.count()).select_from(ProjectUser)) == 0
        assert session.scalar(select(func.count()).select_from(AnalysisRun)) == 0
        assert session.scalar(select(func.count()).select_from(Finding)) == 0
        assert session.scalar(select(func.count()).select_from(Rule)) == 1
        assert session.scalar(select(func.count()).select_from(User)) == 1

    engine.dispose()


def test_rule_supported_languages_accepts_only_documented_values_and_tracks_changes(
    tmp_path: Path,
) -> None:
    engine = create_db_engine(f"sqlite:///{tmp_path / 'rule-languages.db'}")
    initialize_database(engine)

    with Session(engine) as session:
        invalid_rule = Rule(
            name="Invalid language rule",
            description="Test-only rule",
            standard_id="TEST-INVALID-LANGUAGE",
            category="TEST",
            severity=Severity.LOW,
            supported_languages=["RUBY"],
        )
        session.add(invalid_rule)
        with pytest.raises(StatementError, match="unsupported language"):
            session.flush()
        session.rollback()

        rule = Rule(
            name="Mutable language rule",
            description="Test-only rule",
            standard_id="TEST-MUTABLE-LANGUAGE",
            category="TEST",
            severity=Severity.LOW,
            supported_languages=[Language.JAVA.value],
        )
        session.add(rule)
        session.commit()

        rule.supported_languages.append(Language.PYTHON.value)
        session.commit()
        session.expire_all()

        persisted_rule = session.get(Rule, rule.id)
        assert persisted_rule is not None
        assert persisted_rule.supported_languages == ["JAVA", "PYTHON"]

    engine.dispose()
