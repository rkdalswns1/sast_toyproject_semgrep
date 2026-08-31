from pathlib import Path

import pytest
from sqlalchemy import func, inspect, select, text
from sqlalchemy.exc import StatementError
from sqlalchemy.orm import Session

from app.db.database import create_db_engine, initialize_database
from app.db.models import (
    AnalysisRun,
    DiagnosticRule,
    Finding,
    Project,
    ProjectUser,
    Rule,
    SchemaVersion,
    User,
)
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
    "diagnostic_rules",
    "schema_versions",
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
    "diagnostic_rules": {("catalog_rule_id", "rules", "id", "CASCADE")},
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


def test_create_all_builds_domain_tables_schema_history_and_foreign_keys(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "schema.db"
    engine = create_db_engine(f"sqlite:///{database_path}")

    initialize_database(engine)
    inspector = inspect(engine)

    assert set(inspector.get_table_names()) == EXPECTED_TABLES
    for table_name, expected in EXPECTED_FOREIGN_KEYS.items():
        assert _foreign_keys(inspector, table_name) == expected

    with engine.connect() as connection:
        assert connection.execute(text("PRAGMA foreign_keys")).scalar_one() == 1

    with Session(engine) as session:
        versions = session.scalars(
            select(SchemaVersion).order_by(SchemaVersion.version)
        ).all()
        assert [version.version for version in versions] == [1, 2, 3, 4, 5]
        assert all(version.description and version.applied_at for version in versions)

    initialize_database(engine)
    with Session(engine) as session:
        assert session.scalar(select(func.count()).select_from(SchemaVersion)) == 5

    engine.dispose()


def test_existing_database_is_upgraded_and_migration_is_recorded(
    tmp_path: Path,
) -> None:
    engine = create_db_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                CREATE TABLE rules (
                    id INTEGER PRIMARY KEY,
                    name VARCHAR(200) NOT NULL,
                    description TEXT NOT NULL,
                    standard_id VARCHAR(100) NOT NULL UNIQUE,
                    category VARCHAR(100) NOT NULL,
                    severity VARCHAR(20) NOT NULL,
                    supported_languages JSON NOT NULL,
                    implementation_status VARCHAR(30) NOT NULL,
                    semgrep_rule_id VARCHAR(255)
                )
                """
            )
        )
        connection.execute(
            text(
                """
                INSERT INTO rules (
                    id, name, description, standard_id, category, severity,
                    supported_languages, implementation_status, semgrep_rule_id
                ) VALUES (
                    1, 'Legacy rule', 'legacy', 'TEST-001', 'TEST', 'LOW',
                    '[]', 'NOT_IMPLEMENTED', NULL
                )
                """
            )
        )

    initialize_database(engine)
    inspector = inspect(engine)
    rule_columns = {column["name"] for column in inspector.get_columns("rules")}
    assert {"item_number", "reference_info", "is_active"} <= rule_columns

    with Session(engine) as session:
        legacy_rule = session.get(Rule, 1)
        assert legacy_rule is not None
        assert legacy_rule.item_number == 1
        assert legacy_rule.reference_info is None
        assert legacy_rule.is_active is True
        assert session.scalars(
            select(SchemaVersion.version).order_by(SchemaVersion.version)
        ).all() == [1, 2, 3, 4, 5]

    engine.dispose()


def test_existing_catalog_rows_are_upgraded_for_expanded_builtin_rules(
    tmp_path: Path,
) -> None:
    engine = create_db_engine(f"sqlite:///{tmp_path / 'catalog-upgrade.db'}")
    initialize_database(engine)

    with Session(engine) as session:
        session.delete(session.get(SchemaVersion, 4))
        session.add(
            Rule(
                name="경로 조작 및 자원 삽입",
                description="legacy catalog row",
                standard_id="제1절-3",
                category="입력데이터 검증 및 표현",
                item_number=3,
                reference_info=None,
                is_active=False,
                severity=Severity.INFO,
                supported_languages=[],
                implementation_status=ImplementationStatus.NOT_IMPLEMENTED,
                semgrep_rule_id=None,
            )
        )
        session.commit()

    initialize_database(engine)

    with Session(engine) as session:
        rule = session.scalar(select(Rule).where(Rule.standard_id == "제1절-3"))
        assert rule is not None
        assert rule.implementation_status is ImplementationStatus.PARTIAL
        assert rule.supported_languages == ["JAVA", "JAVASCRIPT", "PYTHON"]
        assert rule.semgrep_rule_id == "kisa-2021-path-traversal-python"
        assert rule.is_active is False
        assert session.get(SchemaVersion, 4) is not None

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
        "rule_item_number_positive",
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


def test_existing_finding_raw_path_is_normalized_by_migration(tmp_path: Path) -> None:
    engine = create_db_engine(f"sqlite:///{tmp_path / 'finding-path-upgrade.db'}")
    initialize_database(engine)

    with Session(engine) as session:
        user = User(
            username="owner@company.com",
            password_hash="hashed-password",
            role=UserRole.ADMIN,
        )
        session.add(user)
        session.flush()
        project = Project(
            name="sample",
            source_type=SourceType.ZIP,
            language=Language.PYTHON,
            source_path="uploads/sample",
            created_by=user.id,
        )
        session.add(project)
        session.flush()
        rule = Rule(
            name="Sample rule",
            description="Test-only rule",
            standard_id="TEST-PATH-001",
            category="TEST",
            severity=Severity.HIGH,
            supported_languages=[Language.PYTHON.value],
            implementation_status=ImplementationStatus.PARTIAL,
        )
        session.add(rule)
        session.flush()
        run = AnalysisRun(
            project_id=project.id,
            engine="Semgrep",
            language=Language.PYTHON,
            status=AnalysisStatus.COMPLETED,
            executed_by=user.id,
        )
        session.add(run)
        session.flush()
        finding = Finding(
            analysis_run_id=run.id,
            rule_id=rule.id,
            rule_name=rule.name,
            kisa_id=rule.standard_id,
            language=Language.PYTHON,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            file_path="src/vulnerable.py",
            start_line=1,
            message="Sample finding",
            raw_result={
                "check_id": "test.path",
                "path": "/tmp/analysis-1/source/src/vulnerable.py",
                "extra": {"message": "preserved"},
            },
        )
        session.add(finding)
        session.delete(session.get(SchemaVersion, 5))
        session.commit()
        finding_id = finding.id

    initialize_database(engine)

    with Session(engine) as session:
        migrated = session.get(Finding, finding_id)
        assert migrated is not None
        assert migrated.raw_result["path"] == "src/vulnerable.py"
        assert migrated.raw_result["check_id"] == "test.path"
        assert migrated.raw_result["extra"] == {"message": "preserved"}
        assert session.get(SchemaVersion, 5) is not None

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
