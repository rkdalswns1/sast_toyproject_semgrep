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
    FindingRevalidation,
    FindingWorkflow,
    Project,
    ProjectUser,
    Rule,
    SchemaVersion,
    User,
)
from app.db.models.enums import (
    AnalysisStatus,
    Confidence,
    FindingStatus,
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
    "finding_workflows",
    "finding_revalidations",
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
    "finding_workflows": {
        ("finding_id", "findings", "id", "CASCADE"),
        ("updated_by", "users", "id", "RESTRICT"),
        ("assignee_id", "users", "id", "RESTRICT"),
    },
    "finding_revalidations": {
        ("source_finding_id", "findings", "id", "CASCADE"),
        ("analysis_run_id", "analysis_runs", "id", "CASCADE"),
        ("matched_finding_id", "findings", "id", "SET NULL"),
        ("executed_by", "users", "id", "RESTRICT"),
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
        assert [version.version for version in versions] == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
        assert all(version.description and version.applied_at for version in versions)

    initialize_database(engine)
    with Session(engine) as session:
        assert session.scalar(select(func.count()).select_from(SchemaVersion)) == 14

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
        ).all() == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]

    engine.dispose()


def test_legacy_admin_roles_are_migrated_without_breaking_project_relations(
    tmp_path: Path,
) -> None:
    engine = create_db_engine(f"sqlite:///{tmp_path / 'legacy-users.db'}")
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                CREATE TABLE users (
                    id INTEGER NOT NULL PRIMARY KEY,
                    username VARCHAR(100) NOT NULL UNIQUE,
                    password_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(5) NOT NULL,
                    is_active BOOLEAN NOT NULL DEFAULT 1,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    CONSTRAINT user_role CHECK (role IN ('ADMIN', 'USER'))
                )
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TABLE projects (
                    id INTEGER NOT NULL PRIMARY KEY,
                    name VARCHAR(200) NOT NULL,
                    description TEXT,
                    source_type VARCHAR(3) NOT NULL,
                    language VARCHAR(10) NOT NULL,
                    source_path VARCHAR(500) NOT NULL,
                    created_by INTEGER NOT NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE RESTRICT
                )
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TABLE project_users (
                    project_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    PRIMARY KEY (project_id, user_id),
                    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """
            )
        )
        connection.execute(
            text(
                "INSERT INTO users (id, username, password_hash, role) VALUES "
                "(1, 'admin@company.com', 'admin-hash', 'ADMIN'), "
                "(2, 'member@company.com', 'member-hash', 'USER')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO projects "
                "(id, name, source_type, language, source_path, created_by) "
                "VALUES (1, 'Legacy project', 'ZIP', 'PYTHON', 'uploads/legacy.zip', 1)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO project_users (project_id, user_id) "
                "VALUES (1, 1), (1, 2)"
            )
        )

    initialize_database(engine)

    with engine.connect() as connection:
        migrated_users = connection.execute(
            text(
                "SELECT id, role, must_change_password FROM users ORDER BY id"
            )
        ).all()
        assert migrated_users == [(1, "SUPER_ADMIN", 0), (2, "USER", 0)]
        assert connection.execute(
            text("SELECT created_by FROM projects WHERE id = 1")
        ).scalar_one() == 1
        assert connection.execute(
            text(
                "SELECT user_id FROM project_users "
                "WHERE project_id = 1 ORDER BY user_id"
            )
        ).scalars().all() == [1, 2]
        assert connection.execute(text("PRAGMA foreign_key_check")).all() == []

    with Session(engine) as session:
        assert session.get(User, 1).role is UserRole.SUPER_ADMIN
        assert session.get(User, 2).must_change_password is False
        assert session.get(SchemaVersion, 6) is not None
        assert session.get(SchemaVersion, 7) is not None
        assert session.get(SchemaVersion, 8) is not None
        assert session.get(SchemaVersion, 9) is not None
        assert session.get(SchemaVersion, 10) is not None
        assert session.get(SchemaVersion, 11) is not None
        assert session.get(SchemaVersion, 12) is not None
        assert session.get(SchemaVersion, 13) is not None
        assert session.get(SchemaVersion, 14) is not None

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


def test_existing_catalog_rows_are_upgraded_for_phase11_rules(tmp_path: Path) -> None:
    engine = create_db_engine(f"sqlite:///{tmp_path / 'phase11-upgrade.db'}")
    initialize_database(engine)

    with Session(engine) as session:
        session.delete(session.get(SchemaVersion, 7))
        session.add_all(
            [
                Rule(
                    name="부적절한 인증서 유효성 검증",
                    description="legacy catalog row",
                    standard_id="제2절-11",
                    category="보안기능",
                    item_number=11,
                    is_active=False,
                    severity=Severity.INFO,
                    supported_languages=[],
                    implementation_status=ImplementationStatus.NOT_IMPLEMENTED,
                ),
                Rule(
                    name="신뢰할 수 없는 데이터의 역직렬화",
                    description="legacy catalog row",
                    standard_id="제5절-5",
                    category="코드오류",
                    item_number=5,
                    is_active=False,
                    severity=Severity.INFO,
                    supported_languages=[],
                    implementation_status=ImplementationStatus.NOT_IMPLEMENTED,
                ),
            ]
        )
        session.commit()

    initialize_database(engine)

    with Session(engine) as session:
        certificate = session.scalar(
            select(Rule).where(Rule.standard_id == "제2절-11")
        )
        deserialization = session.scalar(
            select(Rule).where(Rule.standard_id == "제5절-5")
        )
        assert certificate is not None
        assert certificate.severity is Severity.HIGH
        assert certificate.supported_languages == ["JAVA", "JAVASCRIPT", "PYTHON"]
        assert certificate.implementation_status is ImplementationStatus.PARTIAL
        assert certificate.semgrep_rule_id == (
            "kisa-2021-improper-certificate-validation-python"
        )
        assert certificate.is_active is False
        assert deserialization is not None
        assert deserialization.severity is Severity.HIGH
        assert deserialization.supported_languages == ["JAVA", "PYTHON"]
        assert deserialization.implementation_status is ImplementationStatus.PARTIAL
        assert deserialization.semgrep_rule_id == (
            "kisa-2021-unsafe-deserialization-python"
        )
        assert deserialization.is_active is False
        assert session.get(SchemaVersion, 7) is not None

    engine.dispose()


def test_existing_projects_default_to_single_language_after_phase12_migration(
    tmp_path: Path,
) -> None:
    engine = create_db_engine(f"sqlite:///{tmp_path / 'phase12-upgrade.db'}")
    initialize_database(engine)

    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO users (username, password_hash, role, is_active, "
                "must_change_password) VALUES "
                "('legacy@company.com', 'hash', 'USER', 1, 0)"
            )
        )
        user_id = connection.execute(
            text("SELECT id FROM users WHERE username = 'legacy@company.com'")
        ).scalar_one()
        connection.execute(
            text(
                "INSERT INTO projects (name, source_type, language, source_path, "
                "created_by, scan_all_languages) VALUES "
                "('Legacy project', 'ZIP', 'PYTHON', '', :user_id, 1)"
            ),
            {"user_id": user_id},
        )
        connection.execute(text("DELETE FROM schema_versions WHERE version = 8"))
        connection.execute(text("ALTER TABLE projects DROP COLUMN scan_all_languages"))

    initialize_database(engine)

    with Session(engine) as session:
        project = session.scalar(
            select(Project).where(Project.name == "Legacy project")
        )
        assert project is not None
        assert project.language is Language.PYTHON
        assert project.scan_all_languages is False
        assert session.get(SchemaVersion, 8) is not None

    engine.dispose()


def test_phase13_migration_backfills_open_workflow_for_existing_finding(
    tmp_path: Path,
) -> None:
    engine = create_db_engine(f"sqlite:///{tmp_path / 'phase13-upgrade.db'}")
    initialize_database(engine)

    with Session(engine) as session:
        user = User(
            username="owner@company.com",
            password_hash="hash",
            role=UserRole.SUPER_ADMIN,
        )
        session.add(user)
        session.flush()
        project = Project(
            name="Legacy Finding project",
            source_type=SourceType.ZIP,
            language=Language.PYTHON,
            source_path="",
            created_by=user.id,
        )
        session.add(project)
        session.flush()
        run = AnalysisRun(
            project_id=project.id,
            engine="Semgrep",
            language=Language.PYTHON,
            status=AnalysisStatus.COMPLETED,
            executed_by=user.id,
        )
        rule = Rule(
            name="Legacy rule",
            description="legacy",
            standard_id="LEGACY-WORKFLOW",
            category="test",
            severity=Severity.HIGH,
            supported_languages=["PYTHON"],
            implementation_status=ImplementationStatus.PARTIAL,
        )
        session.add_all([run, rule])
        session.flush()
        finding = Finding(
            analysis_run_id=run.id,
            rule_id=rule.id,
            rule_name=rule.name,
            kisa_id=rule.standard_id,
            language=Language.PYTHON,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            file_path="legacy.py",
            start_line=1,
            message="legacy",
            raw_result={"path": "legacy.py"},
        )
        session.add(finding)
        session.flush()
        finding_id = finding.id
        session.delete(session.get(SchemaVersion, 9))
        session.commit()

    initialize_database(engine)

    with Session(engine) as session:
        workflow = session.get(FindingWorkflow, finding_id)
        assert workflow is not None
        assert workflow.status is FindingStatus.OPEN
        assert workflow.note is None
        assert workflow.updated_by is None
        assert workflow.updated_at is None
        assert session.get(SchemaVersion, 9) is not None

    engine.dispose()


def test_phase14_migration_adds_nullable_source_metadata_to_existing_project(
    tmp_path: Path,
) -> None:
    engine = create_db_engine(f"sqlite:///{tmp_path / 'phase14-upgrade.db'}")
    initialize_database(engine)

    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO users (username, password_hash, role, is_active, "
                "must_change_password) VALUES "
                "('source-owner@company.com', 'hash', 'SUPER_ADMIN', 1, 0)"
            )
        )
        user_id = connection.execute(
            text("SELECT id FROM users WHERE username = 'source-owner@company.com'")
        ).scalar_one()
        connection.execute(
            text(
                "INSERT INTO projects (name, source_type, language, source_path, "
                "created_by, scan_all_languages) VALUES "
                "('Legacy source project', 'ZIP', 'PYTHON', '', :user_id, 0)"
            ),
            {"user_id": user_id},
        )
        connection.execute(text("DELETE FROM schema_versions WHERE version = 10"))
        connection.execute(text("ALTER TABLE projects DROP COLUMN source_version"))
        connection.execute(text("ALTER TABLE projects DROP COLUMN deployment_version"))
        connection.execute(text("ALTER TABLE projects DROP COLUMN source_description"))

    initialize_database(engine)

    with Session(engine) as session:
        project = session.scalar(
            select(Project).where(Project.name == "Legacy source project")
        )
        assert project is not None
        assert project.source_version is None
        assert project.deployment_version is None
        assert project.source_description is None
        assert session.get(SchemaVersion, 10) is not None

    engine.dispose()


def test_phase16_migration_adds_nullable_assignment_to_existing_workflow_table(
    tmp_path: Path,
) -> None:
    engine = create_db_engine(f"sqlite:///{tmp_path / 'phase16-upgrade.db'}")
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                CREATE TABLE finding_workflows (
                    finding_id INTEGER NOT NULL PRIMARY KEY,
                    status VARCHAR(20) NOT NULL DEFAULT 'OPEN',
                    note TEXT,
                    updated_by INTEGER,
                    updated_at DATETIME,
                    FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE,
                    FOREIGN KEY(updated_by) REFERENCES users(id) ON DELETE RESTRICT
                )
                """
            )
        )

    initialize_database(engine)
    inspector = inspect(engine)
    columns = {
        column["name"]
        for column in inspector.get_columns("finding_workflows")
    }
    assert {"assignee_id", "due_date"} <= columns
    with engine.connect() as connection:
        assignee_fk = next(
            row
            for row in connection.execute(
                text("PRAGMA foreign_key_list(finding_workflows)")
            ).all()
            if row[3] == "assignee_id"
        )
        assert (assignee_fk[2], assignee_fk[4], assignee_fk[6]) == (
            "users", "id", "RESTRICT"
        )
    with Session(engine) as session:
        assert session.get(SchemaVersion, 11) is not None

    engine.dispose()


def test_phase17_migration_creates_revalidation_history_table(
    tmp_path: Path,
) -> None:
    engine = create_db_engine(f"sqlite:///{tmp_path / 'phase17-upgrade.db'}")
    initialize_database(engine)
    with engine.begin() as connection:
        connection.execute(text("DELETE FROM schema_versions WHERE version = 12"))
        connection.execute(text("DROP TABLE finding_revalidations"))

    initialize_database(engine)
    inspector = inspect(engine)
    assert "finding_revalidations" in inspector.get_table_names()
    assert _foreign_keys(inspector, "finding_revalidations") == (
        EXPECTED_FOREIGN_KEYS["finding_revalidations"]
    )
    with Session(engine) as session:
        assert session.get(SchemaVersion, 12) is not None
        assert session.scalar(
            select(func.count()).select_from(FindingRevalidation)
        ) == 0

    engine.dispose()


def test_phase18_migration_adds_nullable_source_summary_to_existing_project(
    tmp_path: Path,
) -> None:
    engine = create_db_engine(f"sqlite:///{tmp_path / 'phase18-upgrade.db'}")
    initialize_database(engine)

    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO users (username, password_hash, role, is_active, "
                "must_change_password) VALUES "
                "('summary-owner@company.com', 'hash', 'SUPER_ADMIN', 1, 0)"
            )
        )
        user_id = connection.execute(
            text("SELECT id FROM users WHERE username = 'summary-owner@company.com'")
        ).scalar_one()
        connection.execute(
            text(
                "INSERT INTO projects (name, source_type, language, source_path, "
                "source_version, created_by, scan_all_languages) VALUES "
                "('Legacy summary project', 'ZIP', 'PYTHON', 'legacy/source', "
                "'source-1', :user_id, 0)"
            ),
            {"user_id": user_id},
        )
        connection.execute(text("DELETE FROM schema_versions WHERE version = 13"))
        connection.execute(text("ALTER TABLE projects DROP COLUMN source_summary"))

    initialize_database(engine)

    with Session(engine) as session:
        project = session.scalar(
            select(Project).where(Project.name == "Legacy summary project")
        )
        assert project is not None
        assert project.source_path == "legacy/source"
        assert project.source_version == "source-1"
        assert project.source_summary is None
        assert session.get(SchemaVersion, 13) is not None
        assert session.get(SchemaVersion, 14) is not None

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
        "finding_status",
        "revalidation_result",
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
            role=UserRole.SUPER_ADMIN,
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
            role=UserRole.SUPER_ADMIN,
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
