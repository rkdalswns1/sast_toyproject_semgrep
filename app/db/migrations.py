"""Small ordered schema migrations retained for the SQLite MVP."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass

from sqlalchemy import Connection, Engine, inspect, select, text, update

from app.db.models.finding import Finding
from app.db.models.schema_version import SchemaVersion


MigrationOperation = Callable[[Connection], None]


@dataclass(frozen=True, slots=True)
class SchemaMigration:
    version: int
    description: str
    apply: MigrationOperation
    requires_foreign_keys_off: bool = False


def _record_initial_schema(_: Connection) -> None:
    """Mark the create_all baseline without altering an existing database."""


def _add_rule_catalog_metadata(connection: Connection) -> None:
    columns = {
        column["name"] for column in inspect(connection).get_columns("rules")
    }
    if "item_number" not in columns:
        connection.execute(
            text(
                "ALTER TABLE rules "
                "ADD COLUMN item_number INTEGER NOT NULL DEFAULT 1"
            )
        )
    if "reference_info" not in columns:
        connection.execute(
            text("ALTER TABLE rules ADD COLUMN reference_info TEXT")
        )
    if "is_active" not in columns:
        connection.execute(
            text(
                "ALTER TABLE rules "
                "ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT 1"
            )
        )


def _add_diagnostic_rules(connection: Connection) -> None:
    connection.execute(
        text(
            "CREATE TABLE IF NOT EXISTS diagnostic_rules ("
            "id INTEGER NOT NULL PRIMARY KEY, "
            "catalog_rule_id INTEGER NOT NULL, "
            "language VARCHAR(20) NOT NULL, "
            "semgrep_rule_id VARCHAR(255) NOT NULL, "
            "is_active BOOLEAN NOT NULL DEFAULT 1, "
            "created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, "
            "updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, "
            "CONSTRAINT uq_diagnostic_rule_language UNIQUE (catalog_rule_id, language), "
            "UNIQUE (semgrep_rule_id), "
            "FOREIGN KEY(catalog_rule_id) REFERENCES rules (id) ON DELETE CASCADE"
            ")"
        )
    )


def _sync_expanded_builtin_rule_metadata(connection: Connection) -> None:
    """Upgrade catalog rows for the second built-in diagnostic-rule batch.

    Preserve administrator-controlled activation state. Only rows that still
    have the old NOT_IMPLEMENTED/empty-language values are migrated.
    """
    implemented_rules = {
        "제1절-3": "kisa-2021-path-traversal-python",
        "제1절-4": "kisa-2021-xss-python",
        "제1절-6": "kisa-2021-unrestricted-upload-python",
        "제1절-8": "kisa-2021-xxe-python",
    }
    supported_languages = json.dumps(["JAVA", "JAVASCRIPT", "PYTHON"])
    for standard_id, semgrep_rule_id in implemented_rules.items():
        connection.execute(
            text(
                "UPDATE rules "
                "SET supported_languages = :supported_languages, "
                "implementation_status = 'PARTIAL', "
                "semgrep_rule_id = :semgrep_rule_id "
                "WHERE standard_id = :standard_id "
                "AND implementation_status = 'NOT_IMPLEMENTED' "
                "AND supported_languages = '[]'"
            ),
            {
                "standard_id": standard_id,
                "supported_languages": supported_languages,
                "semgrep_rule_id": semgrep_rule_id,
            },
        )


def _normalize_existing_finding_raw_paths(connection: Connection) -> None:
    """Replace transient workspace paths in existing raw Finding JSON."""
    findings = connection.execute(
        select(Finding.id, Finding.file_path, Finding.raw_result)
    ).all()
    for finding_id, file_path, raw_result in findings:
        if not isinstance(raw_result, dict) or raw_result.get("path") == file_path:
            continue
        normalized_raw_result = dict(raw_result)
        normalized_raw_result["path"] = file_path
        connection.execute(
            update(Finding)
            .where(Finding.id == finding_id)
            .values(raw_result=normalized_raw_result)
        )


def _upgrade_user_roles_and_password_policy(connection: Connection) -> None:
    """Rebuild legacy SQLite users while preserving identifiers and relations."""
    columns = {
        column["name"] for column in inspect(connection).get_columns("users")
    }
    if "must_change_password" in columns:
        return

    connection.execute(text("DROP TABLE IF EXISTS users_phase10"))
    connection.execute(
        text(
            "CREATE TABLE users_phase10 ("
            "id INTEGER NOT NULL PRIMARY KEY, "
            "username VARCHAR(100) NOT NULL UNIQUE, "
            "password_hash VARCHAR(255) NOT NULL, "
            "role VARCHAR(15) NOT NULL, "
            "is_active BOOLEAN NOT NULL DEFAULT 1, "
            "must_change_password BOOLEAN NOT NULL DEFAULT 0, "
            "created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, "
            "updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, "
            "CONSTRAINT user_role CHECK ("
            "role IN ('SUPER_ADMIN', 'PROJECT_MANAGER', 'USER')"
            ")"
            ")"
        )
    )
    connection.execute(
        text(
            "INSERT INTO users_phase10 ("
            "id, username, password_hash, role, is_active, "
            "must_change_password, created_at, updated_at"
            ") SELECT id, username, password_hash, "
            "CASE role WHEN 'ADMIN' THEN 'SUPER_ADMIN' ELSE 'USER' END, "
            "is_active, 0, created_at, updated_at FROM users"
        )
    )
    connection.execute(text("DROP TABLE users"))
    connection.execute(text("ALTER TABLE users_phase10 RENAME TO users"))
    violations = connection.execute(text("PRAGMA foreign_key_check")).all()
    if violations:
        raise RuntimeError("User role migration would violate foreign keys")


def _sync_phase11_builtin_rule_metadata(connection: Connection) -> None:
    """Enable the approved Phase 11 catalog rows on existing databases."""
    implemented_rules = {
        "제2절-11": (
            ["JAVA", "JAVASCRIPT", "PYTHON"],
            "kisa-2021-improper-certificate-validation-python",
        ),
        "제5절-5": (
            ["JAVA", "PYTHON"],
            "kisa-2021-unsafe-deserialization-python",
        ),
    }
    for standard_id, (languages, semgrep_rule_id) in implemented_rules.items():
        connection.execute(
            text(
                "UPDATE rules "
                "SET supported_languages = :supported_languages, "
                "implementation_status = 'PARTIAL', "
                "semgrep_rule_id = :semgrep_rule_id, "
                "severity = 'HIGH' "
                "WHERE standard_id = :standard_id "
                "AND implementation_status = 'NOT_IMPLEMENTED' "
                "AND supported_languages = '[]'"
            ),
            {
                "standard_id": standard_id,
                "supported_languages": json.dumps(languages),
                "semgrep_rule_id": semgrep_rule_id,
            },
        )


SCHEMA_MIGRATIONS: tuple[SchemaMigration, ...] = (
    SchemaMigration(1, "Initial SAST domain schema baseline", _record_initial_schema),
    SchemaMigration(
        2,
        "Add item number, reference information, and active state to rules",
        _add_rule_catalog_metadata,
    ),
    SchemaMigration(
        3,
        "Add language-specific Semgrep diagnostic rule mappings",
        _add_diagnostic_rules,
    ),
    SchemaMigration(
        4,
        "Synchronize metadata for the expanded built-in diagnostic rules",
        _sync_expanded_builtin_rule_metadata,
    ),
    SchemaMigration(
        5,
        "Normalize stored Semgrep result paths to source-relative paths",
        _normalize_existing_finding_raw_paths,
    ),
    SchemaMigration(
        6,
        "Add three roles and initial-password change state to users",
        _upgrade_user_roles_and_password_policy,
        requires_foreign_keys_off=True,
    ),
    SchemaMigration(
        7,
        "Enable approved certificate validation and deserialization rules",
        _sync_phase11_builtin_rule_metadata,
    ),
)


def apply_schema_migrations(engine: Engine) -> None:
    """Apply each missing migration once and record only successful versions."""
    for migration in SCHEMA_MIGRATIONS:
        with engine.connect() as connection:
            if migration.requires_foreign_keys_off and engine.dialect.name == "sqlite":
                connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
                connection.commit()
            try:
                with connection.begin():
                    already_applied = connection.scalar(
                        select(SchemaVersion.version).where(
                            SchemaVersion.version == migration.version
                        )
                    )
                    if already_applied is not None:
                        continue
                    migration.apply(connection)
                    connection.execute(
                        SchemaVersion.__table__.insert().values(
                            version=migration.version,
                            description=migration.description,
                        )
                    )
            finally:
                if migration.requires_foreign_keys_off and engine.dialect.name == "sqlite":
                    connection.exec_driver_sql("PRAGMA foreign_keys=ON")
                    connection.commit()
