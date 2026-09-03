"""Small ordered schema migrations retained for the SQLite MVP."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass

from sqlalchemy import Connection, Engine, inspect, select, text, update

from app.db.models.finding import Finding
from app.db.models.schema_version import SchemaVersion
from app.rules.cwe import APPROVED_CWE_MAPPINGS


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


def _sync_phase23_builtin_rule_metadata(connection: Connection) -> None:
    """Enable the approved Phase 23 catalog rows on existing databases."""
    implemented_rules = {
        "제1절-2": (
            ["JAVA", "JAVASCRIPT", "PYTHON"],
            "kisa-2021-code-injection-python",
            "HIGH",
        ),
        "제2절-7": (
            ["JAVA", "JAVASCRIPT", "PYTHON"],
            "kisa-2021-insufficient-key-length-python",
            "MEDIUM",
        ),
        "제6절-3": (
            ["JAVA"],
            "kisa-2021-private-array-returned-java",
            "INFO",
        ),
        "제6절-4": (
            ["JAVA"],
            "kisa-2021-public-array-assigned-java",
            "INFO",
        ),
        "제7절-2": (
            ["JAVA"],
            "kisa-2021-system-exit-in-servlet-java",
            "MEDIUM",
        ),
    }
    for standard_id, (languages, semgrep_rule_id, severity) in implemented_rules.items():
        connection.execute(
            text(
                "UPDATE rules "
                "SET supported_languages = :supported_languages, "
                "implementation_status = 'PARTIAL', "
                "semgrep_rule_id = :semgrep_rule_id, severity = :severity "
                "WHERE standard_id = :standard_id "
                "AND implementation_status = 'NOT_IMPLEMENTED' "
                "AND supported_languages = '[]'"
            ),
            {
                "standard_id": standard_id,
                "supported_languages": json.dumps(languages),
                "semgrep_rule_id": semgrep_rule_id,
                "severity": severity,
            },
        )


def _add_multi_language_project_mode(connection: Connection) -> None:
    """Add an opt-in scan mode while preserving existing project behavior."""
    columns = {
        column["name"] for column in inspect(connection).get_columns("projects")
    }
    if "scan_all_languages" not in columns:
        connection.execute(
            text(
                "ALTER TABLE projects ADD COLUMN "
                "scan_all_languages BOOLEAN NOT NULL DEFAULT 0"
            )
        )


def _add_finding_workflows(connection: Connection) -> None:
    """Create and backfill the latest Finding remediation state."""
    connection.execute(
        text(
            "CREATE TABLE IF NOT EXISTS finding_workflows ("
            "finding_id INTEGER NOT NULL PRIMARY KEY, "
            "status VARCHAR(20) NOT NULL DEFAULT 'OPEN', "
            "note TEXT, updated_by INTEGER, updated_at DATETIME, "
            "CONSTRAINT finding_status CHECK (status IN ("
            "'OPEN', 'IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE', 'ACCEPTED_RISK'"
            ")), "
            "FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE, "
            "FOREIGN KEY(updated_by) REFERENCES users(id) ON DELETE RESTRICT"
            ")"
        )
    )
    connection.execute(
        text(
            "CREATE INDEX IF NOT EXISTS ix_finding_workflows_updated_by "
            "ON finding_workflows (updated_by)"
        )
    )
    connection.execute(
        text(
            "INSERT OR IGNORE INTO finding_workflows (finding_id, status) "
            "SELECT id, 'OPEN' FROM findings"
        )
    )


def _add_project_source_metadata(connection: Connection) -> None:
    """Add optional metadata for the latest uploaded project source."""
    columns = {
        column["name"] for column in inspect(connection).get_columns("projects")
    }
    if "source_version" not in columns:
        connection.execute(
            text("ALTER TABLE projects ADD COLUMN source_version VARCHAR(100)")
        )
    if "deployment_version" not in columns:
        connection.execute(
            text("ALTER TABLE projects ADD COLUMN deployment_version VARCHAR(100)")
        )
    if "source_description" not in columns:
        connection.execute(
            text("ALTER TABLE projects ADD COLUMN source_description TEXT")
        )


def _add_finding_assignment_and_due_date(connection: Connection) -> None:
    """Add optional project-member ownership and a calendar due date."""
    columns = {
        column["name"]
        for column in inspect(connection).get_columns("finding_workflows")
    }
    if "assignee_id" not in columns:
        connection.execute(
            text(
                "ALTER TABLE finding_workflows ADD COLUMN assignee_id INTEGER "
                "REFERENCES users(id) ON DELETE RESTRICT"
            )
        )
    if "due_date" not in columns:
        connection.execute(
            text("ALTER TABLE finding_workflows ADD COLUMN due_date DATE")
        )
    connection.execute(
        text(
            "CREATE INDEX IF NOT EXISTS ix_finding_workflows_assignee_id "
            "ON finding_workflows (assignee_id)"
        )
    )


def _add_finding_revalidations(connection: Connection) -> None:
    """Create immutable Finding-to-new-analysis comparison history."""
    connection.execute(
        text(
            "CREATE TABLE IF NOT EXISTS finding_revalidations ("
            "id INTEGER NOT NULL PRIMARY KEY, "
            "source_finding_id INTEGER NOT NULL, "
            "analysis_run_id INTEGER NOT NULL, "
            "matched_finding_id INTEGER, "
            "result VARCHAR(20) NOT NULL, "
            "executed_by INTEGER NOT NULL, "
            "created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, "
            "CONSTRAINT uq_finding_revalidation_run UNIQUE "
            "(source_finding_id, analysis_run_id), "
            "CONSTRAINT revalidation_result CHECK (result IN ("
            "'STILL_DETECTED', 'LIKELY_RESOLVED', 'REVIEW_REQUIRED'"
            ")), "
            "FOREIGN KEY(source_finding_id) REFERENCES findings(id) "
            "ON DELETE CASCADE, "
            "FOREIGN KEY(analysis_run_id) REFERENCES analysis_runs(id) "
            "ON DELETE CASCADE, "
            "FOREIGN KEY(matched_finding_id) REFERENCES findings(id) "
            "ON DELETE SET NULL, "
            "FOREIGN KEY(executed_by) REFERENCES users(id) ON DELETE RESTRICT"
            ")"
        )
    )
    for column_name in (
        "source_finding_id",
        "analysis_run_id",
        "matched_finding_id",
        "executed_by",
    ):
        connection.execute(
            text(
                f"CREATE INDEX IF NOT EXISTS "
                f"ix_finding_revalidations_{column_name} "
                f"ON finding_revalidations ({column_name})"
            )
        )


def _add_project_source_summary(connection: Connection) -> None:
    """Add a bounded summary of the latest safely extracted source."""
    columns = {
        column["name"] for column in inspect(connection).get_columns("projects")
    }
    if "source_summary" not in columns:
        connection.execute(text("ALTER TABLE projects ADD COLUMN source_summary JSON"))


def _add_cwe_mapping_and_finding_snapshots(connection: Connection) -> None:
    """Add Rule-ID-level CWE metadata and backfill exact known snapshots."""
    diagnostic_columns = {
        column["name"]
        for column in inspect(connection).get_columns("diagnostic_rules")
    }
    diagnostic_additions = {
        "primary_cwe_id": "VARCHAR(20)",
        "related_cwe_ids": "JSON NOT NULL DEFAULT '[]'",
        "cwe_mapping_confidence": "VARCHAR(6)",
        "remediation_guidance": "TEXT",
    }
    for column_name, column_type in diagnostic_additions.items():
        if column_name not in diagnostic_columns:
            connection.execute(
                text(
                    f"ALTER TABLE diagnostic_rules ADD COLUMN "
                    f"{column_name} {column_type}"
                )
            )

    finding_columns = {
        column["name"] for column in inspect(connection).get_columns("findings")
    }
    finding_additions = {
        "primary_cwe_id": "VARCHAR(20)",
        "related_cwe_ids": "JSON NOT NULL DEFAULT '[]'",
        "cwe_mapping_confidence": "VARCHAR(6)",
    }
    for column_name, column_type in finding_additions.items():
        if column_name not in finding_columns:
            connection.execute(
                text(
                    f"ALTER TABLE findings ADD COLUMN {column_name} {column_type}"
                )
            )

    for rule_id, mapping in APPROVED_CWE_MAPPINGS.items():
        values = {
            "rule_id": rule_id,
            "primary_cwe_id": mapping.primary_cwe_id,
            "related_cwe_ids": json.dumps(list(mapping.related_cwe_ids)),
            "confidence": mapping.confidence.value,
            "guidance": mapping.remediation_guidance,
        }
        connection.execute(
            text(
                "UPDATE diagnostic_rules SET primary_cwe_id = :primary_cwe_id, "
                "related_cwe_ids = :related_cwe_ids, "
                "cwe_mapping_confidence = :confidence, "
                "remediation_guidance = :guidance "
                "WHERE semgrep_rule_id = :rule_id"
            ),
            values,
        )

    existing_findings = connection.execute(
        text("SELECT id, raw_result FROM findings")
    ).all()
    for finding_id, raw_result in existing_findings:
        if isinstance(raw_result, str):
            try:
                raw_result = json.loads(raw_result)
            except json.JSONDecodeError:
                continue
        if not isinstance(raw_result, dict):
            continue
        check_id = raw_result.get("check_id")
        if not isinstance(check_id, str):
            continue
        mapping = APPROVED_CWE_MAPPINGS.get(check_id)
        if mapping is None:
            mapping = APPROVED_CWE_MAPPINGS.get(check_id.rsplit(".", 1)[-1])
        if mapping is None:
            continue
        connection.execute(
            text(
                "UPDATE findings SET primary_cwe_id = :primary_cwe_id, "
                "related_cwe_ids = :related_cwe_ids, "
                "cwe_mapping_confidence = :confidence "
                "WHERE id = :finding_id"
            ),
            {
                "finding_id": finding_id,
                "primary_cwe_id": mapping.primary_cwe_id,
                "related_cwe_ids": json.dumps(list(mapping.related_cwe_ids)),
                "confidence": mapping.confidence.value,
            },
        )


def _add_public_github_source_metadata(connection: Connection) -> None:
    """Add latest source origin and immutable GitHub identity fields."""
    columns = {
        column["name"] for column in inspect(connection).get_columns("projects")
    }
    additions = {
        "source_origin": "VARCHAR(6) NOT NULL DEFAULT 'ZIP'",
        "repository_url": "VARCHAR(500)",
        "repository_ref": "VARCHAR(255)",
        "repository_commit": "VARCHAR(40)",
    }
    for column_name, column_type in additions.items():
        if column_name not in columns:
            connection.execute(
                text(
                    f"ALTER TABLE projects ADD COLUMN "
                    f"{column_name} {column_type}"
                )
            )


def _add_project_expiration_and_finding_suppressions(connection: Connection) -> None:
    """Add project expiry and exact-code false-positive suppression storage."""
    project_columns = {
        column["name"] for column in inspect(connection).get_columns("projects")
    }
    if "expires_on" not in project_columns:
        connection.execute(text("ALTER TABLE projects ADD COLUMN expires_on DATE"))

    connection.execute(
        text(
            "CREATE TABLE IF NOT EXISTS finding_suppressions ("
            "id INTEGER NOT NULL PRIMARY KEY, "
            "project_id INTEGER NOT NULL, language VARCHAR(20) NOT NULL, "
            "semgrep_rule_id VARCHAR(255) NOT NULL, "
            "file_path VARCHAR(500) NOT NULL, evidence_sha256 VARCHAR(64) NOT NULL, "
            "source_finding_id INTEGER, created_by INTEGER NOT NULL, "
            "is_active BOOLEAN NOT NULL DEFAULT 1, "
            "created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, "
            "updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, "
            "CONSTRAINT suppression_language CHECK ("
            "language IN ('JAVA', 'JAVASCRIPT', 'PYTHON')), "
            "CONSTRAINT uq_finding_suppression_fingerprint UNIQUE ("
            "project_id, language, semgrep_rule_id, file_path, evidence_sha256), "
            "FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE, "
            "FOREIGN KEY(source_finding_id) REFERENCES findings(id) ON DELETE SET NULL, "
            "FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE RESTRICT"
            ")"
        )
    )
    for column_name in ("project_id", "source_finding_id", "created_by"):
        connection.execute(
            text(
                f"CREATE INDEX IF NOT EXISTS ix_finding_suppressions_{column_name} "
                f"ON finding_suppressions ({column_name})"
            )
        )


def _add_finding_suppression_hits(connection: Connection) -> None:
    """Add immutable per-analysis records for automatically excluded results."""
    connection.execute(
        text(
            "CREATE TABLE IF NOT EXISTS finding_suppression_hits ("
            "id INTEGER NOT NULL PRIMARY KEY, "
            "analysis_run_id INTEGER NOT NULL, suppression_id INTEGER, "
            "source_finding_id INTEGER, reviewed_by INTEGER NOT NULL, "
            "kisa_id VARCHAR(100) NOT NULL, rule_name VARCHAR(200) NOT NULL, "
            "language VARCHAR(20) NOT NULL, semgrep_rule_id VARCHAR(255) NOT NULL, "
            "file_path VARCHAR(500) NOT NULL, start_line INTEGER NOT NULL, "
            "start_column INTEGER, end_line INTEGER, end_column INTEGER, "
            "message TEXT NOT NULL, review_note TEXT, reviewed_at DATETIME, "
            "created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, "
            "CONSTRAINT suppression_hit_language CHECK ("
            "language IN ('JAVA', 'JAVASCRIPT', 'PYTHON')), "
            "FOREIGN KEY(analysis_run_id) REFERENCES analysis_runs(id) ON DELETE CASCADE, "
            "FOREIGN KEY(suppression_id) REFERENCES finding_suppressions(id) ON DELETE SET NULL, "
            "FOREIGN KEY(source_finding_id) REFERENCES findings(id) ON DELETE SET NULL, "
            "FOREIGN KEY(reviewed_by) REFERENCES users(id) ON DELETE RESTRICT"
            ")"
        )
    )
    for column_name in (
        "analysis_run_id",
        "suppression_id",
        "source_finding_id",
        "reviewed_by",
    ):
        connection.execute(
            text(
                f"CREATE INDEX IF NOT EXISTS ix_finding_suppression_hits_{column_name} "
                f"ON finding_suppression_hits ({column_name})"
            )
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
    SchemaMigration(
        8,
        "Add opt-in multi-language project analysis mode",
        _add_multi_language_project_mode,
    ),
    SchemaMigration(
        9,
        "Add and backfill Finding remediation workflows",
        _add_finding_workflows,
    ),
    SchemaMigration(
        10,
        "Add optional ZIP source metadata to projects",
        _add_project_source_metadata,
    ),
    SchemaMigration(
        11,
        "Add Finding assignee and remediation due date",
        _add_finding_assignment_and_due_date,
    ),
    SchemaMigration(
        12,
        "Add Finding revalidation history",
        _add_finding_revalidations,
    ),
    SchemaMigration(
        13,
        "Add latest safely extracted project source summary",
        _add_project_source_summary,
    ),
    SchemaMigration(
        14,
        "Add CWE mappings and immutable Finding snapshots",
        _add_cwe_mapping_and_finding_snapshots,
    ),
    SchemaMigration(
        15,
        "Add public GitHub source identity to projects",
        _add_public_github_source_metadata,
    ),
    SchemaMigration(
        16,
        "Add project expiration and false-positive suppressions",
        _add_project_expiration_and_finding_suppressions,
    ),
    SchemaMigration(
        17,
        "Add per-analysis false-positive suppression history",
        _add_finding_suppression_hits,
    ),
    SchemaMigration(
        18,
        "Enable the approved second KISA diagnostic-rule expansion",
        _sync_phase23_builtin_rule_metadata,
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
