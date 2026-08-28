"""Small ordered schema migrations retained for the SQLite MVP."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from sqlalchemy import Connection, Engine, inspect, select, text

from app.db.models.schema_version import SchemaVersion


MigrationOperation = Callable[[Connection], None]


@dataclass(frozen=True, slots=True)
class SchemaMigration:
    version: int
    description: str
    apply: MigrationOperation


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
)


def apply_schema_migrations(engine: Engine) -> None:
    """Apply each missing migration once and record only successful versions."""
    for migration in SCHEMA_MIGRATIONS:
        with engine.begin() as connection:
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
