"""Project-scoped exact-code suppression created from a false-positive Finding."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, String, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.enums import Language
from app.db.models.mixins import TimestampMixin
from app.db.models.types import persisted_enum

if TYPE_CHECKING:
    from app.db.models.finding import Finding
    from app.db.models.finding_suppression_hit import FindingSuppressionHit
    from app.db.models.project import Project
    from app.db.models.user import User


class FindingSuppression(TimestampMixin, Base):
    __tablename__ = "finding_suppressions"
    __table_args__ = (
        UniqueConstraint(
            "project_id",
            "language",
            "semgrep_rule_id",
            "file_path",
            "evidence_sha256",
            name="uq_finding_suppression_fingerprint",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    language: Mapped[Language] = mapped_column(
        persisted_enum(Language, "suppression_language"), nullable=False
    )
    semgrep_rule_id: Mapped[str] = mapped_column(String(255), nullable=False)
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    evidence_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    source_finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_by: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("1")
    )

    project: Mapped[Project] = relationship(back_populates="suppressions")
    source_finding: Mapped[Finding | None] = relationship()
    creator: Mapped[User] = relationship()
    hits: Mapped[list[FindingSuppressionHit]] = relationship(
        back_populates="suppression", passive_deletes=True
    )
