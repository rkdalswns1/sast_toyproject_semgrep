"""Immutable per-analysis record of one automatically suppressed result."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.enums import Language
from app.db.models.types import persisted_enum

if TYPE_CHECKING:
    from app.db.models.analysis_run import AnalysisRun
    from app.db.models.finding import Finding
    from app.db.models.finding_suppression import FindingSuppression
    from app.db.models.user import User


class FindingSuppressionHit(Base):
    __tablename__ = "finding_suppression_hits"

    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_run_id: Mapped[int] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    suppression_id: Mapped[int | None] = mapped_column(
        ForeignKey("finding_suppressions.id", ondelete="SET NULL"), index=True
    )
    source_finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), index=True
    )
    reviewed_by: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    kisa_id: Mapped[str] = mapped_column(String(100), nullable=False)
    rule_name: Mapped[str] = mapped_column(String(200), nullable=False)
    language: Mapped[Language] = mapped_column(
        persisted_enum(Language, "suppression_hit_language"), nullable=False
    )
    semgrep_rule_id: Mapped[str] = mapped_column(String(255), nullable=False)
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    start_line: Mapped[int] = mapped_column(nullable=False)
    start_column: Mapped[int | None] = mapped_column()
    end_line: Mapped[int | None] = mapped_column()
    end_column: Mapped[int | None] = mapped_column()
    message: Mapped[str] = mapped_column(Text, nullable=False)
    review_note: Mapped[str | None] = mapped_column(Text)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    analysis_run: Mapped[AnalysisRun] = relationship(back_populates="suppression_hits")
    suppression: Mapped[FindingSuppression | None] = relationship(
        back_populates="hits"
    )
    source_finding: Mapped[Finding | None] = relationship(
        back_populates="suppression_hits"
    )
    reviewer: Mapped[User] = relationship()
