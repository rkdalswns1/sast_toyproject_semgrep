"""Normalized analysis finding model."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.enums import Confidence, Language, Severity
from app.db.models.types import persisted_enum

if TYPE_CHECKING:
    from app.db.models.analysis_run import AnalysisRun
    from app.db.models.rule import Rule


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_run_id: Mapped[int] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    rule_id: Mapped[int] = mapped_column(
        ForeignKey("rules.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    rule_name: Mapped[str] = mapped_column(String(200), nullable=False)
    kisa_id: Mapped[str] = mapped_column(String(100), nullable=False)
    language: Mapped[Language] = mapped_column(
        persisted_enum(Language, "finding_language"), nullable=False
    )
    severity: Mapped[Severity] = mapped_column(
        persisted_enum(Severity, "finding_severity"), nullable=False
    )
    confidence: Mapped[Confidence] = mapped_column(
        persisted_enum(Confidence, "finding_confidence"), nullable=False
    )
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    start_line: Mapped[int] = mapped_column(nullable=False)
    start_column: Mapped[int | None] = mapped_column()
    end_line: Mapped[int | None] = mapped_column()
    end_column: Mapped[int | None] = mapped_column()
    message: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    recommendation: Mapped[str | None] = mapped_column(Text)
    raw_result: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )

    analysis_run: Mapped[AnalysisRun] = relationship(back_populates="findings")
    rule: Mapped[Rule] = relationship(back_populates="findings")

