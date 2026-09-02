"""History of rechecking one Finding against a new analysis run."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.enums import RevalidationResult
from app.db.models.types import persisted_enum

if TYPE_CHECKING:
    from app.db.models.analysis_run import AnalysisRun
    from app.db.models.finding import Finding
    from app.db.models.user import User


class FindingRevalidation(Base):
    __tablename__ = "finding_revalidations"
    __table_args__ = (
        UniqueConstraint(
            "source_finding_id",
            "analysis_run_id",
            name="uq_finding_revalidation_run",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    source_finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    analysis_run_id: Mapped[int] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    matched_finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True
    )
    result: Mapped[RevalidationResult] = mapped_column(
        persisted_enum(RevalidationResult, "revalidation_result"), nullable=False
    )
    executed_by: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    source_finding: Mapped[Finding] = relationship(
        back_populates="revalidations", foreign_keys=[source_finding_id]
    )
    matched_finding: Mapped[Finding | None] = relationship(
        back_populates="matched_revalidations", foreign_keys=[matched_finding_id]
    )
    analysis_run: Mapped[AnalysisRun] = relationship(
        back_populates="finding_revalidations"
    )
    executor: Mapped[User] = relationship(
        back_populates="finding_revalidations", foreign_keys=[executed_by]
    )
