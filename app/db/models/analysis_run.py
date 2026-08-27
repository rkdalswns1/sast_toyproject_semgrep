"""Analysis execution model."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.enums import AnalysisStatus, Language
from app.db.models.types import persisted_enum

if TYPE_CHECKING:
    from app.db.models.finding import Finding
    from app.db.models.project import Project
    from app.db.models.user import User


class AnalysisRun(Base):
    __tablename__ = "analysis_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    engine: Mapped[str] = mapped_column(String(50), nullable=False)
    language: Mapped[Language] = mapped_column(
        persisted_enum(Language, "analysis_language"), nullable=False
    )
    status: Mapped[AnalysisStatus] = mapped_column(
        persisted_enum(AnalysisStatus, "analysis_status"),
        nullable=False,
        default=AnalysisStatus.PENDING,
    )
    executed_by: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[str | None] = mapped_column(Text)
    summary: Mapped[dict[str, Any] | None] = mapped_column(JSON)

    project: Mapped[Project] = relationship(back_populates="analysis_runs")
    executor: Mapped[User] = relationship(
        back_populates="executed_analysis_runs", foreign_keys=[executed_by]
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="analysis_run",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

