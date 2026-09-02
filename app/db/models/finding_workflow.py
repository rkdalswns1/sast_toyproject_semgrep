"""Latest remediation workflow state for one normalized Finding."""

from __future__ import annotations

from datetime import date, datetime
from typing import TYPE_CHECKING

from sqlalchemy import Date, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.enums import FindingStatus
from app.db.models.types import persisted_enum

if TYPE_CHECKING:
    from app.db.models.finding import Finding
    from app.db.models.user import User


class FindingWorkflow(Base):
    __tablename__ = "finding_workflows"

    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True
    )
    status: Mapped[FindingStatus] = mapped_column(
        persisted_enum(FindingStatus, "finding_status"),
        nullable=False,
        default=FindingStatus.OPEN,
        server_default=FindingStatus.OPEN.value,
    )
    note: Mapped[str | None] = mapped_column(Text)
    assignee_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    due_date: Mapped[date | None] = mapped_column(Date)
    updated_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    finding: Mapped[Finding] = relationship(back_populates="workflow")
    updater: Mapped[User | None] = relationship(
        back_populates="finding_workflow_updates", foreign_keys=[updated_by]
    )
    assignee: Mapped[User | None] = relationship(
        back_populates="assigned_finding_workflows", foreign_keys=[assignee_id]
    )
