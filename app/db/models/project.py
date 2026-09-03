"""Project and project membership models."""

from __future__ import annotations

from datetime import date
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, Boolean, Date, ForeignKey, String, Text, false
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.enums import Language, SourceOrigin, SourceType
from app.db.models.mixins import TimestampMixin
from app.db.models.types import persisted_enum

if TYPE_CHECKING:
    from app.db.models.analysis_run import AnalysisRun
    from app.db.models.finding_suppression import FindingSuppression
    from app.db.models.user import User


class Project(TimestampMixin, Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    expires_on: Mapped[date | None] = mapped_column(Date)
    source_type: Mapped[SourceType] = mapped_column(
        persisted_enum(SourceType, "source_type"), nullable=False
    )
    source_origin: Mapped[SourceOrigin] = mapped_column(
        persisted_enum(SourceOrigin, "source_origin"),
        nullable=False,
        default=SourceOrigin.ZIP,
        server_default=SourceOrigin.ZIP.value,
    )
    repository_url: Mapped[str | None] = mapped_column(String(500))
    repository_ref: Mapped[str | None] = mapped_column(String(255))
    repository_commit: Mapped[str | None] = mapped_column(String(40))
    language: Mapped[Language] = mapped_column(
        persisted_enum(Language, "project_language"), nullable=False
    )
    scan_all_languages: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=false()
    )
    source_path: Mapped[str] = mapped_column(String(500), nullable=False)
    source_version: Mapped[str | None] = mapped_column(String(100))
    deployment_version: Mapped[str | None] = mapped_column(String(100))
    source_description: Mapped[str | None] = mapped_column(Text)
    source_summary: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    created_by: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )

    creator: Mapped[User] = relationship(
        back_populates="created_projects", foreign_keys=[created_by]
    )
    memberships: Mapped[list[ProjectUser]] = relationship(
        back_populates="project",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    users: Mapped[list[User]] = relationship(
        secondary="project_users", back_populates="projects", viewonly=True
    )
    analysis_runs: Mapped[list[AnalysisRun]] = relationship(
        back_populates="project",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    suppressions: Mapped[list[FindingSuppression]] = relationship(
        back_populates="project",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class ProjectUser(Base):
    __tablename__ = "project_users"

    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )

    project: Mapped[Project] = relationship(back_populates="memberships")
    user: Mapped[User] = relationship(back_populates="project_memberships")
