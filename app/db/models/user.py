"""User model."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import Boolean, String, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.enums import UserRole
from app.db.models.mixins import TimestampMixin
from app.db.models.types import persisted_enum

if TYPE_CHECKING:
    from app.db.models.analysis_run import AnalysisRun
    from app.db.models.project import Project, ProjectUser


class User(TimestampMixin, Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        persisted_enum(UserRole, "user_role"), nullable=False
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("1")
    )
    must_change_password: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("0")
    )

    created_projects: Mapped[list[Project]] = relationship(
        back_populates="creator", foreign_keys="Project.created_by"
    )
    executed_analysis_runs: Mapped[list[AnalysisRun]] = relationship(
        back_populates="executor", foreign_keys="AnalysisRun.executed_by"
    )
    project_memberships: Mapped[list[ProjectUser]] = relationship(
        back_populates="user", passive_deletes=True
    )
    projects: Mapped[list[Project]] = relationship(
        secondary="project_users", back_populates="users", viewonly=True
    )
