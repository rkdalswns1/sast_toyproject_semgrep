"""Security rule catalog model."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import String, Text
from sqlalchemy.ext.mutable import MutableList
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.enums import ImplementationStatus, Severity
from app.db.models.types import LanguageListType, persisted_enum

if TYPE_CHECKING:
    from app.db.models.finding import Finding


class Rule(Base):
    __tablename__ = "rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    standard_id: Mapped[str] = mapped_column(
        String(100), nullable=False, unique=True
    )
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[Severity] = mapped_column(
        persisted_enum(Severity, "rule_severity"), nullable=False
    )
    supported_languages: Mapped[list[str]] = mapped_column(
        MutableList.as_mutable(LanguageListType()), nullable=False, default=list
    )
    implementation_status: Mapped[ImplementationStatus] = mapped_column(
        persisted_enum(ImplementationStatus, "implementation_status"),
        nullable=False,
        default=ImplementationStatus.NOT_IMPLEMENTED,
    )
    semgrep_rule_id: Mapped[str | None] = mapped_column(String(255))

    findings: Mapped[list[Finding]] = relationship(back_populates="rule")
