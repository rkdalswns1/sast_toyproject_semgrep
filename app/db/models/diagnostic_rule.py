"""Language-specific Semgrep mappings for an official KISA catalog entry."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, String, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.enums import Language
from app.db.models.mixins import TimestampMixin
from app.db.models.types import persisted_enum

if TYPE_CHECKING:
    from app.db.models.rule import Rule


class DiagnosticRule(TimestampMixin, Base):
    __tablename__ = "diagnostic_rules"
    __table_args__ = (
        UniqueConstraint("catalog_rule_id", "language", name="uq_diagnostic_rule_language"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    catalog_rule_id: Mapped[int] = mapped_column(
        ForeignKey("rules.id", ondelete="CASCADE"), nullable=False, index=True
    )
    language: Mapped[Language] = mapped_column(
        persisted_enum(Language, "diagnostic_rule_language"), nullable=False
    )
    semgrep_rule_id: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("1")
    )

    catalog_rule: Mapped[Rule] = relationship(back_populates="diagnostic_rules")
