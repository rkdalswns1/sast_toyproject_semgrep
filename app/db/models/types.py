"""Reusable SQLAlchemy column types."""

from enum import Enum
from typing import TypeVar

from sqlalchemy import JSON, Enum as SqlEnum
from sqlalchemy.types import TypeDecorator

from app.db.models.enums import Language


EnumType = TypeVar("EnumType", bound=Enum)


def persisted_enum(enum_type: type[EnumType], name: str) -> SqlEnum[EnumType]:
    return SqlEnum(
        enum_type,
        name=name,
        native_enum=False,
        create_constraint=True,
        validate_strings=True,
    )


class LanguageListType(TypeDecorator[list[str]]):
    """Persist only documented Language values in JSON lists."""

    impl = JSON
    cache_ok = True

    def process_bind_param(
        self, value: list[str] | None, dialect: object
    ) -> list[str] | None:
        if value is None:
            return None
        if not isinstance(value, list):
            raise ValueError("supported_languages must be a list")

        normalized: list[str] = []
        for language in value:
            try:
                normalized.append(Language(language).value)
            except ValueError as exc:
                raise ValueError(
                    f"unsupported language in supported_languages: {language!r}"
                ) from exc
        return normalized
