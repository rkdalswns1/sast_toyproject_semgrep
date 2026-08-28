"""Company account-identifier validation and normalization."""

from __future__ import annotations

import re


class AccountIdentifierError(ValueError):
    """Raised when an account identifier violates the company policy."""


_LOCAL_PART_PATTERN = re.compile(r"^[A-Za-z0-9._%+-]+$")


def normalize_company_email(value: str, domain: str) -> str:
    """Return a lowercase company email or reject the identifier."""
    normalized = value.strip().lower()
    normalized_domain = domain.strip().lower().lstrip("@")
    if not normalized_domain or "." not in normalized_domain:
        raise AccountIdentifierError("회사 이메일 도메인 설정이 올바르지 않습니다.")

    local_part, separator, supplied_domain = normalized.rpartition("@")
    if (
        separator != "@"
        or supplied_domain != normalized_domain
        or not local_part
        or not _LOCAL_PART_PATTERN.fullmatch(local_part)
        or len(normalized) > 100
    ):
        raise AccountIdentifierError(
            f"계정은 @{normalized_domain} 회사 이메일 형식이어야 합니다."
        )
    return normalized
