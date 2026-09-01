"""Central registry and source-language detection for supported analyzers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.db.models.enums import Language


class LanguageDetectionError(ValueError):
    """Raised when source files do not match the selected project language."""


@dataclass(frozen=True, slots=True)
class LanguageProfile:
    language: Language
    label: str
    extensions: tuple[str, ...]
    semgrep_language: str


LANGUAGE_PROFILES: tuple[LanguageProfile, ...] = (
    LanguageProfile(Language.JAVA, "Java", (".java",), "java"),
    LanguageProfile(
        Language.JAVASCRIPT,
        "JavaScript",
        (".js", ".jsx", ".mjs", ".cjs"),
        "javascript",
    ),
    LanguageProfile(Language.PYTHON, "Python", (".py",), "python"),
)

_PROFILE_BY_LANGUAGE = {
    profile.language: profile for profile in LANGUAGE_PROFILES
}
_LANGUAGE_BY_EXTENSION = {
    extension: profile.language
    for profile in LANGUAGE_PROFILES
    for extension in profile.extensions
}


def language_profile(language: Language) -> LanguageProfile:
    try:
        return _PROFILE_BY_LANGUAGE[language]
    except KeyError as exc:  # pragma: no cover - guarded by the persisted Enum.
        raise LanguageDetectionError("지원하지 않는 분석 언어입니다.") from exc


def detect_source_languages(source_root: Path) -> set[Language]:
    """Detect registered languages from regular source-file extensions."""
    detected: set[Language] = set()
    for source_file in source_root.rglob("*"):
        if source_file.is_symlink():
            raise LanguageDetectionError("소스에 허용되지 않는 링크가 있습니다.")
        if not source_file.is_file():
            continue
        language = _LANGUAGE_BY_EXTENSION.get(source_file.suffix.lower())
        if language is not None:
            detected.add(language)
    return detected


def require_selected_language(
    source_root: Path, selected_language: Language
) -> set[Language]:
    detected = detect_source_languages(source_root)
    if selected_language not in detected:
        profile = language_profile(selected_language)
        extensions = ", ".join(profile.extensions)
        raise LanguageDetectionError(
            f"선택한 {profile.label} 소스 파일({extensions})을 ZIP에서 찾을 수 없습니다."
        )
    return detected


def resolve_analysis_languages(
    source_root: Path, selected_language: Language, *, scan_all_languages: bool
) -> tuple[set[Language], set[Language]]:
    """Return detected and effective scan languages for one project run."""
    detected = detect_source_languages(source_root)
    if scan_all_languages:
        if not detected:
            raise LanguageDetectionError(
                "ZIP에서 지원하는 Java, JavaScript 또는 Python 소스 파일을 찾을 수 없습니다."
            )
        return detected, detected

    if selected_language not in detected:
        profile = language_profile(selected_language)
        extensions = ", ".join(profile.extensions)
        raise LanguageDetectionError(
            f"선택한 {profile.label} 소스 파일({extensions})을 ZIP에서 찾을 수 없습니다."
        )
    return detected, {selected_language}
