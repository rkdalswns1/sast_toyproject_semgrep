"""Application configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _positive_int(name: str, default: int) -> int:
    raw_value = os.getenv(name, str(default))
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if value <= 0:
        raise RuntimeError(f"{name} must be greater than zero")
    return value


def _project_path(raw_path: str) -> Path:
    path = Path(raw_path)
    return path if path.is_absolute() else PROJECT_ROOT / path


@dataclass(frozen=True, slots=True)
class Settings:
    app_env: str
    database_url: str
    session_secret: str
    upload_dir: Path
    max_upload_bytes: int
    max_extracted_bytes: int
    max_archive_files: int
    max_single_file_bytes: int
    semgrep_timeout_seconds: int
    template_dir: Path
    static_dir: Path

    @classmethod
    def from_env(cls, env_file: Path | None = None) -> "Settings":
        load_dotenv(env_file or PROJECT_ROOT / ".env", override=False)

        session_secret = os.getenv("SESSION_SECRET")
        if not session_secret:
            raise RuntimeError("SESSION_SECRET environment variable is required")

        return cls(
            app_env=os.getenv("APP_ENV", "development"),
            database_url=os.getenv("DATABASE_URL", "sqlite:///./sast.db"),
            session_secret=session_secret,
            upload_dir=_project_path(os.getenv("UPLOAD_DIR", "./uploads")),
            max_upload_bytes=_positive_int("MAX_UPLOAD_BYTES", 20 * 1024 * 1024),
            max_extracted_bytes=_positive_int(
                "MAX_EXTRACTED_BYTES", 100 * 1024 * 1024
            ),
            max_archive_files=_positive_int("MAX_ARCHIVE_FILES", 2_000),
            max_single_file_bytes=_positive_int(
                "MAX_SINGLE_FILE_BYTES", 10 * 1024 * 1024
            ),
            semgrep_timeout_seconds=_positive_int("SEMGREP_TIMEOUT_SECONDS", 60),
            template_dir=PROJECT_ROOT / "app" / "templates",
            static_dir=PROJECT_ROOT / "app" / "static",
        )

