"""Application configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MIN_SESSION_SECRET_BYTES = 32
INSECURE_SESSION_SECRETS = {
    "replace-with-a-long-random-secret",
    "generate-a-unique-secret-with-at-least-32-bytes",
}


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
    account_email_domain: str = "company.com"
    semgrep_jobs: int = 2
    semgrep_max_memory_mb: int = 1_024
    semgrep_max_target_bytes: int = 1_000_000
    max_semgrep_output_bytes: int = 20 * 1024 * 1024
    max_semgrep_error_bytes: int = 64 * 1024
    github_download_timeout_seconds: int = 30
    project_expiry_sweep_seconds: int = 3_600

    def __post_init__(self) -> None:
        secret_size = len(self.session_secret.encode("utf-8"))
        if (
            secret_size < MIN_SESSION_SECRET_BYTES
            or self.session_secret in INSECURE_SESSION_SECRETS
        ):
            raise RuntimeError(
                "SESSION_SECRET must be at least 32 bytes and must not use the example value"
            )
        positive_limits = {
            "MAX_UPLOAD_BYTES": self.max_upload_bytes,
            "MAX_EXTRACTED_BYTES": self.max_extracted_bytes,
            "MAX_ARCHIVE_FILES": self.max_archive_files,
            "MAX_SINGLE_FILE_BYTES": self.max_single_file_bytes,
            "SEMGREP_TIMEOUT_SECONDS": self.semgrep_timeout_seconds,
            "SEMGREP_JOBS": self.semgrep_jobs,
            "SEMGREP_MAX_MEMORY_MB": self.semgrep_max_memory_mb,
            "SEMGREP_MAX_TARGET_BYTES": self.semgrep_max_target_bytes,
            "MAX_SEMGREP_OUTPUT_BYTES": self.max_semgrep_output_bytes,
            "MAX_SEMGREP_ERROR_BYTES": self.max_semgrep_error_bytes,
            "GITHUB_DOWNLOAD_TIMEOUT_SECONDS": self.github_download_timeout_seconds,
            "PROJECT_EXPIRY_SWEEP_SECONDS": self.project_expiry_sweep_seconds,
        }
        for name, value in positive_limits.items():
            if value <= 0:
                raise RuntimeError(f"{name} must be greater than zero")

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
            account_email_domain=os.getenv("ACCOUNT_EMAIL_DOMAIN", "company.com")
            .strip()
            .lower()
            .lstrip("@"),
            semgrep_jobs=_positive_int("SEMGREP_JOBS", 2),
            semgrep_max_memory_mb=_positive_int("SEMGREP_MAX_MEMORY_MB", 1_024),
            semgrep_max_target_bytes=_positive_int(
                "SEMGREP_MAX_TARGET_BYTES", 1_000_000
            ),
            max_semgrep_output_bytes=_positive_int(
                "MAX_SEMGREP_OUTPUT_BYTES", 20 * 1024 * 1024
            ),
            max_semgrep_error_bytes=_positive_int(
                "MAX_SEMGREP_ERROR_BYTES", 64 * 1024
            ),
            github_download_timeout_seconds=_positive_int(
                "GITHUB_DOWNLOAD_TIMEOUT_SECONDS", 30
            ),
            project_expiry_sweep_seconds=_positive_int(
                "PROJECT_EXPIRY_SWEEP_SECONDS", 3_600
            ),
        )
