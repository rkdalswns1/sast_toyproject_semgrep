import asyncio
import os
import stat
from pathlib import Path

from httpx import ASGITransport, AsyncClient
import pytest

from app.config import Settings
from app.main import create_app


def test_settings_requires_session_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SESSION_SECRET", raising=False)

    with pytest.raises(RuntimeError, match="SESSION_SECRET environment variable is required"):
        Settings.from_env(tmp_path / "missing.env")


def test_health_and_database_initialization(tmp_path: Path) -> None:
    database_path = tmp_path / "phase1.db"
    upload_path = tmp_path / "uploads"
    settings = Settings(
        app_env="test",
        database_url=f"sqlite:///{database_path}",
        session_secret="test-session-secret-at-least-32-characters",
        upload_dir=upload_path,
        max_upload_bytes=20 * 1024 * 1024,
        max_extracted_bytes=100 * 1024 * 1024,
        max_archive_files=2_000,
        max_single_file_bytes=10 * 1024 * 1024,
        semgrep_timeout_seconds=60,
        template_dir=Path("app/templates").resolve(),
        static_dir=Path("app/static").resolve(),
    )

    application = create_app(settings)

    async def exercise_app():
        async with application.router.lifespan_context(application):
            transport = ASGITransport(app=application)
            async with AsyncClient(
                transport=transport, base_url="http://testserver"
            ) as client:
                return await client.get("/health")

    response = asyncio.run(exercise_app())

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert database_path.is_file()
    assert upload_path.is_dir()
    if os.name == "posix":
        assert stat.S_IMODE(upload_path.stat().st_mode) == 0o700
