import asyncio
import io
import re
import stat
import zipfile
from dataclasses import replace
from pathlib import Path

from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.db.models.enums import Language
from app.db.models.project import Project
from app.db.models.user import User
from app.main import create_app
from app.projects.services import create_project


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        app_env="test",
        database_url=f"sqlite:///{tmp_path / 'upload.db'}",
        session_secret="test-session-secret-at-least-32-characters",
        upload_dir=tmp_path / "uploads",
        max_upload_bytes=20 * 1024 * 1024,
        max_extracted_bytes=100 * 1024 * 1024,
        max_archive_files=2_000,
        max_single_file_bytes=10 * 1024 * 1024,
        semgrep_timeout_seconds=60,
        template_dir=Path("app/templates").resolve(),
        static_dir=Path("app/static").resolve(),
    )


def _csrf_token(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


def _zip_bytes(entries: dict[str, str]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return output.getvalue()


def _symlink_zip_bytes() -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        entry = zipfile.ZipInfo("link.py")
        entry.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(entry, "target.py")
    return output.getvalue()


def _encrypted_flag_zip_bytes() -> bytes:
    data = bytearray(_zip_bytes({"secret.py": "print('hidden')"}))
    local_header = data.find(b"PK\x03\x04")
    central_header = data.find(b"PK\x01\x02")
    assert local_header >= 0 and central_header >= 0
    local_flags = int.from_bytes(data[local_header + 6 : local_header + 8], "little")
    central_flags = int.from_bytes(
        data[central_header + 8 : central_header + 10], "little"
    )
    data[local_header + 6 : local_header + 8] = (local_flags | 1).to_bytes(2, "little")
    data[central_header + 8 : central_header + 10] = (central_flags | 1).to_bytes(
        2, "little"
    )
    return bytes(data)


async def _login_as_admin(client: AsyncClient) -> None:
    page = await client.get("/login")
    response = await client.post(
        "/login",
        data={
            "username": "admin@company.com",
            "password": "admin",
            "csrf_token": _csrf_token(page.text),
        },
    )
    assert response.status_code == 303


def _create_project(application, name: str = "Upload target") -> int:
    with Session(application.state.db_engine) as session:
        admin = session.scalar(select(User).where(User.username == "admin@company.com"))
        assert admin is not None
        admin_id = admin.id
    with Session(application.state.db_engine) as session:
        project = create_project(
            session,
            name=name,
            description=None,
            language=Language.PYTHON,
            created_by=admin_id,
        )
        return project.id


def test_safe_zip_upload_persists_isolated_source_workspace(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    application = create_app(settings)

    async def exercise() -> int:
        async with application.router.lifespan_context(application):
            project_id = _create_project(application)
            transport = ASGITransport(app=application)
            async with AsyncClient(
                transport=transport, base_url="http://testserver", follow_redirects=False
            ) as client:
                await _login_as_admin(client)
                detail = await client.get(f"/projects/{project_id}")
                response = await client.post(
                    f"/projects/{project_id}/analysis",
                    data={"csrf_token": _csrf_token(detail.text)},
                    files={
                        "source_file": (
                            "sample.zip",
                            _zip_bytes({"src/app.py": "print('safe')"}),
                            "application/zip",
                        )
                    },
                )
                assert response.status_code == 303
                return project_id

    project_id = asyncio.run(exercise())

    with Session(application.state.db_engine) as session:
        project = session.get(Project, project_id)
        assert project is not None
        extracted_path = Path(project.source_path)
    assert extracted_path.is_dir()
    assert extracted_path.parent.parent.parent == settings.upload_dir / "projects" / str(project_id)
    assert (extracted_path / "src" / "app.py").read_text() == "print('safe')"
    assert (extracted_path.parent / "source.zip").is_file()


def test_zip_slip_and_symlink_uploads_are_rejected_without_persistence(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    application = create_app(settings)

    async def exercise() -> int:
        async with application.router.lifespan_context(application):
            project_id = _create_project(application)
            transport = ASGITransport(app=application)
            async with AsyncClient(
                transport=transport, base_url="http://testserver", follow_redirects=False
            ) as client:
                await _login_as_admin(client)
                detail = await client.get(f"/projects/{project_id}")
                token = _csrf_token(detail.text)
                for archive in (
                    _zip_bytes({"../escape.py": "raise RuntimeError"}),
                    _symlink_zip_bytes(),
                    _encrypted_flag_zip_bytes(),
                ):
                    response = await client.post(
                        f"/projects/{project_id}/analysis",
                        data={"csrf_token": token},
                        files={"source_file": ("unsafe.zip", archive, "application/zip")},
                    )
                    assert response.status_code == 400
                return project_id

    project_id = asyncio.run(exercise())

    with Session(application.state.db_engine) as session:
        project = session.get(Project, project_id)
        assert project is not None
        assert project.source_path == ""
    assert not list(settings.upload_dir.rglob("escape.py"))
    assert not list(settings.upload_dir.rglob("link.py"))


def test_zip_limits_are_checked_before_source_path_is_updated(tmp_path: Path) -> None:
    settings = replace(_settings(tmp_path), max_archive_files=1, max_extracted_bytes=4)
    application = create_app(settings)

    async def exercise() -> int:
        async with application.router.lifespan_context(application):
            project_id = _create_project(application)
            transport = ASGITransport(app=application)
            async with AsyncClient(
                transport=transport, base_url="http://testserver", follow_redirects=False
            ) as client:
                await _login_as_admin(client)
                detail = await client.get(f"/projects/{project_id}")
                token = _csrf_token(detail.text)
                too_many_files = await client.post(
                    f"/projects/{project_id}/analysis",
                    data={"csrf_token": token},
                    files={
                        "source_file": (
                            "many.zip",
                            _zip_bytes({"a.py": "a", "b.py": "b"}),
                            "application/zip",
                        )
                    },
                )
                assert too_many_files.status_code == 400
                too_large_after_extract = await client.post(
                    f"/projects/{project_id}/analysis",
                    data={"csrf_token": token},
                    files={
                        "source_file": (
                            "large.zip",
                            _zip_bytes({"a.py": "12345"}),
                            "application/zip",
                        )
                    },
                )
                assert too_large_after_extract.status_code == 400
                return project_id

    project_id = asyncio.run(exercise())

    with Session(application.state.db_engine) as session:
        project = session.get(Project, project_id)
        assert project is not None
        assert project.source_path == ""
