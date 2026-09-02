"""Phase 20 public GitHub intake, security limits, and route authorization tests."""

import asyncio
import io
import re
import zipfile
from pathlib import Path

import httpx
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import inspect, select, text
from sqlalchemy.orm import Session

from app.auth.security import hash_password
from app.config import Settings
from app.db.database import create_db_engine, initialize_database
from app.db.models.analysis_run import AnalysisRun
from app.db.models.enums import AnalysisStatus, Language, SourceOrigin, UserRole
from app.db.models.project import Project, ProjectUser
from app.db.models.schema_version import SchemaVersion
from app.db.models.user import User
from app.main import create_app
from app.projects.github import (
    GitHubProjectSource,
    GitHubSourceError,
    collect_github_project_source,
    normalize_github_ref,
    parse_github_repository_url,
)
from app.projects.services import create_project
from app.projects.upload import StoredProjectSource


SHA = "0123456789abcdef0123456789abcdef01234567"


def _settings(tmp_path: Path, *, max_upload_bytes: int = 20 * 1024 * 1024) -> Settings:
    return Settings(
        app_env="test",
        database_url=f"sqlite:///{tmp_path / 'github.db'}",
        session_secret="test-session-secret-at-least-32-characters",
        upload_dir=tmp_path / "uploads",
        max_upload_bytes=max_upload_bytes,
        max_extracted_bytes=100 * 1024 * 1024,
        max_archive_files=2_000,
        max_single_file_bytes=10 * 1024 * 1024,
        semgrep_timeout_seconds=60,
        template_dir=Path("app/templates").resolve(),
        static_dir=Path("app/static").resolve(),
    )


def _zip_bytes() -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("sample-main/src/app.py", "print('github')")
    return output.getvalue()


def _csrf_token(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


async def _login(client: AsyncClient, username: str, password: str) -> None:
    page = await client.get("/login")
    response = await client.post(
        "/login",
        data={
            "username": username,
            "password": password,
            "csrf_token": _csrf_token(page.text),
        },
    )
    assert response.status_code == 303


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/owner/repo",
        "https://gitlab.com/owner/repo",
        "https://user@github.com/owner/repo",
        "https://github.com:443/owner/repo",
        "https://github.com/owner/repo/issues",
        "https://github.com/owner/repo?token=secret",
        "https://github.com/owner/repo#main",
        "https://github.com/owner/repo/",
    ],
)
def test_github_url_allowlist_rejects_noncanonical_urls(url: str) -> None:
    with pytest.raises(GitHubSourceError):
        parse_github_repository_url(url)


@pytest.mark.parametrize("ref", ["../main", "feature//x", "main.lock", "bad ref", "@{x}"])
def test_github_ref_rejects_unsafe_forms(ref: str) -> None:
    with pytest.raises(GitHubSourceError):
        normalize_github_ref(ref)


def test_collects_default_branch_commit_and_reuses_safe_zip_pipeline(tmp_path: Path) -> None:
    archive = _zip_bytes()

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/repos/acme/sample":
            return httpx.Response(200, json={"default_branch": "main"})
        if path == "/repos/acme/sample/commits/main":
            return httpx.Response(200, json={"sha": SHA})
        if path == f"/repos/acme/sample/zipball/{SHA}":
            return httpx.Response(
                302,
                headers={"location": f"https://codeload.github.com/acme/sample/zip/{SHA}"},
            )
        if request.url.host == "codeload.github.com":
            return httpx.Response(200, content=archive)
        return httpx.Response(500)

    async def exercise() -> GitHubProjectSource:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler), follow_redirects=False
        ) as client:
            return await collect_github_project_source(
                "https://github.com/acme/sample.git",
                "",
                project_id=7,
                settings=_settings(tmp_path),
                client=client,
            )

    result = asyncio.run(exercise())
    assert result.repository_url == "https://github.com/acme/sample"
    assert result.requested_ref is None
    assert result.commit_sha == SHA
    assert (result.stored_source.path / "sample-main/src/app.py").read_text() == "print('github')"
    assert result.stored_source.summary["detected_languages"] == ["PYTHON"]


def test_github_archive_redirect_and_size_limits_are_enforced(tmp_path: Path) -> None:
    def unsafe_redirect(request: httpx.Request) -> httpx.Response:
        if "/commits/" in request.url.path:
            return httpx.Response(200, json={"sha": SHA})
        return httpx.Response(302, headers={"location": "https://evil.example/source.zip"})

    async def exercise(handler, max_bytes: int) -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await collect_github_project_source(
                "https://github.com/acme/sample",
                "main",
                project_id=1,
                settings=_settings(tmp_path, max_upload_bytes=max_bytes),
                client=client,
            )

    with pytest.raises(GitHubSourceError, match="허용되지 않은"):
        asyncio.run(exercise(unsafe_redirect, 1024))

    def oversized(request: httpx.Request) -> httpx.Response:
        if "/commits/" in request.url.path:
            return httpx.Response(200, json={"sha": SHA})
        return httpx.Response(200, content=b"x" * 129)

    with pytest.raises(GitHubSourceError, match="크기 제한"):
        asyncio.run(exercise(oversized, 128))

    def timed_out(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timeout", request=request)

    with pytest.raises(GitHubSourceError, match="연결 시간이 초과"):
        asyncio.run(exercise(timed_out, 128))


def test_phase20_migration_upgrades_existing_project_table(tmp_path: Path) -> None:
    engine = create_db_engine(f"sqlite:///{tmp_path / 'migration.db'}")
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE projects ("
                "id INTEGER PRIMARY KEY, name VARCHAR(200) NOT NULL, "
                "description TEXT, source_type VARCHAR(3) NOT NULL, "
                "language VARCHAR(20) NOT NULL, "
                "scan_all_languages BOOLEAN NOT NULL DEFAULT 0, "
                "source_path VARCHAR(500) NOT NULL, source_version VARCHAR(100), "
                "deployment_version VARCHAR(100), source_description TEXT, "
                "source_summary JSON, created_by INTEGER NOT NULL, "
                "created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, "
                "updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, "
                "FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE RESTRICT)"
            )
        )

    initialize_database(engine)
    columns = {column["name"] for column in inspect(engine).get_columns("projects")}
    assert {"source_origin", "repository_url", "repository_ref", "repository_commit"} <= columns
    with Session(engine) as session:
        assert session.get(SchemaVersion, 15) is not None
    engine.dispose()


def test_github_route_persists_identity_and_blocks_user(tmp_path: Path, monkeypatch) -> None:
    settings = _settings(tmp_path)
    application = create_app(settings)

    async def fake_collect(*args, project_id: int, **kwargs) -> GitHubProjectSource:
        source_path = settings.upload_dir / "projects" / str(project_id) / "sources" / "mock" / "extracted"
        source_path.mkdir(parents=True, exist_ok=True)
        (source_path / "app.py").write_text("print('safe')")
        return GitHubProjectSource(
            stored_source=StoredProjectSource(
                path=source_path,
                summary={
                    "archive_name": "sample.zip",
                    "uploaded_at": "2026-09-02T00:00:00+00:00",
                    "file_count": 1,
                    "total_bytes": 13,
                    "detected_languages": ["PYTHON"],
                    "sample_paths": ["app.py"],
                },
            ),
            repository_url="https://github.com/acme/sample",
            requested_ref="release-1",
            commit_sha=SHA,
        )

    monkeypatch.setattr(
        "app.analysis.routes.collect_github_project_source", fake_collect
    )

    async def exercise() -> tuple[int, int]:
        async with application.router.lifespan_context(application):
            with Session(application.state.db_engine) as session:
                admin = session.scalar(select(User).where(User.username == "admin@company.com"))
                assert admin is not None
                admin_id = admin.id
                session.rollback()
                project = create_project(
                    session,
                    name="GitHub target",
                    description=None,
                    language=Language.PYTHON,
                    created_by=admin_id,
                )
                project_id = project.id
                session.rollback()
                with session.begin():
                    viewer = User(
                        username="viewer@company.com",
                        password_hash=hash_password("viewer-password"),
                        role=UserRole.USER,
                        must_change_password=False,
                    )
                    session.add(viewer)
                    manager = User(
                        username="manager@company.com",
                        password_hash=hash_password("manager-password"),
                        role=UserRole.PROJECT_MANAGER,
                        must_change_password=False,
                    )
                    outsider = User(
                        username="outsider@company.com",
                        password_hash=hash_password("outsider-password"),
                        role=UserRole.PROJECT_MANAGER,
                        must_change_password=False,
                    )
                    session.add_all([manager, outsider])
                    session.flush()
                    session.add(ProjectUser(project_id=project_id, user_id=viewer.id))
                    session.add(ProjectUser(project_id=project_id, user_id=manager.id))
                    viewer_id = viewer.id

            transport = ASGITransport(app=application)
            async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as admin_client:
                await _login(admin_client, "admin@company.com", "admin")
                page = await admin_client.get(f"/projects/{project_id}")
                response = await admin_client.post(
                    f"/projects/{project_id}/github-source",
                    data={
                        "repository_url": "https://github.com/acme/sample",
                        "repository_ref": "release-1",
                        "source_version": "1.0",
                        "csrf_token": _csrf_token(page.text),
                    },
                )
                assert response.status_code == 303
                detail = await admin_client.get(f"/projects/{project_id}")
                assert "GitHub 소스 정보" in detail.text
                assert SHA in detail.text
                with Session(application.state.db_engine) as session:
                    admin = session.scalar(select(User).where(User.username == "admin@company.com"))
                    assert admin is not None
                    run = AnalysisRun(
                        project_id=project_id,
                        engine="Semgrep",
                        language=Language.PYTHON,
                        status=AnalysisStatus.COMPLETED,
                        executed_by=admin.id,
                        summary={
                            "provenance": {
                                "source_metadata": {
                                    "source_version": "1.0",
                                    "deployment_version": None,
                                    "description": None,
                                    "source_origin": "GITHUB",
                                    "repository_url": "https://github.com/acme/sample",
                                    "repository_ref": "release-1",
                                    "repository_commit": SHA,
                                }
                            }
                        },
                    )
                    session.add(run)
                    session.commit()
                    analysis_id = run.id
                analysis_detail = await admin_client.get(f"/analysis/{analysis_id}")
                assert "GITHUB" in analysis_detail.text
                assert "release-1" in analysis_detail.text
                assert SHA in analysis_detail.text

            async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as manager_client:
                await _login(manager_client, "manager@company.com", "manager-password")
                page = await manager_client.get(f"/projects/{project_id}")
                imported = await manager_client.post(
                    f"/projects/{project_id}/github-source",
                    data={
                        "repository_url": "https://github.com/acme/sample",
                        "repository_ref": "release-1",
                        "source_version": "1.0",
                        "csrf_token": _csrf_token(page.text),
                    },
                )
                assert imported.status_code == 303

            async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as viewer_client:
                await _login(viewer_client, "viewer@company.com", "viewer-password")
                page = await viewer_client.get(f"/projects/{project_id}")
                password_page = await viewer_client.get("/account/password")
                denied = await viewer_client.post(
                    f"/projects/{project_id}/github-source",
                    data={
                        "repository_url": "https://github.com/acme/sample",
                        "csrf_token": _csrf_token(password_page.text),
                    },
                )
                assert denied.status_code == 403
                assert "GitHub 소스 가져오기" not in page.text

            async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as outsider_client:
                await _login(outsider_client, "outsider@company.com", "outsider-password")
                password_page = await outsider_client.get("/account/password")
                hidden = await outsider_client.post(
                    f"/projects/{project_id}/github-source",
                    data={
                        "repository_url": "https://github.com/acme/sample",
                        "csrf_token": _csrf_token(password_page.text),
                    },
                )
                assert hidden.status_code == 404
            return project_id, viewer_id

    project_id, _ = asyncio.run(exercise())
    with Session(application.state.db_engine) as session:
        project = session.get(Project, project_id)
        assert project is not None
        assert project.source_origin is SourceOrigin.GITHUB
        assert project.repository_ref == "release-1"
        assert project.repository_commit == SHA
        assert project.source_version == "1.0"
