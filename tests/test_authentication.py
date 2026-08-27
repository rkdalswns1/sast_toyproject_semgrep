import asyncio
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import Request
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.dependencies import get_db
from app.auth.security import verify_password
from app.config import Settings
from app.db.models.enums import UserRole
from app.db.models.user import User
from app.main import create_app


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        app_env="test",
        database_url=f"sqlite:///{tmp_path / 'auth.db'}",
        session_secret="test-session-secret",
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


async def _login_as_admin(client: AsyncClient) -> str:
    login_page = await client.get("/login")
    token = _csrf_token(login_page.text)
    response = await client.post(
        "/login",
        data={"username": "admin", "password": "admin", "csrf_token": token},
    )
    assert response.status_code == 303
    return token


def test_bootstrap_login_and_csrf_protection(tmp_path: Path) -> None:
    application = create_app(_settings(tmp_path))

    async def exercise() -> None:
        async with application.router.lifespan_context(application):
            transport = ASGITransport(app=application)
            async with AsyncClient(
                transport=transport, base_url="http://testserver", follow_redirects=False
            ) as client:
                login_page = await client.get("/login")
                assert login_page.status_code == 200
                token = _csrf_token(login_page.text)
                assert "sast_session" in client.cookies
                assert "HttpOnly" in login_page.headers["set-cookie"]
                assert "SameSite=lax" in login_page.headers["set-cookie"]

                assert (await client.post("/login", data={"username": "admin", "password": "admin"})).status_code == 403
                assert (
                    await client.post(
                        "/login",
                        data={"username": "admin", "password": "wrong", "csrf_token": token},
                    )
                ).status_code == 400
                assert (
                    await client.post(
                        "/login",
                        data={"username": "admin", "password": "admin", "csrf_token": token},
                    )
                ).headers["location"] == "/users"

                users_page = await client.get("/users")
                assert users_page.status_code == 200
                token = _csrf_token(users_page.text)
                assert (await client.post("/logout", data={})).status_code == 403
                assert (await client.post("/logout", data={"csrf_token": token})).status_code == 303
                assert (await client.get("/users")).headers["location"] == "/login"

    asyncio.run(exercise())

    with Session(application.state.db_engine) as session:
        users = session.scalars(select(User)).all()
        assert len(users) == 1
        assert users[0].username == "admin"
        assert users[0].password_hash != "admin"
        assert verify_password("admin", users[0].password_hash)


def test_admin_user_management_and_role_protection(tmp_path: Path) -> None:
    application = create_app(_settings(tmp_path))

    async def exercise() -> None:
        async with application.router.lifespan_context(application):
            transport = ASGITransport(app=application)
            async with AsyncClient(
                transport=transport, base_url="http://testserver", follow_redirects=False
            ) as admin_client:
                await _login_as_admin(admin_client)
                users_page = await admin_client.get("/users")
                token = _csrf_token(users_page.text)
                created = await admin_client.post(
                    "/users",
                    data={
                        "username": "member",
                        "password": "member-password",
                        "password_confirmation": "member-password",
                        "role": "USER",
                        "is_active": "true",
                        "csrf_token": token,
                    },
                )
                assert created.status_code == 303

                duplicate = await admin_client.post(
                    "/users",
                    data={
                        "username": "member",
                        "password": "member-password",
                        "password_confirmation": "member-password",
                        "role": "USER",
                        "is_active": "true",
                        "csrf_token": token,
                    },
                )
                assert duplicate.status_code == 400

                with Session(application.state.db_engine) as session:
                    admin = session.scalar(select(User).where(User.username == "admin"))
                    member = session.scalar(select(User).where(User.username == "member"))
                    assert admin is not None
                    assert member is not None
                    assert member.password_hash != "member-password"
                    assert verify_password("member-password", member.password_hash)
                    admin_id = admin.id
                    member_id = member.id

                token = _csrf_token((await admin_client.get("/users")).text)
                self_disable = await admin_client.post(
                    f"/users/{admin_id}/toggle-active", data={"csrf_token": token}
                )
                assert self_disable.status_code == 400
                last_admin_role_change = await admin_client.post(
                    f"/users/{admin_id}/edit",
                    data={"role": "USER", "is_active": "true", "csrf_token": token},
                )
                assert last_admin_role_change.status_code == 400

                reset = await admin_client.post(
                    f"/users/{member_id}/reset-password",
                    data={
                        "password": "reset-password",
                        "password_confirmation": "reset-password",
                        "csrf_token": token,
                    },
                )
                assert reset.status_code == 303

            async with AsyncClient(
                transport=transport, base_url="http://testserver", follow_redirects=False
            ) as user_client:
                login_page = await user_client.get("/login")
                user_token = _csrf_token(login_page.text)
                response = await user_client.post(
                    "/login",
                    data={
                        "username": "member",
                        "password": "reset-password",
                        "csrf_token": user_token,
                    },
                )
                assert response.headers["location"] == "/health"
                assert (await user_client.get("/users")).status_code == 403

    asyncio.run(exercise())

    with Session(application.state.db_engine) as session:
        member = session.scalar(select(User).where(User.username == "member"))
        assert member is not None
        assert verify_password("reset-password", member.password_hash)
        assert member.role is UserRole.USER


def test_request_database_dependency_rolls_back_and_closes() -> None:
    class TrackingSession:
        rolled_back = False
        closed = False

        def rollback(self) -> None:
            self.rolled_back = True

        def close(self) -> None:
            self.closed = True

    tracking_session = TrackingSession()
    app = SimpleNamespace(state=SimpleNamespace(session_factory=lambda: tracking_session))
    request = Request({"type": "http", "app": app, "headers": [], "method": "GET", "path": "/"})
    async def exercise() -> None:
        dependency = get_db(request)
        assert await anext(dependency) is tracking_session
        with pytest.raises(RuntimeError, match="database failure"):
            await dependency.athrow(RuntimeError("database failure"))
        assert tracking_session.rolled_back
        assert tracking_session.closed

    asyncio.run(exercise())
