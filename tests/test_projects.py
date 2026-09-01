import asyncio
import re
from pathlib import Path

from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.db.models.enums import UserRole
from app.db.models.project import Project, ProjectUser
from app.db.models.user import User
from app.main import create_app


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        app_env="test",
        database_url=f"sqlite:///{tmp_path / 'projects.db'}",
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


async def _login(
    client: AsyncClient,
    username: str,
    password: str,
    *,
    new_password: str | None = None,
) -> None:
    login_page = await client.get("/login")
    response = await client.post(
        "/login",
        data={
            "username": username,
            "password": password,
            "csrf_token": _csrf_token(login_page.text),
        },
    )
    assert response.status_code == 303
    if response.headers["location"] == "/account/password":
        assert new_password is not None
        password_page = await client.get("/account/password")
        changed = await client.post(
            "/account/password",
            data={
                "current_password": password,
                "new_password": new_password,
                "new_password_confirmation": new_password,
                "csrf_token": _csrf_token(password_page.text),
            },
        )
        assert changed.status_code == 303
        assert changed.headers["location"] == "/projects"


def test_project_crud_membership_and_access_control(tmp_path: Path) -> None:
    application = create_app(_settings(tmp_path))

    async def exercise() -> None:
        async with application.router.lifespan_context(application):
            transport = ASGITransport(app=application)
            async with AsyncClient(
                transport=transport, base_url="http://testserver", follow_redirects=False
            ) as admin_client:
                await _login(admin_client, "admin@company.com", "admin")
                project_list = await admin_client.get("/projects")
                assert project_list.status_code == 200
                token = _csrf_token(project_list.text)

                assert (
                    await admin_client.post(
                        "/projects",
                        data={"name": "Unprotected", "language": "PYTHON"},
                    )
                ).status_code == 403
                created = await admin_client.post(
                    "/projects",
                    data={
                        "name": "Gateway",
                        "description": "Security gateway",
                        "language": "PYTHON",
                        "csrf_token": token,
                    },
                )
                assert created.status_code == 303
                assert created.headers["location"].startswith("/projects/")
                project_id = int(created.headers["location"].rsplit("/", 1)[1])

                users_page = await admin_client.get("/users/new")
                token = _csrf_token(users_page.text)
                created_user = await admin_client.post(
                    "/users",
                    data={
                        "username": "member@company.com",
                        "password": "member-password",
                        "password_confirmation": "member-password",
                        "role": "PROJECT_MANAGER",
                        "is_active": "true",
                        "csrf_token": token,
                    },
                )
                assert created_user.status_code == 303

                with Session(application.state.db_engine) as session:
                    member = session.scalar(
                        select(User).where(User.username == "member@company.com")
                    )
                    assert member is not None
                    member_id = member.id

                assignment_page = await admin_client.get(f"/projects/{project_id}/users")
                token = _csrf_token(assignment_page.text)
                assigned = await admin_client.post(
                    f"/projects/{project_id}/users",
                    data={"user_ids": str(member_id), "csrf_token": token},
                )
                assert assigned.status_code == 303

                edit_page = await admin_client.get(f"/projects/{project_id}/edit")
                token = _csrf_token(edit_page.text)
                updated = await admin_client.post(
                    f"/projects/{project_id}/edit",
                    data={
                        "name": "Gateway v2",
                        "description": "Updated description",
                        "language": "JAVA",
                        "csrf_token": token,
                    },
                )
                assert updated.status_code == 303

            async with AsyncClient(
                transport=transport, base_url="http://testserver", follow_redirects=False
            ) as user_client:
                await _login(
                    user_client,
                    "member@company.com",
                    "member-password",
                    new_password="member-personal-password",
                )
                project_list = await user_client.get("/projects")
                assert project_list.status_code == 200
                assert "Gateway v2" in project_list.text
                user_token = _csrf_token(project_list.text)
                assert (
                    await user_client.post(
                        "/projects",
                        data={
                            "name": "Forbidden project",
                            "language": "PYTHON",
                            "csrf_token": user_token,
                        },
                    )
                ).status_code == 403
                assert (
                    await user_client.post(
                        f"/projects/{project_id}/edit",
                        data={
                            "name": "Gateway managed",
                            "description": "Managed by project manager",
                            "language": "JAVA",
                            "csrf_token": user_token,
                        },
                    )
                ).status_code == 303
                assert (await user_client.get(f"/projects/{project_id}")).status_code == 200
                assert (await user_client.get("/projects/new")).status_code == 403
                assert (await user_client.get(f"/projects/{project_id}/users")).status_code == 200
                assert (await user_client.get("/users")).status_code == 403
                assert (await user_client.get("/rules/new")).status_code == 403

    asyncio.run(exercise())

    with Session(application.state.db_engine) as session:
        project = session.scalar(select(Project).where(Project.name == "Gateway managed"))
        assert project is not None
        assert project.description == "Managed by project manager"
        assert project.language.value == "JAVA"
        member = session.scalar(
            select(User).where(User.username == "member@company.com")
        )
        assert member is not None
        assert member.role is UserRole.PROJECT_MANAGER
        assert member.must_change_password is False
        member_ids = set(
            session.scalars(
                select(ProjectUser.user_id).where(ProjectUser.project_id == project.id)
            ).all()
        )
        assert member.id in member_ids
        assert project.created_by in member_ids


def test_unassigned_user_cannot_discover_project(tmp_path: Path) -> None:
    application = create_app(_settings(tmp_path))

    async def exercise() -> None:
        async with application.router.lifespan_context(application):
            transport = ASGITransport(app=application)
            async with AsyncClient(
                transport=transport, base_url="http://testserver", follow_redirects=False
            ) as admin_client:
                await _login(admin_client, "admin@company.com", "admin")
                token = _csrf_token((await admin_client.get("/projects")).text)
                response = await admin_client.post(
                    "/projects",
                    data={"name": "Private", "language": "JAVASCRIPT", "csrf_token": token},
                )
                project_id = int(response.headers["location"].rsplit("/", 1)[1])
                token = _csrf_token((await admin_client.get("/users/new")).text)
                await admin_client.post(
                    "/users",
                    data={
                        "username": "outsider@company.com",
                        "password": "outsider-password",
                        "password_confirmation": "outsider-password",
                        "role": "USER",
                        "is_active": "true",
                        "csrf_token": token,
                    },
                )

            async with AsyncClient(
                transport=transport, base_url="http://testserver", follow_redirects=False
            ) as user_client:
                await _login(
                    user_client,
                    "outsider@company.com",
                    "outsider-password",
                    new_password="outsider-personal-password",
                )
                assert "Private" not in (await user_client.get("/projects")).text
                assert (await user_client.get(f"/projects/{project_id}")).status_code == 404

    asyncio.run(exercise())
