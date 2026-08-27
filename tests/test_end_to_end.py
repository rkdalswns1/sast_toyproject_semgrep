"""Phase 9 end-to-end verification of the documented MVP user flow."""

import asyncio
import io
import re
import zipfile
from pathlib import Path

from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.db.models.analysis_run import AnalysisRun
from app.db.models.enums import AnalysisStatus
from app.db.models.finding import Finding
from app.db.models.user import User
from app.main import create_app


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        app_env="test", database_url=f"sqlite:///{tmp_path / 'e2e.db'}",
        session_secret="test-session-secret", upload_dir=tmp_path / "uploads",
        max_upload_bytes=20 * 1024 * 1024, max_extracted_bytes=100 * 1024 * 1024,
        max_archive_files=2_000, max_single_file_bytes=10 * 1024 * 1024,
        semgrep_timeout_seconds=60, template_dir=Path("app/templates").resolve(),
        static_dir=Path("app/static").resolve(),
    )


def _csrf_token(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


def _vulnerable_zip() -> bytes:
    archive_bytes = io.BytesIO()
    with zipfile.ZipFile(archive_bytes, "w") as archive:
        archive.writestr(
            "src/vulnerable.py",
            "import hashlib\nimport subprocess\n"
            "cursor.execute('SELECT * FROM users WHERE name=' + user_input)\n"
            "subprocess.run(user_input, shell=True)\n"
            "password = 'secret'\nhashlib.md5(password.encode())\n",
        )
    return archive_bytes.getvalue()


async def _login(client: AsyncClient, username: str, password: str) -> None:
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


def test_authenticated_upload_analysis_findings_and_access_boundaries(tmp_path: Path) -> None:
    application = create_app(_settings(tmp_path))

    async def exercise() -> tuple[int, int, int]:
        async with application.router.lifespan_context(application):
            transport = ASGITransport(app=application)
            async with AsyncClient(
                transport=transport, base_url="http://testserver", follow_redirects=False
            ) as admin_client:
                assert (await admin_client.get("/projects")).headers["location"] == "/login"
                await _login(admin_client, "admin", "admin")

                projects_page = await admin_client.get("/projects")
                create_project_response = await admin_client.post(
                    "/projects",
                    data={
                        "name": "Integrated scan",
                        "language": "PYTHON",
                        "csrf_token": _csrf_token(projects_page.text),
                    },
                )
                assert create_project_response.status_code == 303
                project_id = int(create_project_response.headers["location"].rsplit("/", 1)[1])

                for username in ("member", "outsider"):
                    user_form = await admin_client.get("/users/new")
                    response = await admin_client.post(
                        "/users",
                        data={
                            "username": username,
                            "password": f"{username}-password",
                            "password_confirmation": f"{username}-password",
                            "role": "USER",
                            "is_active": "true",
                            "csrf_token": _csrf_token(user_form.text),
                        },
                    )
                    assert response.status_code == 303

                with Session(application.state.db_engine) as session:
                    member = session.scalar(select(User).where(User.username == "member"))
                    assert member is not None
                    member_id = member.id

                assignment_page = await admin_client.get(f"/projects/{project_id}/users")
                assignment_response = await admin_client.post(
                    f"/projects/{project_id}/users",
                    data={
                        "user_ids": str(member_id),
                        "csrf_token": _csrf_token(assignment_page.text),
                    },
                )
                assert assignment_response.status_code == 303

                detail_page = await admin_client.get(f"/projects/{project_id}")
                upload_response = await admin_client.post(
                    f"/projects/{project_id}/analysis",
                    data={"csrf_token": _csrf_token(detail_page.text)},
                    files={"source_file": ("source.zip", _vulnerable_zip(), "application/zip")},
                )
                assert upload_response.status_code == 303

                run_response = await admin_client.post(
                    f"/projects/{project_id}/analysis",
                    data={"csrf_token": _csrf_token(detail_page.text)},
                )
                assert run_response.status_code == 303
                analysis_id = int(run_response.headers["location"].rsplit("/", 1)[1])

                findings_page = await admin_client.get(
                    f"/analysis/{analysis_id}/findings?severity=HIGH"
                )
                assert findings_page.status_code == 200
                assert "SQL 삽입" in findings_page.text
                assert "운영체제 명령어 삽입" in findings_page.text
                finding_id_match = re.search(r"/findings/(\d+)", findings_page.text)
                assert finding_id_match is not None
                finding_id = int(finding_id_match.group(1))
                finding_page = await admin_client.get(f"/findings/{finding_id}")
                assert finding_page.status_code == 200
                assert "원본 Semgrep 결과" in finding_page.text

            async with AsyncClient(
                transport=transport, base_url="http://testserver", follow_redirects=False
            ) as member_client:
                await _login(member_client, "member", "member-password")
                assert (await member_client.get(f"/projects/{project_id}")).status_code == 200
                assert (await member_client.get(f"/analysis/{analysis_id}")).status_code == 200
                assert (await member_client.get(f"/analysis/{analysis_id}/findings")).status_code == 200
                assert (await member_client.get(f"/findings/{finding_id}")).status_code == 200

            async with AsyncClient(
                transport=transport, base_url="http://testserver", follow_redirects=False
            ) as outsider_client:
                await _login(outsider_client, "outsider", "outsider-password")
                assert (await outsider_client.get(f"/projects/{project_id}")).status_code == 404
                assert (await outsider_client.get(f"/analysis/{analysis_id}")).status_code == 404
                assert (await outsider_client.get(f"/analysis/{analysis_id}/findings")).status_code == 404
                assert (await outsider_client.get(f"/findings/{finding_id}")).status_code == 404
                return project_id, analysis_id, finding_id

    _, analysis_id, _ = asyncio.run(exercise())
    with Session(application.state.db_engine) as session:
        analysis_run = session.get(AnalysisRun, analysis_id)
        findings = session.scalars(
            select(Finding).where(Finding.analysis_run_id == analysis_id)
        ).all()
        assert analysis_run is not None
        assert analysis_run.status is AnalysisStatus.COMPLETED
        assert analysis_run.summary == {
            "finding_count": 4,
            "error_count": 0,
            "stored_finding_count": 4,
        }
        assert len(findings) == 4
