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
from app.db.models.enums import AnalysisStatus, FindingStatus, Language
from app.db.models.finding import Finding
from app.db.models.finding_workflow import FindingWorkflow
from app.db.models.user import User
from app.main import create_app


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        app_env="test", database_url=f"sqlite:///{tmp_path / 'e2e.db'}",
        session_secret="test-session-secret-at-least-32-characters", upload_dir=tmp_path / "uploads",
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


def test_authenticated_upload_analysis_findings_and_access_boundaries(tmp_path: Path) -> None:
    application = create_app(_settings(tmp_path))

    async def exercise() -> tuple[int, int, int]:
        async with application.router.lifespan_context(application):
            transport = ASGITransport(app=application)
            async with AsyncClient(
                transport=transport, base_url="http://testserver", follow_redirects=False
            ) as admin_client:
                assert (await admin_client.get("/projects")).headers["location"] == "/login"
                await _login(admin_client, "admin@company.com", "admin")

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

                test_users = (
                    ("member@company.com", "member-password", "PROJECT_MANAGER"),
                    ("viewer@company.com", "viewer-password", "USER"),
                    ("outsider@company.com", "outsider-password", "USER"),
                )
                for username, initial_password, role in test_users:
                    user_form = await admin_client.get("/users/new")
                    response = await admin_client.post(
                        "/users",
                        data={
                            "username": username,
                            "password": initial_password,
                            "password_confirmation": initial_password,
                            "role": role,
                            "is_active": "true",
                            "csrf_token": _csrf_token(user_form.text),
                        },
                    )
                    assert response.status_code == 303

                with Session(application.state.db_engine) as session:
                    member = session.scalar(
                        select(User).where(User.username == "member@company.com")
                    )
                    viewer = session.scalar(
                        select(User).where(User.username == "viewer@company.com")
                    )
                    assert member is not None and viewer is not None
                    member_id = member.id
                    viewer_id = viewer.id

                assignment_page = await admin_client.get(f"/projects/{project_id}/users")
                assignment_response = await admin_client.post(
                    f"/projects/{project_id}/users",
                    data={
                        "user_ids": [str(member_id), str(viewer_id)],
                        "csrf_token": _csrf_token(assignment_page.text),
                    },
                )
                assert assignment_response.status_code == 303

                detail_page = await admin_client.get(f"/projects/{project_id}")
                upload_response = await admin_client.post(
                    f"/projects/{project_id}/analysis",
                    data={
                        "source_version": "source-v1",
                        "deployment_version": "deploy-v1",
                        "source_description": "첫 번째 분석 대상",
                        "csrf_token": _csrf_token(detail_page.text),
                    },
                    files={"source_file": ("source.zip", _vulnerable_zip(), "application/zip")},
                )
                assert upload_response.status_code == 303

                run_response = await admin_client.post(
                    f"/projects/{project_id}/analysis",
                    data={"csrf_token": _csrf_token(detail_page.text)},
                )
                assert run_response.status_code == 303
                analysis_id = int(run_response.headers["location"].rsplit("/", 1)[1])
                analysis_detail = await admin_client.get(f"/analysis/{analysis_id}")
                assert "활성 규칙: 10개" in analysis_detail.text
                assert "활성 규칙 구성 SHA-256" in analysis_detail.text
                assert "source-v1" in analysis_detail.text
                assert "deploy-v1" in analysis_detail.text
                assert "첫 번째 분석 대상" in analysis_detail.text

                current_project = await admin_client.get(f"/projects/{project_id}")
                replacement_upload = await admin_client.post(
                    f"/projects/{project_id}/analysis",
                    data={
                        "source_version": "source-v2",
                        "deployment_version": "deploy-v2",
                        "source_description": "다음 분석을 위한 교체 소스",
                        "csrf_token": _csrf_token(current_project.text),
                    },
                    files={
                        "source_file": (
                            "source-v2.zip",
                            _vulnerable_zip(),
                            "application/zip",
                        )
                    },
                )
                assert replacement_upload.status_code == 303
                historical_detail = await admin_client.get(f"/analysis/{analysis_id}")
                assert "source-v1" in historical_detail.text
                assert "deploy-v1" in historical_detail.text
                assert "source-v2" not in historical_detail.text
                analysis_history = await admin_client.get(
                    f"/projects/{project_id}/analysis"
                )
                assert "source-v1 / deploy-v1" in analysis_history.text

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

                with Session(application.state.db_engine) as session:
                    admin = session.scalar(
                        select(User).where(User.username == "admin@company.com")
                    )
                    assert admin is not None
                    failed_run = AnalysisRun(
                        project_id=project_id,
                        engine="Semgrep",
                        language=Language.PYTHON,
                        status=AnalysisStatus.FAILED,
                        executed_by=admin.id,
                        error_message="private analyzer detail",
                    )
                    session.add(failed_run)
                    session.commit()
                    failed_analysis_id = failed_run.id
                admin_failure = await admin_client.get(
                    f"/analysis/{failed_analysis_id}"
                )
                assert "private analyzer detail" in admin_failure.text

            async with AsyncClient(
                transport=transport, base_url="http://testserver", follow_redirects=False
            ) as member_client:
                await _login(
                    member_client,
                    "member@company.com",
                    "member-password",
                    new_password="member-personal-password",
                )
                member_projects = await member_client.get("/projects")
                member_project = await member_client.get(f"/projects/{project_id}")
                assert member_project.status_code == 200
                assert "ZIP 소스 업로드" in member_project.text
                assert "Semgrep 분석 실행" in member_project.text
                assert (await member_client.get(f"/projects/{project_id}/edit")).status_code == 200
                assert (await member_client.get(f"/projects/{project_id}/users")).status_code == 200
                assert (await member_client.get("/projects/new")).status_code == 403
                assert (await member_client.get("/users")).status_code == 403
                assert (await member_client.get("/rules/new")).status_code == 403
                assert (await member_client.get(f"/analysis/{analysis_id}")).status_code == 200
                assert (await member_client.get(f"/analysis/{analysis_id}/findings")).status_code == 200
                member_finding = await member_client.get(f"/findings/{finding_id}")
                assert member_finding.status_code == 200
                status_response = await member_client.post(
                    f"/findings/{finding_id}/status",
                    data={
                        "workflow_status": "RESOLVED",
                        "note": "프로젝트 담당자가 수정 여부를 확인함",
                        "csrf_token": _csrf_token(member_finding.text),
                    },
                )
                assert status_response.status_code == 303
                member_failure = await member_client.get(
                    f"/analysis/{failed_analysis_id}"
                )
                assert "private analyzer detail" in member_failure.text

            async with AsyncClient(
                transport=transport, base_url="http://testserver", follow_redirects=False
            ) as viewer_client:
                await _login(
                    viewer_client,
                    "viewer@company.com",
                    "viewer-password",
                    new_password="viewer-personal-password",
                )
                viewer_finding = await viewer_client.get(f"/findings/{finding_id}")
                assert viewer_finding.status_code == 200
                assert "조치 완료" in viewer_finding.text
                assert "프로젝트 담당자가 수정 여부를 확인함" in viewer_finding.text
                assert "조치 상태 저장" not in viewer_finding.text
                viewer_projects = await viewer_client.get("/projects")
                viewer_update = await viewer_client.post(
                    f"/findings/{finding_id}/status",
                    data={
                        "workflow_status": "OPEN",
                        "note": "일반 사용자는 변경할 수 없어야 함",
                        "csrf_token": _csrf_token(viewer_projects.text),
                    },
                )
                assert viewer_update.status_code == 403

            async with AsyncClient(
                transport=transport, base_url="http://testserver", follow_redirects=False
            ) as outsider_client:
                await _login(
                    outsider_client,
                    "outsider@company.com",
                    "outsider-password",
                    new_password="outsider-personal-password",
                )
                assert (await outsider_client.get(f"/projects/{project_id}")).status_code == 404
                assert (await outsider_client.get(f"/analysis/{analysis_id}")).status_code == 404
                assert (
                    await outsider_client.get(f"/analysis/{failed_analysis_id}")
                ).status_code == 404
                assert (await outsider_client.get(f"/analysis/{analysis_id}/findings")).status_code == 404
                assert (await outsider_client.get(f"/findings/{finding_id}")).status_code == 404
                return project_id, analysis_id, finding_id

    _, analysis_id, finding_id = asyncio.run(exercise())
    with Session(application.state.db_engine) as session:
        analysis_run = session.get(AnalysisRun, analysis_id)
        findings = session.scalars(
            select(Finding).where(Finding.analysis_run_id == analysis_id)
        ).all()
        assert analysis_run is not None
        assert analysis_run.status is AnalysisStatus.COMPLETED
        assert analysis_run.summary is not None
        assert {
            key: analysis_run.summary[key]
            for key in ("finding_count", "error_count", "stored_finding_count")
        } == {
            "finding_count": 4,
            "error_count": 0,
            "stored_finding_count": 4,
        }
        assert analysis_run.summary["provenance"]["selected_language"] == "PYTHON"
        assert analysis_run.summary["provenance"]["source_metadata"] == {
            "source_version": "source-v1",
            "deployment_version": "deploy-v1",
            "description": "첫 번째 분석 대상",
        }
        assert len(analysis_run.summary["provenance"]["active_rules"]) == 10
        assert len(analysis_run.summary["provenance"]["active_rules_sha256"]) == 64
        assert len(findings) == 4
        workflow = session.get(FindingWorkflow, finding_id)
        assert workflow is not None
        assert workflow.status is FindingStatus.RESOLVED
        assert workflow.updater is not None
        assert workflow.updater.username == "member@company.com"
