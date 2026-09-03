"""Phase 15 CSV/PDF report content and authorization tests."""

import asyncio
import csv
import io
import re
from datetime import datetime, timezone
from pathlib import Path

from httpx import ASGITransport, AsyncClient
from pypdf import PdfReader
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.security import hash_password
from app.config import Settings
from app.db.models.analysis_run import AnalysisRun
from app.db.models.enums import (
    AnalysisStatus,
    Confidence,
    FindingStatus,
    Language,
    Severity,
    SourceType,
    UserRole,
)
from app.db.models.finding import Finding
from app.db.models.finding_workflow import FindingWorkflow
from app.db.models.project import Project, ProjectUser
from app.db.models.rule import Rule
from app.db.models.user import User
from app.main import create_app


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        app_env="test",
        database_url=f"sqlite:///{tmp_path / 'reports.db'}",
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


def _seed_report_data(application) -> tuple[int, int]:
    with Session(application.state.db_engine) as session:
        admin = session.scalar(
            select(User).where(User.username == "admin@company.com")
        )
        rule = session.scalar(select(Rule).where(Rule.standard_id == "제1절-1"))
        assert admin is not None and rule is not None
        password_hash = hash_password("report-password")
        manager = User(
            username="report-manager@company.com",
            password_hash=password_hash,
            role=UserRole.PROJECT_MANAGER,
            must_change_password=False,
        )
        viewer = User(
            username="report-viewer@company.com",
            password_hash=password_hash,
            role=UserRole.USER,
            must_change_password=False,
        )
        outsider = User(
            username="report-outsider@company.com",
            password_hash=password_hash,
            role=UserRole.USER,
            must_change_password=False,
        )
        session.add_all([manager, viewer, outsider])
        session.flush()
        project = Project(
            name="고객 포털",
            description="보고서 시험 프로젝트",
            source_type=SourceType.ZIP,
            language=Language.PYTHON,
            source_path="",
            source_version="current-version-must-not-be-used",
            deployment_version="current-deploy-must-not-be-used",
            created_by=admin.id,
        )
        session.add(project)
        session.flush()
        session.add_all(
            [
                ProjectUser(project_id=project.id, user_id=admin.id),
                ProjectUser(project_id=project.id, user_id=manager.id),
                ProjectUser(project_id=project.id, user_id=viewer.id),
            ]
        )
        run = AnalysisRun(
            project_id=project.id,
            engine="Semgrep",
            language=Language.PYTHON,
            status=AnalysisStatus.COMPLETED,
            executed_by=admin.id,
            started_at=datetime(2026, 9, 1, 10, 30, tzinfo=timezone.utc),
            finished_at=datetime(2026, 9, 1, 10, 31, tzinfo=timezone.utc),
            error_message="INTERNAL-ERROR-MUST-NOT-LEAK /srv/private/workspace",
            summary={
                "provenance": {
                    "source_metadata": {
                        "source_version": "source-1.7.0",
                        "deployment_version": "deploy-2026.09",
                        "description": "고객 전달용 배포 후보",
                    }
                }
            },
        )
        empty_run = AnalysisRun(
            project_id=project.id,
            engine="Semgrep",
            language=Language.PYTHON,
            status=AnalysisStatus.COMPLETED,
            executed_by=admin.id,
            started_at=datetime(2026, 9, 2, 9, 0, tzinfo=timezone.utc),
            summary={"provenance": {"source_metadata": {}}},
        )
        session.add_all([run, empty_run])
        session.flush()
        finding_a = Finding(
            analysis_run_id=run.id,
            rule_id=rule.id,
            rule_name="SQL 삽입",
            kisa_id="제1절-1",
            language=Language.PYTHON,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            primary_cwe_id="CWE-89",
            cwe_mapping_confidence=Confidence.HIGH,
            file_path="src/app.py",
            start_line=12,
            start_column=3,
            message='=HYPERLINK("https://invalid.example", "위험")',
            evidence={"secret": "/srv/private/evidence"},
            recommendation="매개변수화 쿼리를 사용하세요.",
            raw_result={"secret": "RAW-SECRET-JSON"},
        )
        finding_b = Finding(
            analysis_run_id=run.id,
            rule_id=rule.id,
            rule_name="절대경로 방어 시험",
            kisa_id="제1절-1",
            language=Language.PYTHON,
            severity=Severity.CRITICAL,
            confidence=Confidence.MEDIUM,
            file_path="/srv/private/absolute.py",
            start_line=7,
            message="긴 한글 메시지도 보고서 안에서 안전하게 줄바꿈되어야 합니다. " * 12,
            raw_result={"secret": "RAW-SECRET-JSON-2"},
        )
        session.add_all([finding_a, finding_b])
        session.flush()
        session.add_all(
            [
                FindingWorkflow(
                    finding_id=finding_a.id,
                    status=FindingStatus.IN_PROGRESS,
                    note="담당자가 수정 중",
                    updated_by=manager.id,
                ),
                FindingWorkflow(
                    finding_id=finding_b.id,
                    status=FindingStatus.FALSE_POSITIVE,
                    note="@검토 근거",
                    updated_by=manager.id,
                ),
            ]
        )
        session.commit()
        return run.id, empty_run.id


def _pdf_text(content: bytes) -> str:
    reader = PdfReader(io.BytesIO(content))
    assert len(reader.pages) >= 1
    return "\n".join(page.extract_text() or "" for page in reader.pages)


def test_reports_include_required_fields_and_exclude_internal_data(
    tmp_path: Path,
) -> None:
    application = create_app(_settings(tmp_path))

    async def exercise() -> None:
        async with application.router.lifespan_context(application):
            run_id, empty_run_id = _seed_report_data(application)
            transport = ASGITransport(app=application)
            async with AsyncClient(
                transport=transport,
                base_url="http://testserver",
                follow_redirects=False,
            ) as client:
                await _login(client, "admin@company.com", "admin")
                analysis_page = await client.get(f"/analysis/{run_id}")
                assert f"/analysis/{run_id}/report.csv" in analysis_page.text
                assert f"/analysis/{run_id}/report.pdf" in analysis_page.text

                csv_response = await client.get(f"/analysis/{run_id}/report.csv")
                assert csv_response.status_code == 200
                assert csv_response.headers["content-type"].startswith("text/csv")
                assert csv_response.headers["content-disposition"] == (
                    f'attachment; filename="analysis-{run_id}-report.csv"'
                )
                rows = list(
                    csv.DictReader(
                        io.StringIO(csv_response.content.decode("utf-8-sig"))
                    )
                )
                assert len(rows) == 1
                assert rows[0]["프로젝트명"] == "고객 포털"
                assert rows[0]["소스 버전"] == "source-1.7.0"
                assert rows[0]["배포 버전"] == "deploy-2026.09"
                assert rows[0]["실행 계정"] == "admin@company.com"
                assert rows[0]["분석 상태"] == "완료"
                assert rows[0]["CRITICAL 건수"] == "0"
                assert rows[0]["HIGH 건수"] == "1"
                assert rows[0]["주요 CWE"] == "CWE-89"
                assert rows[0]["CWE 매핑 확신"] == "HIGH"
                assert rows[0]["조치 권고"] == "매개변수화 쿼리를 사용하세요."
                assert rows[0]["메시지"].startswith("'=")
                assert rows[0]["조치 상태"] == "조치 중"
                assert rows[0]["검토 의견"] == "담당자가 수정 중"
                csv_text = csv_response.content.decode("utf-8-sig")
                assert "절대경로 방어 시험" not in csv_text
                assert "@검토 근거" not in csv_text
                assert "RAW-SECRET-JSON" not in csv_text
                assert "INTERNAL-ERROR-MUST-NOT-LEAK" not in csv_text
                assert "/srv/private" not in csv_text

                pdf_response = await client.get(f"/analysis/{run_id}/report.pdf")
                assert pdf_response.status_code == 200
                assert pdf_response.content.startswith(b"%PDF-")
                assert pdf_response.headers["content-type"] == "application/pdf"
                assert pdf_response.headers["content-disposition"] == (
                    f'attachment; filename="analysis-{run_id}-report.pdf"'
                )
                pdf_text = _pdf_text(pdf_response.content)
                for expected in (
                    "정적 애플리케이션 보안 진단 결과 보고서",
                    "고객 포털",
                    "source-1.7.0",
                    "deploy-2026.09",
                    "admin@company.com",
                    "SQL 삽입",
                    "CWE-89",
                    "매개변수화 쿼리를 사용하세요.",
                    "조치 중",
                    "담당자가 수정 중",
                ):
                    assert expected in pdf_text
                assert "절대경로 방어 시험" not in pdf_text
                assert "@검토 근거" not in pdf_text
                assert "RAW-SECRET-JSON" not in pdf_text
                assert "INTERNAL-ERROR-MUST-NOT-LEAK" not in pdf_text
                assert "/srv/private" not in pdf_text
                assert "current-version-must-not-be-used" not in pdf_text

                empty_csv = await client.get(
                    f"/analysis/{empty_run_id}/report.csv"
                )
                empty_rows = list(
                    csv.DictReader(
                        io.StringIO(empty_csv.content.decode("utf-8-sig"))
                    )
                )
                assert len(empty_rows) == 1
                assert empty_rows[0]["KISA ID"] == ""
                empty_pdf = await client.get(
                    f"/analysis/{empty_run_id}/report.pdf"
                )
                assert "탐지된 Finding이 없습니다." in _pdf_text(empty_pdf.content)

    asyncio.run(exercise())


def test_report_downloads_follow_project_access_for_all_roles(tmp_path: Path) -> None:
    application = create_app(_settings(tmp_path))

    async def exercise() -> None:
        async with application.router.lifespan_context(application):
            run_id, _ = _seed_report_data(application)
            transport = ASGITransport(app=application)
            for username in (
                "admin@company.com",
                "report-manager@company.com",
                "report-viewer@company.com",
            ):
                password = "admin" if username == "admin@company.com" else "report-password"
                async with AsyncClient(
                    transport=transport,
                    base_url="http://testserver",
                    follow_redirects=False,
                ) as client:
                    await _login(client, username, password)
                    assert (
                        await client.get(f"/analysis/{run_id}/report.csv")
                    ).status_code == 200
                    assert (
                        await client.get(f"/analysis/{run_id}/report.pdf")
                    ).status_code == 200

            async with AsyncClient(
                transport=transport,
                base_url="http://testserver",
                follow_redirects=False,
            ) as outsider:
                await _login(
                    outsider,
                    "report-outsider@company.com",
                    "report-password",
                )
                assert (
                    await outsider.get(f"/analysis/{run_id}/report.csv")
                ).status_code == 404
                assert (
                    await outsider.get(f"/analysis/{run_id}/report.pdf")
                ).status_code == 404

    asyncio.run(exercise())
