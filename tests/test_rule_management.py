import asyncio
import re
from pathlib import Path

from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.db.models.diagnostic_rule import DiagnosticRule
from app.db.models.enums import Language
from app.db.models.rule import Rule
from app.db.models.user import User
from app.auth.security import hash_password
from app.db.models.enums import UserRole
from app.main import create_app


def _settings(tmp_path: Path) -> Settings:
    return Settings(app_env="test", database_url=f"sqlite:///{tmp_path / 'rules-ui.db'}", session_secret="test-session-secret-at-least-32-characters", upload_dir=tmp_path / "uploads", max_upload_bytes=20 * 1024 * 1024, max_extracted_bytes=100 * 1024 * 1024, max_archive_files=2_000, max_single_file_bytes=10 * 1024 * 1024, semgrep_timeout_seconds=60, template_dir=Path("app/templates").resolve(), static_dir=Path("app/static").resolve())


def _csrf(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match
    return match.group(1)


def test_catalog_views_and_admin_mapping_management(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    async def exercise() -> int:
        async with app.router.lifespan_context(app):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                login = await client.get("/login")
                response = await client.post("/login", data={"username":"admin@company.com", "password":"admin", "csrf_token":_csrf(login.text)}, follow_redirects=False)
                assert response.status_code == 303
                projects = await client.get("/projects")
                assert 'class="site-sidebar"' in projects.text
                assert 'class="secondary button catalog-action" href="/rules"' in projects.text
                catalog = await client.get("/rules?implementation_status=PARTIAL&language=JAVASCRIPT")
                assert catalog.status_code == 200 and "SQL 삽입" in catalog.text
                assert 'class="table-scroll"' in catalog.text and 'class="rule-table"' in catalog.text
                with Session(app.state.db_engine) as session:
                    rule = session.scalar(select(Rule).where(Rule.standard_id == "제1절-2")); assert rule
                    rule_id = rule.id
                edit = await client.get(f"/rules/{rule_id}/edit")
                response = await client.post(f"/rules/{rule_id}/edit", data={"languages":"PYTHON", "python_rule_id":"custom-code-injection-python", "csrf_token":_csrf(edit.text)}, follow_redirects=False)
                assert response.headers["location"] == f"/rules/{rule_id}"
                return rule_id
    rule_id = asyncio.run(exercise())
    with Session(app.state.db_engine) as session:
        mapping = session.scalar(select(DiagnosticRule).where(DiagnosticRule.catalog_rule_id == rule_id))
        assert mapping and mapping.language is Language.PYTHON and mapping.semgrep_rule_id == "custom-code-injection-python"


def test_user_can_read_catalog_but_cannot_manage_mappings(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    async def exercise() -> None:
        async with app.router.lifespan_context(app):
            with Session(app.state.db_engine) as session:
                session.add(User(username="reader@company.com", password_hash=hash_password("reader-password"), role=UserRole.USER, is_active=True)); session.commit()
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                login = await client.get("/login")
                response = await client.post("/login", data={"username":"reader@company.com", "password":"reader-password", "csrf_token":_csrf(login.text)}, follow_redirects=False)
                assert response.status_code == 303
                assert (await client.get("/rules")).status_code == 200
                assert (await client.get("/rules/new")).status_code == 403
    asyncio.run(exercise())
