import asyncio
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.analysis.service import execute_project_analysis
from app.config import Settings
from app.db.models.enums import ImplementationStatus, Language
from app.db.models.finding import Finding
from app.db.models.rule import Rule
from app.db.models.user import User
from app.main import create_app
from app.projects.services import create_project, update_project_source
from app.rules.catalog import KISA_2021_CATALOG


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        app_env="test", database_url=f"sqlite:///{tmp_path / 'rules.db'}",
        session_secret="test-session-secret", upload_dir=tmp_path / "uploads",
        max_upload_bytes=20 * 1024 * 1024, max_extracted_bytes=100 * 1024 * 1024,
        max_archive_files=2_000, max_single_file_bytes=10 * 1024 * 1024,
        semgrep_timeout_seconds=60, template_dir=Path("app/templates").resolve(),
        static_dir=Path("app/static").resolve(),
    )


def test_kisa_2021_catalog_seeds_all_49_official_items_idempotently(tmp_path: Path) -> None:
    application = create_app(_settings(tmp_path))

    async def exercise() -> None:
        async with application.router.lifespan_context(application):
            with Session(application.state.db_engine) as session:
                assert session.scalar(select(func.count()).select_from(Rule)) == 49
                sql_injection = session.scalar(
                    select(Rule).where(Rule.standard_id == "제1절-1")
                )
                assert sql_injection is not None
                assert sql_injection.name == "SQL 삽입"
                assert sql_injection.category == "입력데이터 검증 및 표현"
                assert sql_injection.semgrep_rule_id == "kisa-2021-sql-injection-python"
                assert sql_injection.supported_languages == [Language.PYTHON.value]
                assert sql_injection.implementation_status is ImplementationStatus.PARTIAL
                not_implemented = session.scalar(
                    select(Rule).where(Rule.standard_id == "제1절-2")
                )
                assert not_implemented is not None
                assert not_implemented.implementation_status is ImplementationStatus.NOT_IMPLEMENTED
                assert not_implemented.supported_languages == []

        async with application.router.lifespan_context(application):
            with Session(application.state.db_engine) as session:
                assert session.scalar(select(func.count()).select_from(Rule)) == 49

    assert len(KISA_2021_CATALOG) == 49
    asyncio.run(exercise())


def test_mapped_local_semgrep_rules_persist_findings_for_supported_language(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    application = create_app(settings)

    async def exercise() -> tuple[int, int]:
        async with application.router.lifespan_context(application):
            with Session(application.state.db_engine) as session:
                admin = session.scalar(select(User).where(User.username == "admin"))
                assert admin is not None
                admin_id = admin.id
            with Session(application.state.db_engine) as session:
                project = create_project(
                    session, name="Catalog rule target", description=None,
                    language=Language.PYTHON, created_by=admin_id,
                )
                project_id = project.id

            source_path = settings.upload_dir / "catalog-rule-test" / "source"
            source_path.mkdir(parents=True)
            (source_path / "vulnerable.py").write_text(
                "import hashlib\nimport subprocess\n"
                "cursor.execute('SELECT * FROM users WHERE name=' + user_input)\n"
                "subprocess.run(user_input, shell=True)\n"
                "password = 'secret'\nhashlib.md5(password.encode())\n",
                encoding="utf-8",
            )
            with Session(application.state.db_engine) as session:
                update_project_source(session, project_id=project_id, source_path=source_path)
                analysis_run = execute_project_analysis(
                    session, project_id=project_id, executed_by=admin_id, settings=settings
                )
                return project_id, analysis_run.id

    _, analysis_id = asyncio.run(exercise())
    with Session(application.state.db_engine) as session:
        findings = session.scalars(
            select(Finding).where(Finding.analysis_run_id == analysis_id).order_by(Finding.rule_name)
        ).all()
        assert {finding.rule_name for finding in findings} == {
            "SQL 삽입", "운영체제 명령어 삽입", "하드코드된 중요정보", "취약한 암호화 알고리즘 사용"
        }
        assert {finding.file_path for finding in findings} == {"vulnerable.py"}
        assert all(finding.raw_result["path"].startswith(str(settings.upload_dir)) for finding in findings)
