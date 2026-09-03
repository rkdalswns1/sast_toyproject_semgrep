import asyncio
import json
import shutil
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.service import execute_project_analysis
from app.config import Settings
from app.db.models.analysis_run import AnalysisRun
from app.db.models.enums import AnalysisStatus, Language
from app.db.models.finding import Finding
from app.db.models.project import Project
from app.db.models.rule import Rule
from app.db.models.user import User
from app.main import create_app
from app.projects.services import create_project, update_project_source


SAMPLES_ROOT = Path(__file__).parent / "samples"
EXPECTED_FINDINGS = json.loads(
    (SAMPLES_ROOT / "expected_findings.json").read_text(encoding="utf-8")
)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        app_env="test",
        database_url=f"sqlite:///{tmp_path / 'diagnostic-examples.db'}",
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


@pytest.mark.parametrize("language", list(Language))
def test_vulnerable_and_safe_samples_match_expected_findings(
    tmp_path: Path, language: Language
) -> None:
    settings = _settings(tmp_path)
    application = create_app(settings)
    expected = EXPECTED_FINDINGS[language.value]

    async def exercise() -> tuple[int, int]:
        async with application.router.lifespan_context(application):
            with Session(application.state.db_engine) as session:
                admin = session.scalar(
                    select(User).where(User.username == "admin@company.com")
                )
                assert admin is not None
                admin_id = admin.id

            run_ids: dict[str, int] = {}
            for sample_kind, filename_key in (
                ("vulnerable", "vulnerable_file"),
                ("safe", "safe_file"),
            ):
                with Session(application.state.db_engine) as session:
                    project = create_project(
                        session,
                        name=f"{language.value} {sample_kind} expectation",
                        description="TST-005 fixed diagnostic sample",
                        language=language,
                        created_by=admin_id,
                    )
                    project_id = project.id

                source_root = (
                    settings.upload_dir
                    / "projects"
                    / str(project_id)
                    / "sources"
                    / sample_kind
                    / "extracted"
                )
                source_root.mkdir(parents=True)
                source_file = SAMPLES_ROOT / language.value.lower() / expected[filename_key]
                shutil.copy2(source_file, source_root / source_file.name)

                with Session(application.state.db_engine) as session:
                    update_project_source(
                        session,
                        project_id=project_id,
                        source_path=source_root,
                    )
                    run = execute_project_analysis(
                        session,
                        project_id=project_id,
                        executed_by=admin_id,
                        settings=settings,
                    )
                    run_ids[sample_kind] = run.id
            return run_ids["vulnerable"], run_ids["safe"]

    vulnerable_run_id, safe_run_id = asyncio.run(exercise())

    with Session(application.state.db_engine) as session:
        vulnerable_run = session.get(AnalysisRun, vulnerable_run_id)
        safe_run = session.get(AnalysisRun, safe_run_id)
        assert vulnerable_run is not None and safe_run is not None
        assert vulnerable_run.status is AnalysisStatus.COMPLETED
        assert safe_run.status is AnalysisStatus.COMPLETED
        assert vulnerable_run.summary is not None
        assert safe_run.summary is not None
        assert vulnerable_run.summary["provenance"]["selected_language"] == language.value
        assert vulnerable_run.summary["provenance"]["detected_languages"] == [
            language.value
        ]
        vulnerable_project = session.get(Project, vulnerable_run.project_id)
        safe_project = session.get(Project, safe_run.project_id)
        assert vulnerable_project is not None and safe_project is not None
        assert vulnerable_run.language is vulnerable_project.language is language
        assert safe_run.language is safe_project.language is language

        findings = session.scalars(
            select(Finding).where(Finding.analysis_run_id == vulnerable_run_id)
        ).all()
        findings_by_standard = {finding.kisa_id: finding for finding in findings}
        assert set(findings_by_standard) == set(expected["findings"])
        assert vulnerable_run.summary["finding_count"] == len(expected["findings"])
        assert vulnerable_run.summary["stored_finding_count"] == len(
            expected["findings"]
        )
        assert vulnerable_run.summary["stored_distinct_kisa_count"] == len(
            expected["findings"]
        )
        assert vulnerable_run.summary["stored_distinct_kisa_count_by_language"] == {
            language.value: len(expected["findings"])
        }

        for standard_id, expected_finding in expected["findings"].items():
            finding = findings_by_standard[standard_id]
            rule = session.get(Rule, finding.rule_id)
            assert rule is not None
            assert rule.standard_id == standard_id
            assert finding.language is vulnerable_run.language
            assert finding.language.value in rule.supported_languages
            assert finding.rule_name == rule.name
            assert finding.file_path == expected["vulnerable_file"]
            assert finding.start_line == expected_finding["line"]
            assert finding.severity.value == expected_finding["severity"]
            assert finding.confidence.value == expected_finding["confidence"]
            assert finding.recommendation
            assert finding.evidence and finding.evidence.get("lines")
            assert finding.raw_result["extra"]["metadata"]["kisa_standard_id"] == standard_id

        safe_findings = session.scalars(
            select(Finding).where(Finding.analysis_run_id == safe_run_id)
        ).all()
        assert safe_findings == []
        assert safe_run.summary["finding_count"] == 0
        assert safe_run.summary["stored_finding_count"] == 0


def test_multi_language_project_scans_all_detected_languages_in_one_run(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    application = create_app(settings)

    async def exercise() -> tuple[int, int]:
        async with application.router.lifespan_context(application):
            with Session(application.state.db_engine) as session:
                admin = session.scalar(
                    select(User).where(User.username == "admin@company.com")
                )
                assert admin is not None
                admin_id = admin.id

            run_ids: list[int] = []
            for sample_kind in ("vulnerable", "safe"):
                with Session(application.state.db_engine) as session:
                    project = create_project(
                        session,
                        name=f"Mixed {sample_kind} expectation",
                        description="Phase 12 mixed-language sample",
                        language=Language.PYTHON,
                        scan_all_languages=True,
                        created_by=admin_id,
                    )
                    project_id = project.id

                source_root = (
                    settings.upload_dir
                    / "projects"
                    / str(project_id)
                    / "sources"
                    / sample_kind
                    / "extracted"
                )
                for language in Language:
                    expected = EXPECTED_FINDINGS[language.value]
                    filename_key = f"{sample_kind}_file"
                    source_file = (
                        SAMPLES_ROOT
                        / language.value.lower()
                        / expected[filename_key]
                    )
                    destination = source_root / language.value.lower()
                    destination.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source_file, destination / source_file.name)

                with Session(application.state.db_engine) as session:
                    update_project_source(
                        session, project_id=project_id, source_path=source_root
                    )
                    run = execute_project_analysis(
                        session,
                        project_id=project_id,
                        executed_by=admin_id,
                        settings=settings,
                    )
                    run_ids.append(run.id)
            return run_ids[0], run_ids[1]

    vulnerable_run_id, safe_run_id = asyncio.run(exercise())

    with Session(application.state.db_engine) as session:
        vulnerable_run = session.get(AnalysisRun, vulnerable_run_id)
        safe_run = session.get(AnalysisRun, safe_run_id)
        assert vulnerable_run is not None and vulnerable_run.summary is not None
        assert safe_run is not None and safe_run.summary is not None
        assert vulnerable_run.status is AnalysisStatus.COMPLETED
        assert safe_run.status is AnalysisStatus.COMPLETED
        assert vulnerable_run.summary["provenance"]["scan_mode"] == "MULTI"
        assert vulnerable_run.summary["provenance"]["detected_languages"] == [
            "JAVA",
            "JAVASCRIPT",
            "PYTHON",
        ]
        assert vulnerable_run.summary["provenance"]["scanned_languages"] == [
            "JAVA",
            "JAVASCRIPT",
            "PYTHON",
        ]
        assert len(vulnerable_run.summary["provenance"]["active_rules"]) == 38
        assert vulnerable_run.summary["stored_finding_count_by_language"] == {
            "JAVA": 15,
            "JAVASCRIPT": 11,
            "PYTHON": 12,
        }
        assert vulnerable_run.summary["stored_distinct_kisa_count_by_language"] == {
            "JAVA": 15,
            "JAVASCRIPT": 11,
            "PYTHON": 12,
        }
        assert vulnerable_run.summary["stored_distinct_kisa_count"] == 15

        findings = session.scalars(
            select(Finding).where(Finding.analysis_run_id == vulnerable_run_id)
        ).all()
        assert len(findings) == 38
        for language in Language:
            language_findings = {
                finding.kisa_id
                for finding in findings
                if finding.language is language
            }
            assert language_findings == set(
                EXPECTED_FINDINGS[language.value]["findings"]
            )

        safe_findings = session.scalars(
            select(Finding).where(Finding.analysis_run_id == safe_run_id)
        ).all()
        assert safe_findings == []
        assert safe_run.summary["finding_count"] == 0
        assert safe_run.summary["stored_finding_count"] == 0
