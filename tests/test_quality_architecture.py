"""QLT-001~005 structural contracts independent of UI behavior."""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from app.analysis.service import _sha256_ruleset
from app.analysis.routes import router as analysis_router
from app.findings.routes import router as findings_router
from app.projects.routes import router as projects_router


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RULESET_ROOT = PROJECT_ROOT / "app" / "rules" / "semgrep" / "kisa-2021"
EXPECTED_STANDARD_IDS = {"제1절-1", "제1절-5", "제2절-4", "제2절-6"}


def _route_modules(router, path: str) -> set[str]:
    return {
        route.endpoint.__module__
        for route in router.routes
        if getattr(route, "path", None) == path and hasattr(route, "endpoint")
    }


def test_analysis_and_finding_routes_have_responsibility_owned_modules() -> None:
    assert _route_modules(projects_router, "/projects") == {"app.projects.routes"}
    assert _route_modules(analysis_router, "/projects/{project_id}/analysis") == {
        "app.analysis.routes"
    }
    assert _route_modules(analysis_router, "/analysis/{analysis_id}") == {
        "app.analysis.routes"
    }
    assert _route_modules(findings_router, "/analysis/{analysis_id}/findings") == {
        "app.findings.routes"
    }
    assert _route_modules(findings_router, "/findings/{finding_id}") == {
        "app.findings.routes"
    }


def test_each_implemented_kisa_item_has_an_independent_rule_file() -> None:
    rule_files = sorted(RULESET_ROOT.glob("*.yml"))
    assert {rule_file.stem for rule_file in rule_files} == {
        "hardcoded-sensitive-information",
        "os-command-injection",
        "sql-injection",
        "weak-crypto",
    }
    assert not (RULESET_ROOT.parent / "kisa-2021.yml").exists()

    all_rule_ids: set[str] = set()
    all_standard_ids: set[str] = set()
    for rule_file in rule_files:
        content = rule_file.read_text(encoding="utf-8")
        rule_ids = re.findall(r"^  - id: ([^\n]+)$", content, flags=re.MULTILINE)
        standard_ids = re.findall(
            r"^      kisa_standard_id: ([^\n]+)$", content, flags=re.MULTILINE
        )
        assert len(rule_ids) == 3
        assert len(standard_ids) == 3
        assert len(set(standard_ids)) == 1
        all_rule_ids.update(rule_ids)
        all_standard_ids.update(standard_ids)

    assert len(all_rule_ids) == 12
    assert all_standard_ids == EXPECTED_STANDARD_IDS


def test_ruleset_hash_is_stable_and_changes_when_one_item_changes(tmp_path: Path) -> None:
    original_hash = _sha256_ruleset(RULESET_ROOT)
    assert original_hash == _sha256_ruleset(RULESET_ROOT)
    assert len(original_hash) == 64

    copied_ruleset = tmp_path / "kisa-2021"
    shutil.copytree(RULESET_ROOT, copied_ruleset)
    assert _sha256_ruleset(copied_ruleset) == original_hash

    changed_rule = copied_ruleset / "sql-injection.yml"
    changed_rule.write_text(
        changed_rule.read_text(encoding="utf-8") + "\n# independent item revision\n",
        encoding="utf-8",
    )
    assert _sha256_ruleset(copied_ruleset) != original_hash
