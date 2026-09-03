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
EXPECTED_STANDARD_IDS = {
    "제1절-1", "제1절-2", "제1절-3", "제1절-4", "제1절-5",
    "제1절-6", "제1절-8", "제2절-4", "제2절-6", "제2절-11", "제5절-5",
    "제2절-7", "제6절-3", "제6절-4", "제7절-2",
}
EXPECTED_RULE_FILES = {
    "code-injection": ("제1절-2", 3),
    "cross-site-scripting": ("제1절-4", 3),
    "hardcoded-sensitive-information": ("제2절-6", 3),
    "improper-certificate-validation": ("제2절-11", 3),
    "insufficient-key-length": ("제2절-7", 3),
    "os-command-injection": ("제1절-5", 3),
    "path-traversal": ("제1절-3", 3),
    "private-array-returned": ("제6절-3", 1),
    "public-array-assigned": ("제6절-4", 1),
    "sql-injection": ("제1절-1", 3),
    "unrestricted-file-upload": ("제1절-6", 3),
    "unsafe-deserialization": ("제5절-5", 2),
    "weak-crypto": ("제2절-4", 3),
    "vulnerable-api": ("제7절-2", 1),
    "xml-external-entity": ("제1절-8", 3),
}


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
    assert {rule_file.stem for rule_file in rule_files} == set(EXPECTED_RULE_FILES)
    assert not (RULESET_ROOT.parent / "kisa-2021.yml").exists()

    all_rule_ids: set[str] = set()
    all_standard_ids: set[str] = set()
    for rule_file in rule_files:
        content = rule_file.read_text(encoding="utf-8")
        rule_ids = re.findall(r"^  - id: ([^\n]+)$", content, flags=re.MULTILINE)
        standard_ids = re.findall(
            r"^      kisa_standard_id: ([^\n]+)$", content, flags=re.MULTILINE
        )
        expected_standard_id, expected_language_count = EXPECTED_RULE_FILES[rule_file.stem]
        assert len(rule_ids) == expected_language_count
        assert len(standard_ids) == expected_language_count
        assert set(standard_ids) == {expected_standard_id}
        all_rule_ids.update(rule_ids)
        all_standard_ids.update(standard_ids)

    assert len(all_rule_ids) == 38
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
