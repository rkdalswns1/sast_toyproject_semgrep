import re
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PINNED_REQUIREMENT = re.compile(r"^[A-Za-z0-9_.-]+==[^=\s]+$")


def test_direct_dependencies_are_exactly_pinned() -> None:
    requirements = [
        line.strip()
        for line in (PROJECT_ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert requirements
    assert all(PINNED_REQUIREMENT.fullmatch(line) for line in requirements)


def test_dependency_monitoring_and_security_policy_are_present() -> None:
    dependabot = (PROJECT_ROOT / ".github" / "dependabot.yml").read_text(
        encoding="utf-8"
    )
    security_policy = (PROJECT_ROOT / "docs" / "security.md").read_text(
        encoding="utf-8"
    )

    assert "package-ecosystem: pip" in dependabot
    assert "interval: weekly" in dependabot
    for requirement_id in range(1, 11):
        assert f"SEC-{requirement_id:03d}" in (
            PROJECT_ROOT / "docs" / "requirements.md"
        ).read_text(encoding="utf-8")
    assert "Critical 또는 High" in security_policy
    assert "라이선스" in security_policy
