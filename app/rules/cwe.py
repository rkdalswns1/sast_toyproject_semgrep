"""Approved CWE mappings for repository-owned Semgrep rules."""

from __future__ import annotations

from dataclasses import dataclass

from app.db.models.enums import Confidence


@dataclass(frozen=True, slots=True)
class ApprovedCweMapping:
    primary_cwe_id: str
    related_cwe_ids: tuple[str, ...]
    confidence: Confidence
    remediation_guidance: str


def mitre_cwe_url(cwe_id: str) -> str:
    """Build the official MITRE detail URL for a validated CWE identifier."""
    return f"https://cwe.mitre.org/data/definitions/{cwe_id.removeprefix('CWE-')}.html"


def _family(
    rule_ids: tuple[str, ...],
    *,
    cwe_id: str,
    confidence: Confidence,
    guidance: str,
) -> dict[str, ApprovedCweMapping]:
    mapping = ApprovedCweMapping(cwe_id, (), confidence, guidance)
    return {rule_id: mapping for rule_id in rule_ids}


APPROVED_CWE_MAPPINGS: dict[str, ApprovedCweMapping] = {
    **_family(
        tuple(f"kisa-2021-sql-injection-{language}" for language in ("java", "javascript", "python")),
        cwe_id="CWE-89",
        confidence=Confidence.HIGH,
        guidance="문자열 연결로 SQL을 만들지 말고 매개변수화 쿼리와 바인딩 변수를 사용하세요.",
    ),
    **_family(
        tuple(f"kisa-2021-path-traversal-{language}" for language in ("java", "javascript", "python")),
        cwe_id="CWE-22",
        confidence=Confidence.HIGH,
        guidance="허용된 기준 디렉터리 아래에서만 경로를 해석하고 정규화한 뒤 경로 이탈 여부를 검사하세요.",
    ),
    **_family(
        tuple(f"kisa-2021-xss-{language}" for language in ("java", "javascript", "python")),
        cwe_id="CWE-79",
        confidence=Confidence.HIGH,
        guidance="신뢰할 수 없는 값은 HTML 출력 위치에 맞게 이스케이프하고 안전 처리 우회 기능을 사용하지 마세요.",
    ),
    **_family(
        tuple(f"kisa-2021-os-command-injection-{language}" for language in ("java", "javascript", "python")),
        cwe_id="CWE-78",
        confidence=Confidence.HIGH,
        guidance="셸 명령 문자열을 조합하지 말고 고정된 실행 파일과 검증된 인자 목록을 사용하세요.",
    ),
    **_family(
        tuple(f"kisa-2021-unrestricted-upload-{language}" for language in ("java", "javascript", "python")),
        cwe_id="CWE-434",
        confidence=Confidence.MEDIUM,
        guidance="허용 확장자와 실제 파일 형식을 검사하고 서버가 생성한 이름으로 웹 루트 밖에 저장하세요.",
    ),
    **_family(
        tuple(f"kisa-2021-xxe-{language}" for language in ("java", "javascript", "python")),
        cwe_id="CWE-611",
        confidence=Confidence.HIGH,
        guidance="XML 파서에서 DTD와 외부 엔터티·외부 스키마 접근을 명시적으로 비활성화하세요.",
    ),
    **_family(
        tuple(f"kisa-2021-weak-crypto-{language}" for language in ("java", "javascript", "python")),
        cwe_id="CWE-328",
        confidence=Confidence.HIGH,
        guidance="MD5와 SHA-1 대신 목적에 적합한 최신 해시 알고리즘을 사용하고 비밀번호에는 전용 비밀번호 해시를 사용하세요.",
    ),
    **_family(
        tuple(f"kisa-2021-hardcoded-sensitive-information-{language}" for language in ("java", "javascript", "python")),
        cwe_id="CWE-798",
        confidence=Confidence.MEDIUM,
        guidance="비밀번호·토큰·API 키를 소스 코드에서 제거하고 접근 통제된 환경변수나 비밀 저장소에서 주입하세요.",
    ),
    **_family(
        (
            "kisa-2021-improper-certificate-validation-python",
            "kisa-2021-improper-certificate-validation-javascript",
        ),
        cwe_id="CWE-295",
        confidence=Confidence.HIGH,
        guidance="TLS 인증서와 호스트명 검증을 끄지 말고 승인된 CA 또는 인증서만 신뢰하도록 구성하세요.",
    ),
    **_family(
        ("kisa-2021-improper-certificate-validation-java",),
        cwe_id="CWE-296",
        confidence=Confidence.HIGH,
        guidance="플랫폼 TrustManagerFactory를 사용하고 서버 인증서 체인과 호스트명을 실제로 검증하세요.",
    ),
    **_family(
        (
            "kisa-2021-unsafe-deserialization-java",
            "kisa-2021-unsafe-deserialization-python",
        ),
        cwe_id="CWE-502",
        confidence=Confidence.HIGH,
        guidance="신뢰할 수 없는 데이터를 네이티브 객체로 역직렬화하지 말고 JSON 같은 데이터 전용 형식과 필드 검증을 사용하세요.",
    ),
}


assert len(APPROVED_CWE_MAPPINGS) == 29
