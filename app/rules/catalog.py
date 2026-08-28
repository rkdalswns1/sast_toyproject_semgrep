"""KISA 2021 implementation-stage catalog transcribed from the supplied guide."""

from __future__ import annotations

from dataclasses import dataclass

from app.db.models.enums import ImplementationStatus, Language, Severity


@dataclass(frozen=True, slots=True)
class CatalogEntry:
    standard_id: str
    category: str
    item_number: int
    name: str
    severity: Severity
    supported_languages: tuple[Language, ...] = ()
    implementation_status: ImplementationStatus = ImplementationStatus.NOT_IMPLEMENTED
    semgrep_rule_id: str | None = None

    @property
    def description(self) -> str:
        return f"KISA 「소프트웨어 보안약점 진단가이드(2021)」의 ‘{self.name}’ 항목."

    @property
    def reference_info(self) -> str:
        return (
            "KISA 소프트웨어 보안약점 진단가이드(2021) "
            f"{self.standard_id} {self.name}"
        )


_INPUT_VALIDATION = "입력데이터 검증 및 표현"
_SECURITY_FUNCTION = "보안기능"
_TIME_AND_STATE = "시간 및 상태"
_ERROR_HANDLING = "에러처리"
_CODE_ERROR = "코드오류"
_ENCAPSULATION = "캡슐화"
_API_MISUSE = "API 오용"
_INITIAL_RULE_LANGUAGES = (
    Language.JAVA,
    Language.JAVASCRIPT,
    Language.PYTHON,
)


def _entry(
    section: int,
    number: int,
    category: str,
    name: str,
    severity: Severity = Severity.INFO,
    languages: tuple[Language, ...] = (),
    status: ImplementationStatus = ImplementationStatus.NOT_IMPLEMENTED,
    semgrep_rule_id: str | None = None,
) -> CatalogEntry:
    return CatalogEntry(
        standard_id=f"제{section}절-{number}",
        category=category,
        item_number=number,
        name=name,
        severity=severity,
        supported_languages=languages,
        implementation_status=status,
        semgrep_rule_id=semgrep_rule_id,
    )


# The official guide uses a section and within-section item number, rather than
# a separate KISA code. Those source identifiers are retained verbatim here.
KISA_2021_CATALOG: tuple[CatalogEntry, ...] = (
    _entry(1, 1, _INPUT_VALIDATION, "SQL 삽입", Severity.HIGH, _INITIAL_RULE_LANGUAGES, ImplementationStatus.PARTIAL, "kisa-2021-sql-injection-python"),
    _entry(1, 2, _INPUT_VALIDATION, "코드삽입"),
    _entry(1, 3, _INPUT_VALIDATION, "경로 조작 및 자원 삽입"),
    _entry(1, 4, _INPUT_VALIDATION, "크로스사이트 스크립트"),
    _entry(1, 5, _INPUT_VALIDATION, "운영체제 명령어 삽입", Severity.HIGH, _INITIAL_RULE_LANGUAGES, ImplementationStatus.PARTIAL, "kisa-2021-os-command-injection-python"),
    _entry(1, 6, _INPUT_VALIDATION, "위험한 형식 파일 업로드"),
    _entry(1, 7, _INPUT_VALIDATION, "신뢰되지 않는 URL 주소로 자동접속 연결"),
    _entry(1, 8, _INPUT_VALIDATION, "부적절한 XML 외부개체 참조"),
    _entry(1, 9, _INPUT_VALIDATION, "XML 삽입"),
    _entry(1, 10, _INPUT_VALIDATION, "LDAP 삽입"),
    _entry(1, 11, _INPUT_VALIDATION, "크로스사이트 요청 위조"),
    _entry(1, 12, _INPUT_VALIDATION, "서버사이드 요청 위조"),
    _entry(1, 13, _INPUT_VALIDATION, "HTTP 응답분할"),
    _entry(1, 14, _INPUT_VALIDATION, "정수형 오버플로우"),
    _entry(1, 15, _INPUT_VALIDATION, "보안기능 결정에 사용되는 부적절한 입력값"),
    _entry(1, 16, _INPUT_VALIDATION, "메모리 버퍼 오버플로우"),
    _entry(1, 17, _INPUT_VALIDATION, "포맷 스트링 삽입"),
    _entry(2, 1, _SECURITY_FUNCTION, "적절한 인증 없는 중요기능 허용"),
    _entry(2, 2, _SECURITY_FUNCTION, "부적절한 인가"),
    _entry(2, 3, _SECURITY_FUNCTION, "중요한 자원에 대한 잘못된 권한 설정"),
    _entry(2, 4, _SECURITY_FUNCTION, "취약한 암호화 알고리즘 사용", Severity.MEDIUM, _INITIAL_RULE_LANGUAGES, ImplementationStatus.PARTIAL, "kisa-2021-weak-crypto-python"),
    _entry(2, 5, _SECURITY_FUNCTION, "암호화되지 않은 중요정보"),
    _entry(2, 6, _SECURITY_FUNCTION, "하드코드된 중요정보", Severity.HIGH, _INITIAL_RULE_LANGUAGES, ImplementationStatus.PARTIAL, "kisa-2021-hardcoded-sensitive-information-python"),
    _entry(2, 7, _SECURITY_FUNCTION, "충분하지 않은 키 길이 사용"),
    _entry(2, 8, _SECURITY_FUNCTION, "적절하지 않은 난수 값 사용"),
    _entry(2, 9, _SECURITY_FUNCTION, "취약한 비밀번호 허용"),
    _entry(2, 10, _SECURITY_FUNCTION, "부적절한 전자서명 확인"),
    _entry(2, 11, _SECURITY_FUNCTION, "부적절한 인증서 유효성 검증"),
    _entry(2, 12, _SECURITY_FUNCTION, "사용자 하드디스크에 저장되는 쿠키를 통한 정보 노출"),
    _entry(2, 13, _SECURITY_FUNCTION, "주석문 안에 포함된 시스템 주요정보"),
    _entry(2, 14, _SECURITY_FUNCTION, "솔트 없이 일방향 해쉬 함수 사용"),
    _entry(2, 15, _SECURITY_FUNCTION, "무결성 검사 없는 코드 다운로드"),
    _entry(2, 16, _SECURITY_FUNCTION, "반복된 인증시도 제한 기능 부재"),
    _entry(3, 1, _TIME_AND_STATE, "경쟁조건: 검사 시점과 사용 시점(TOCTOU)"),
    _entry(3, 2, _TIME_AND_STATE, "종료되지 않는 반복문 또는 재귀 함수"),
    _entry(4, 1, _ERROR_HANDLING, "오류 메시지 정보노출"),
    _entry(4, 2, _ERROR_HANDLING, "오류상황 대응 부재"),
    _entry(4, 3, _ERROR_HANDLING, "부적절한 예외 처리"),
    _entry(5, 1, _CODE_ERROR, "Null Pointer 역참조"),
    _entry(5, 2, _CODE_ERROR, "부적절한 자원 해제"),
    _entry(5, 3, _CODE_ERROR, "해제된 자원 사용"),
    _entry(5, 4, _CODE_ERROR, "초기화되지 않은 변수 사용"),
    _entry(5, 5, _CODE_ERROR, "신뢰할 수 없는 데이터의 역직렬화"),
    _entry(6, 1, _ENCAPSULATION, "잘못된 세션에 의한 데이터 정보 노출"),
    _entry(6, 2, _ENCAPSULATION, "제거되지 않고 남은 디버그 코드"),
    _entry(6, 3, _ENCAPSULATION, "Public 메소드부터 반환된 Private 배열"),
    _entry(6, 4, _ENCAPSULATION, "Private 배열에 Public 데이터 할당"),
    _entry(7, 1, _API_MISUSE, "DNS lookup에 의존한 보안결정"),
    _entry(7, 2, _API_MISUSE, "취약한 API 사용"),
)
