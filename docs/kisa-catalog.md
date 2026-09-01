# KISA Catalog Source Policy

KISA 49개 보안약점 카탈로그의 정확한 ID, 명칭, 설명 및 분류는 사용자가 제공하는 공식 자료를 기준으로 작성한다.

Codex는 공식 자료 없이 항목명, ID 또는 설명을 추측해서 만들지 않는다.

## Required Source Before Phase 8

Phase 8을 시작하기 전에 사용자가 다음 자료를 제공한다.

- KISA 공식 문서 또는 신뢰할 수 있는 원문
- 49개 항목의 ID와 명칭
- 가능한 경우 항목별 설명
- 가능한 경우 항목별 조치 방법

공식 자료가 준비되지 않은 경우 Phase 8 구현을 중단하고 사용자에게 자료를 요청한다.

## Catalog and Detection

다음 두 가지 상태를 구분한다.

1. KISA 카탈로그에 등록되어 있는가
2. 프로그램이 해당 항목을 자동 탐지할 수 있는가

KISA 카탈로그에 존재한다고 해서 자동 탐지가 구현된 것으로 처리하지 않는다.

## Mapping Policy

- 공식 카탈로그의 ID와 명칭을 그대로 사용한다.
- 존재하지 않는 KISA ID를 만들지 않는다.
- Semgrep 규칙과 직접 대응하지 않는 항목은 `NOT_IMPLEMENTED`로 기록한다.
- 일부 경우만 탐지할 수 있다면 `PARTIAL`로 기록한다.
- 실제 탐지와 테스트가 존재하는 경우에만 `IMPLEMENTED`로 기록한다.
- Java, JavaScript, Python 지원 여부를 각각 관리한다.
- Semgrep 규칙 ID와 KISA 항목의 대응 관계를 명시한다.
- 동일 KISA 항목의 언어별 Semgrep 규칙은 각 규칙 metadata의 `kisa_standard_id`로 하나의 카탈로그 항목에 연결한다.
- 공식 가이드의 절 내부 번호를 `item_number`에 저장한다.
- `reference_info`에는 `소프트웨어 보안약점 진단가이드(2021)`와 공식 절·항목을 기록한다.
- 카탈로그 seed 항목은 기본적으로 활성 상태로 등록하되, 비활성화해도 기존 Finding과 이력은 유지한다.
- 언어별 Semgrep Rule ID 연결과 카탈로그 활성 상태 관리는 SUPER_ADMIN만 수행한다.

## Current Automatic Detection Scope

- Java, JavaScript, Python 공통: SQL 삽입, 경로 조작 및 자원 삽입, 크로스사이트 스크립트, 운영체제 명령어 삽입, 위험한 형식 파일 업로드, 부적절한 XML 외부개체 참조, 취약한 암호화 알고리즘 사용, 하드코드된 중요정보, 부적절한 인증서 유효성 검증
- Java, Python: 신뢰할 수 없는 데이터의 역직렬화
- 위 열 항목은 대표 패턴만 자동 탐지하므로 `PARTIAL`이며, 나머지 39개 항목은 `NOT_IMPLEMENTED`를 유지한다.
