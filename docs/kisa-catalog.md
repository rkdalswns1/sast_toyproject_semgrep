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
