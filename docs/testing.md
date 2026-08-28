# Test Contract

이 문서는 RFP TST-001~008의 시험 데이터, 기대 결과와 실행 방법을 정의한다.

## Isolation

- 모든 자동 테스트는 pytest가 제공하는 임시 SQLite DB와 임시 업로드 디렉터리를 사용한다.
- 개발자의 `.env`, `sast.db`, `uploads/` 및 기존 분석 이력을 변경하지 않는다.
- Semgrep 실행을 대체하는 단위 테스트와 실제 로컬 Semgrep을 실행하는 통합 테스트를 구분한다.
- 실제 Semgrep 테스트는 네트워크 규칙 다운로드 없이 저장소의 `app/rules/semgrep/kisa-2021/` 아래 진단 항목별 규칙만 사용한다.

## Diagnostic Samples

```text
tests/samples/
├── expected_findings.json
├── python/
│   ├── vulnerable.py
│   └── safe.py
├── java/
│   ├── Vulnerable.java
│   └── Safe.java
└── javascript/
    ├── vulnerable.js
    └── safe.js
```

`expected_findings.json`은 지원 언어별 취약 파일에서 기대하는 KISA 기준 ID, 시작 줄, 심각도와 신뢰도를 고정한다. 취약 예제는 현재 `PARTIAL`로 구현된 네 항목을 각각 한 번 포함한다.

- `제1절-1`: SQL 삽입
- `제1절-5`: 운영체제 명령어 삽입
- `제2절-6`: 하드코드된 중요정보
- `제2절-4`: 취약한 암호화 알고리즘 사용

정상 예제는 매개변수화 쿼리, shell을 사용하지 않는 프로세스 실행, 외부 비밀정보 로딩 및 SHA-256을 사용하며 위 네 항목이 탐지되지 않아야 한다.

## Requirement Matrix

| RFP ID | 핵심 검증 | 자동 테스트 |
|---|---|---|
| TST-001 | ADMIN·USER 로그인, 쿠키 발급, 미인증 차단 | `tests/test_authentication.py` |
| TST-002 | USER 쓰기·분석·권한 변경 차단, ADMIN 허용 | `tests/test_projects.py`, `tests/test_end_to_end.py` |
| TST-003 | 할당 사용자 조회, 미할당 사용자 결과 404 | `tests/test_projects.py`, `tests/test_end_to_end.py` |
| TST-004 | ZIP 수집부터 실제 Semgrep·정규화까지 | `tests/test_end_to_end.py`, `tests/test_diagnostic_examples.py` |
| TST-005 | 취약·정상 예제, 기대 위치·메타데이터 | `tests/test_diagnostic_examples.py` |
| TST-006 | 49개 전체 필수 필드와 구현 상태 | `tests/test_rule_catalog.py` |
| TST-007 | 상태·저장·필터·상세·Rule FK | `tests/test_findings.py`, `tests/test_end_to_end.py` |
| TST-008 | 잘못된 대상·실행 오류·수정 후 재실행 | `tests/test_analysis_execution.py` |

## Commands

전체 시험:

```bash
.venv/bin/pytest -q
```

RFP TST 핵심 시험:

```bash
.venv/bin/pytest -q \
  tests/test_authentication.py \
  tests/test_projects.py \
  tests/test_end_to_end.py \
  tests/test_diagnostic_examples.py \
  tests/test_rule_catalog.py \
  tests/test_findings.py \
  tests/test_analysis_execution.py
```

## Manual Acceptance

1. ADMIN과 할당된 USER로 각각 로그인한다.
2. USER 화면에는 프로젝트 생성·수정, 사용자 할당, ZIP 업로드와 분석 실행 기능이 없는지 확인한다.
3. ADMIN으로 취약 샘플 ZIP을 업로드하고 분석한다.
4. 분석 상태가 COMPLETED이고 네 Finding의 기준 ID, 파일, 줄, 심각도와 신뢰도가 기대 결과와 일치하는지 확인한다.
5. 심각도와 신뢰도 필터를 적용하고 Finding 상세에서 원본 결과와 Rule 기준 정보를 확인한다.
6. 프로젝트 언어와 다른 소스 ZIP을 분석하여 FAILED와 안전한 오류 안내를 확인한다.
7. 올바른 ZIP으로 교체해 다시 분석하고 새 실행은 COMPLETED, 이전 실패 실행은 이력에 남는지 확인한다.
