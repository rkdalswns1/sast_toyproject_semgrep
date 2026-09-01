# Test Contract

이 문서는 RFP TST-001~008의 시험 데이터, 기대 결과와 실행 방법을 정의한다.

## Isolation

- 모든 자동 테스트는 pytest가 제공하는 임시 SQLite DB와 임시 업로드 디렉터리를 사용한다.
- 개발자의 `.env`, `sast.db`, `uploads/` 및 기존 분석 이력을 변경하지 않는다.
- Semgrep 실행을 대체하는 단위 테스트와 실제 로컬 Semgrep을 실행하는 통합 테스트를 구분한다.
- 실제 Semgrep 테스트는 네트워크 규칙 다운로드 없이 저장소의 `app/rules/semgrep/kisa-2021/` 아래 진단 항목별 규칙만 사용한다.
- 기존 DB 업그레이드 시험은 마이그레이션 버전 4가 확장된 내장 규칙 메타데이터를 갱신하고, 관리자가 선택한 언어별 매핑과 카탈로그 활성 상태를 재시작 후에도 보존하는지 확인한다.
- Phase 10 업그레이드 시험은 기존 `ADMIN`을 `SUPER_ADMIN`으로 변환하고 사용자·프로젝트·분석 관계와 비밀번호 해시를 보존하며 신규 `must_change_password` 컬럼을 기존 계정에 `false`로 설정하는지 확인한다.
- Phase 11 업그레이드 시험은 마이그레이션 버전 7이 인증서 검증과 역직렬화 항목의 구현 상태·지원 언어·대표 Rule ID를 갱신하면서 관리자가 선택한 활성 상태를 보존하는지 확인한다.

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

`expected_findings.json`은 지원 언어별 취약 파일에서 기대하는 KISA 기준 ID, 시작 줄, 심각도와 신뢰도를 고정한다. 취약 예제는 현재 `PARTIAL`로 구현된 열 항목을 지원 언어별로 각각 한 번 포함한다.

- `제1절-1`: SQL 삽입
- `제1절-3`: 경로 조작 및 자원 삽입
- `제1절-4`: 크로스사이트 스크립트
- `제1절-5`: 운영체제 명령어 삽입
- `제1절-6`: 위험한 형식 파일 업로드
- `제1절-8`: 부적절한 XML 외부개체 참조
- `제2절-6`: 하드코드된 중요정보
- `제2절-4`: 취약한 암호화 알고리즘 사용
- `제2절-11`: 부적절한 인증서 유효성 검증(Java, JavaScript, Python)
- `제5절-5`: 신뢰할 수 없는 데이터의 역직렬화(Java, Python)

정상 예제는 매개변수화 쿼리, 경로 정규화, HTML 이스케이프, 업로드 파일명 재생성, 외부 엔티티 비활성화, shell을 사용하지 않는 프로세스 실행, 외부 비밀정보 로딩, SHA-256, 인증서 검증 활성화 및 안전한 데이터 파싱을 사용하며 지원 대상 항목이 탐지되지 않아야 한다.

## Requirement Matrix

| RFP ID | 핵심 검증 | 자동 테스트 |
|---|---|---|
| TST-001 | 세 역할 로그인, 쿠키 발급, 최초 비밀번호 변경 강제, 본인 비밀번호 변경, 미인증 차단 | `tests/test_authentication.py` |
| TST-002 | SUPER_ADMIN 전체 관리, 할당 PROJECT_MANAGER 운영, USER 읽기 전용 | `tests/test_projects.py`, `tests/test_end_to_end.py` |
| TST-003 | 할당 사용자 조회, 미할당 사용자 결과 404 | `tests/test_projects.py`, `tests/test_end_to_end.py` |
| TST-004 | ZIP 수집부터 실제 Semgrep·정규화, 활성 규칙 스냅샷까지 | `tests/test_end_to_end.py`, `tests/test_diagnostic_examples.py`, `tests/test_analysis_execution.py` |
| TST-005 | 취약·정상 예제, 기대 위치·메타데이터 | `tests/test_diagnostic_examples.py` |
| TST-006 | 49개 전체 필수 필드와 구현 상태 | `tests/test_rule_catalog.py` |
| TST-007 | 상태·저장·필터·상세·Rule FK·상대경로 정규화 | `tests/test_findings.py`, `tests/test_rule_catalog.py`, `tests/test_end_to_end.py` |
| TST-008 | 잘못된 대상·실행 오류·수정 후 재실행 | `tests/test_analysis_execution.py` |

실행 오류 시험은 Semgrep의 제한된 표준 오류가 실패 실행에 저장되는지, 오류 로그 상한을 초과하면 프로세스 그룹이 종료되는지, 저장된 원문이 SUPER_ADMIN과 해당 프로젝트의 PROJECT_MANAGER에게만 표시되는지를 포함한다.

SEC-007 시험은 프로젝트별 소스 경계, 분석별 작업공간 생성·삭제와 Semgrep에 애플리케이션 비밀 환경변수가 전달되지 않는지를 검증한다.

SFR-012 등록 시험은 SUPER_ADMIN의 KISA 항목·언어별 Semgrep Rule ID 등록과 수정, DB 지속성, PROJECT_MANAGER·USER 접근 차단 및 중복 Rule ID 거부를 검증한다. YAML의 문법과 탐지 동작은 실제 Semgrep 진단 예제 시험이 담당한다.

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

1. SUPER_ADMIN이 PROJECT_MANAGER와 USER 계정을 생성하고 두 신규 계정이 최초 로그인 후 개인 비밀번호를 변경하는지 확인한다.
2. SUPER_ADMIN은 모든 프로젝트를 조회하고 PROJECT_MANAGER는 할당된 프로젝트에서만 수정·사용자 배정·ZIP 업로드·분석 실행을 할 수 있는지 확인한다.
3. USER 화면에는 프로젝트 생성·수정, 사용자 할당, ZIP 업로드와 분석 실행 기능이 없는지 확인한다.
4. SUPER_ADMIN 또는 담당 PROJECT_MANAGER로 취약 샘플 ZIP을 업로드하고 분석한다.
5. 분석 상태가 COMPLETED이고 Finding의 기준 ID, 파일, 줄, 심각도와 신뢰도가 기대 결과와 일치하는지 확인한다.
6. 심각도와 신뢰도 필터를 적용하고 Finding 상세에서 원본 결과와 Rule 기준 정보를 확인한다.
7. 프로젝트 언어와 다른 소스 ZIP을 분석하여 FAILED와 역할별 오류 표시를 확인한다.
8. 올바른 ZIP으로 교체해 다시 분석하고 새 실행은 COMPLETED, 이전 실패 실행은 이력에 남는지 확인한다.
