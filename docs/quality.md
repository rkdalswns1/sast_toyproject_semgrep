# Quality Contract

이 문서는 RFP QLT-001~005를 코드 구조와 검증 가능한 불변조건으로 고정한다.

## Module Ownership

| 모듈 | 소유 책임 |
|---|---|
| `app/auth/` | 로그인·로그아웃, 세션, CSRF, 비밀번호, 사용자 및 역할 정책 |
| `app/projects/` | 프로젝트 CRUD, 사용자 할당, 소스 작업공간과 프로젝트 접근 경계 |
| `app/analysis/` | 언어 registry, Semgrep 실행, AnalysisRun 생명주기와 분석 화면 라우트 |
| `app/rules/` | KISA 카탈로그, seed 및 진단 항목별 Semgrep 규칙 |
| `app/findings/` | Semgrep 결과 정규화, Finding 저장·필터·상세 화면 라우트 |
| `app/db/` | SQLAlchemy 모델, 세션, FK 설정과 스키마 변경 이력 |

프로젝트 접근 검사는 `app/projects/access.py`가 공유한다. URL 구조는 책임 분리와 독립적이며 분석·Finding URL을 변경하지 않는다.

## Independent Diagnostic Items

Semgrep 규칙은 `app/rules/semgrep/kisa-2021/` 아래에 KISA 진단 항목별 YAML 파일 하나로 관리한다. 한 파일은 동일한 기준 ID의 언어별 규칙만 포함한다.

진단 항목을 추가하거나 변경할 때는 다음 범위만 수정한다.

1. 공식 자료에 근거한 `app/rules/catalog.py` 항목과 구현 상태
2. 해당 항목의 독립 YAML 파일과 언어별 규칙
3. `tests/samples/`의 고정 취약·정상 예제 및 `expected_findings.json`

개발자는 YAML을 작성·시험하여 규칙 디렉터리에 배치한다. 웹 애플리케이션은 YAML을 해석하지 않으며, SUPER_ADMIN이 입력한 KISA 항목·언어·Semgrep Rule ID 연결을 `diagnostic_rules`에 저장한다. 같은 KISA 항목과 언어 및 같은 Semgrep Rule ID의 중복은 DB 제약으로 방지한다.

공통 분석 실행 서비스나 Finding 모델을 항목별로 복제하지 않는다. AnalysisRun의 규칙 세트 SHA-256은 규칙 디렉터리의 상대 경로와 파일 내용을 정렬하여 계산하므로 어느 파일이 변경되어도 실행 이력에 반영된다.

## Extension Contract

새 언어를 추가할 때는 `Language` Enum, 중앙 language registry, 해당 진단 항목의 언어별 규칙과 고정 시험 데이터를 추가한다. ZIP 수집, AnalysisRun 상태 전이, Semgrep JSON 수집, Finding 정규화 및 결과 화면은 그대로 재사용한다.

새 진단 기준을 추가할 때는 별도 카탈로그와 규칙 디렉터리를 추가하되 공통 AnalysisRun과 Finding 형식을 유지한다. MVP 분석 엔진은 Semgrep 하나로 고정한다.

## Common Finding Contract

모든 엔진 결과는 저장 전에 다음 공통 필드로 정규화한다.

- 분석 실행 및 Rule FK
- 분석 시점의 Rule 이름, 기준 ID와 언어
- 심각도와 신뢰도
- 상대 파일 경로, 시작·종료 줄과 열
- 메시지, 근거 코드와 권고
- 정규화 전 Semgrep 단일 결과 객체

절대 작업 경로와 경로 탈출 결과는 저장하지 않는다. `Finding.file_path`와 `Finding.raw_result.path`는 모두 업로드 소스 루트 기준 상대경로로 정규화한다. 그 밖의 Semgrep 단일 결과 필드는 원본 구조를 유지한다. 카탈로그에 매핑되지 않은 Semgrep 결과는 임의 Rule을 생성하지 않고 제외한다.

## Consistency Invariants

- AnalysisRun은 유효한 Project와 실행자에 연결되며 실행 시작 시 Project 언어를 스냅샷으로 저장한다.
- 단일 언어와 통합 분석 모두 Finding 언어는 Semgrep Rule ID와 일치하는 활성 DiagnosticRule에서 파생하며 호출자가 임의 값으로 지정하지 않는다.
- Finding은 실제 분석 언어에 해당하고 카탈로그 Rule이 지원하는 활성 DiagnosticRule에만 연결한다.
- Finding의 Rule 이름, 기준 ID, 언어, 심각도와 신뢰도는 분석 시점 스냅샷으로 보존한다.
- FindingWorkflow는 Finding과 1:1이며 탐지 원본을 수정하지 않고 후속 조치 상태만 분리해 저장한다.
- Project의 소스 메타데이터는 최신 ZIP을 나타내고 AnalysisRun provenance에는 실행 시점 값을 복사하여 이후 업로드와 독립적으로 보존한다.
- CSV와 PDF는 같은 불변 보고서 스냅샷을 사용하여 필드와 집계가 형식별로 달라지지 않게 한다. 보고서 생성은 분석 원본과 DB 상태를 변경하지 않는다.
- Project 삭제 시 하위 AnalysisRun과 Finding은 함께 삭제하고, 참조 중인 사용자와 Rule 삭제는 FK 정책으로 제한한다.
- SQLite 연결마다 FK 검사를 활성화하며 저장 트랜잭션이 실패하면 전체 변경을 rollback한다.

## Verification

```bash
.venv/bin/pytest -q tests/test_quality_architecture.py
.venv/bin/pytest -q tests/test_diagnostic_examples.py tests/test_database_schema.py
.venv/bin/pytest -q
```
