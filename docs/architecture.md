# Architecture

## Stack

- FastAPI
- Jinja2
- SQLAlchemy 2.x
- SQLite
- Semgrep
- pytest

Python 패키지의 정확한 버전은 프로젝트 루트의 `requirements.txt`에서 관리한다.

## Directory Boundaries

```text
app/
├── main.py
├── db/
├── auth/
├── projects/
├── analysis/
├── findings/
├── rules/
├── templates/
└── static/
tests/
scripts/
uploads/
```

`app/auth/`, `app/projects/`, `app/analysis/`, `app/findings/`, `app/rules/`는 각각 인증, 프로젝트, 분석 실행, 정규화 결과, 진단 항목의 서비스와 라우트를 소유한다. 프로젝트 접근 검사는 `app/projects/access.py`를 공유하되 분석과 Finding URL 라우트는 각 책임 모듈에 둔다.

`app/rules/semgrep/kisa-2021/`는 KISA 진단 항목마다 개발자가 관리하는 독립 YAML 파일 하나를 두고, `scripts/`는 seed와 관리용 일회성 작업만 담당한다. 웹 애플리케이션은 YAML을 해석하지 않고 SUPER_ADMIN이 입력한 언어별 Semgrep Rule ID와 KISA 카탈로그의 연결만 DB에 저장한다. 세부 품질·확장 계약은 `quality.md`를 따른다.

## Authorization Model

- `SUPER_ADMIN`은 계정·규칙·프로젝트 생성과 모든 프로젝트 자원에 접근한다.
- `PROJECT_MANAGER`는 `project_users`로 할당된 프로젝트의 정보 수정, 사용자 배정, ZIP 업로드 또는 공개 GitHub 소스 수집, 분석 실행과 오류 원문 조회를 수행한다.
- `USER`는 `project_users`로 할당된 프로젝트의 분석 이력과 Finding을 읽기 전용으로 조회한다.
- 신규 계정은 `must_change_password=true`로 생성하며 최초 로그인 후 본인이 현재 초기 비밀번호를 확인하고 새 비밀번호로 변경하기 전까지 다른 보호 기능에 접근하지 못한다.

## Analysis Flow

```text
(ZIP upload 또는 public GitHub archive download) → safe extraction → source summary confirmation
→ registered-language detection → Semgrep
→ JSON result → normalizer → Finding persistence → result pages
```

분석 엔진과 결과 저장 사이에는 정규화 계층을 둔다. Semgrep 원본 결과는 `raw_result`로 보존한다.

CWE는 언어별 Semgrep Rule ID인 DiagnosticRule에 연결하고 분석 시 Finding에 복사한다. 따라서 KISA 항목 하나에 언어별로 다른 CWE를 둘 수 있으며, 규칙 관리 정보가 바뀌어도 과거 Finding·보고서의 CWE와 조치 권고는 유지된다.

Finding의 탐지 원본과 조치 관리는 분리한다. `FindingWorkflow`는 최신 상태·의견·담당자·기한만 보관하고, 기한 초과 여부는 조회 시 현재 날짜와 상태로 계산한다.

Finding 재검증은 기존 분석 파이프라인을 재사용하여 항상 새 AnalysisRun과 Finding을 만든다. 원본과 새 결과의 비교 이력은 `FindingRevalidation`에 저장하고 원본 Finding 및 FindingWorkflow는 수정하지 않는다.

업로드 소스 요약은 안전한 압축 해제가 끝난 staging 영역의 실제 정규 파일로 계산한다. Project에는 현재 소스의 제한된 요약만 저장하며 원본 ZIP 파일명에서 경로 성분을 제거하고 모든 파일 위치는 소스 루트 기준 상대경로로 제한한다. 요약은 소스 경로·버전 메타데이터와 함께 교체되며 별도 업로드 이력을 만들지 않는다.

CSV와 PDF 보고서는 AnalysisRun, Project, Finding, FindingWorkflow를 읽어 공통 보고서 스냅샷으로 변환한 뒤 요청 시 메모리에서 생성한다. 보고서 생성은 DB를 변경하지 않으며 원본 Semgrep JSON과 시스템 경로를 출력 계층에 전달하지 않는다.

분석은 MVP에서 HTTP 요청 안에서 동기 실행한다. 분석 요청을 받으면 AnalysisRun을 `RUNNING` 상태로 변경하고 Semgrep을 실행한다. 성공하면 `COMPLETED`, 오류 또는 시간초과가 발생하면 `FAILED`로 변경한다.

Semgrep 실행 제한 시간은 기본 60초이며 환경변수로 조정할 수 있다. 동시 작업 수, 규칙별 메모리, 대상 파일 크기와 JSON 출력 크기도 제한한다. 실행 프로세스는 별도 프로세스 그룹에서 시작하고 timeout 또는 출력 제한 초과 시 그룹 전체를 종료한다.

저장된 소스 경로는 DB 값을 그대로 신뢰하지 않고 `uploads/projects/{project_id}/sources/` 하위인지 다시 검증한다. 분석마다 소유자 전용 임시 작업 디렉터리를 만들고 정규 파일만 복사하며, 성공·실패와 관계없이 실행 후 삭제한다.

Semgrep 자식 프로세스는 애플리케이션 환경 전체를 상속하지 않으며 HOME, 임시 및 캐시 위치를 분석별 작업공간으로 제한한다.

지원 언어의 표시명, 확장자 및 Semgrep 언어명은 중앙 language registry에서 관리한다. 프로젝트 폼과 분석 전 언어 식별은 같은 registry를 참조한다. 프로젝트는 기준 언어와 `scan_all_languages` 설정을 저장한다. 단일 언어 모드는 기준 언어만 분석하고, 통합 분석 모드는 ZIP에서 감지된 모든 지원 언어를 하나의 Semgrep 프로세스로 분석한다. 새 언어는 공통 분석 흐름이나 Finding 모델을 복제하지 않고 registry와 해당 Semgrep 규칙을 추가하여 확장한다.

Semgrep의 `--jobs`가 하나의 실행 내부에서 대상 파일을 병렬 처리한다. 언어별 Semgrep 프로세스를 별도로 실행하지 않으므로 실행 상태, timeout, 출력 제한과 JSON 결과는 한 AnalysisRun에서 원자적으로 관리한다. 혼합 분석의 Finding 언어는 매칭된 활성 DiagnosticRule의 언어에서 결정하며, 부모 AnalysisRun의 `language`는 프로젝트 기준 언어를 보존한다.

각 AnalysisRun의 `summary.provenance`에는 다음 재현성 정보를 기록한다.

- 분석에 사용한 소스 스냅샷의 업로드 루트 기준 상대 경로
- 정렬된 소스 트리의 SHA-256
- Semgrep 버전
- 로컬 규칙 세트 SHA-256
- 분석 시점에 활성화된 언어별 Rule ID·KISA ID·명칭·심각도 목록과 해당 목록의 SHA-256
- 식별된 소스 언어
- 실제 분석한 언어와 단일·통합 분석 모드
- 분석 실행 시점의 소스 버전·배포 버전·설명과 수집 방식·저장소 URL·ref·commit SHA

## Database Initialization

MVP에서는 Alembic을 사용하지 않는다.

애플리케이션 시작 시 SQLAlchemy `create_all()`을 사용하여 존재하지 않는 테이블을 생성한 뒤, `app/db/migrations.py`의 순서가 고정된 경량 마이그레이션을 적용한다.

적용이 완료된 버전, 설명 및 적용 시각은 `schema_versions`에 기록한다. 동일한 버전은 다시 실행하지 않는다. 기존 SQLite DB의 컬럼 추가는 마이그레이션이 담당하며, 신규 DB는 최신 모델로 생성한 후 같은 버전을 이력으로 기록한다.

SQLite 연결마다 foreign key 검사를 활성화한다.

프로젝트 삭제는 SUPER_ADMIN 전용 서비스가 처리한다. DB의 연쇄 삭제로 프로젝트 하위 데이터를 정리하고, 소스 파일은 저장된 경로 문자열을 사용하지 않고 설정된 업로드 루트와 프로젝트 ID로 전용 디렉터리를 계산해 제거한다.

## Request Database Session

Phase 3부터 FastAPI 의존성으로 요청마다 하나의 SQLAlchemy `Session`을 만든다. 요청 처리가 정상적으로 끝나면 라우트 또는 서비스가 의도한 변경만 명시적으로 commit하고, 예외가 발생하면 해당 Session을 rollback한다. 어떤 경우에도 요청 종료 시 Session을 닫으며, Session을 요청 간 또는 백그라운드 작업 간에 공유하지 않는다.

## Explicit Non-goals

MVP에서는 React/Next.js, REST API 전용 구조, 비동기 Queue, Git clone·비공개 저장소 인증 연계, 추가 SAST 엔진, Docker 도입을 구현하지 않는다.
