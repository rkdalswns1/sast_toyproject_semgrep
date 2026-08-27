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

`app/rules/`는 규칙 카탈로그와 애플리케이션 로직을 담당하고, `scripts/`는 seed와 관리용 일회성 작업만 담당한다.

## Analysis Flow

```text
ZIP upload → safe extraction → language detection → Semgrep
→ JSON result → normalizer → Finding persistence → result pages
```

분석 엔진과 결과 저장 사이에는 정규화 계층을 둔다. Semgrep 원본 결과는 `raw_result`로 보존한다.

분석은 MVP에서 HTTP 요청 안에서 동기 실행한다. 분석 요청을 받으면 AnalysisRun을 `RUNNING` 상태로 변경하고 Semgrep을 실행한다. 성공하면 `COMPLETED`, 오류 또는 시간초과가 발생하면 `FAILED`로 변경한다.

Semgrep 실행 제한 시간은 기본 60초이며 환경변수로 조정할 수 있다.

## Database Initialization

MVP에서는 Alembic을 사용하지 않는다.

애플리케이션 시작 시 SQLAlchemy `create_all()`을 사용하여 존재하지 않는 테이블을 생성한다.

SQLite 연결마다 foreign key 검사를 활성화한다.

## Request Database Session

Phase 3부터 FastAPI 의존성으로 요청마다 하나의 SQLAlchemy `Session`을 만든다. 요청 처리가 정상적으로 끝나면 라우트 또는 서비스가 의도한 변경만 명시적으로 commit하고, 예외가 발생하면 해당 Session을 rollback한다. 어떤 경우에도 요청 종료 시 Session을 닫으며, Session을 요청 간 또는 백그라운드 작업 간에 공유하지 않는다.

## Explicit Non-goals

MVP에서는 React/Next.js, REST API 전용 구조, 비동기 Queue, Git 연계, 추가 SAST 엔진, Docker 도입을 구현하지 않는다.
