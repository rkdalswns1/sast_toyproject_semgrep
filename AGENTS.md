# Project Instructions

## Goal

정적 애플리케이션 보안 테스트 프로그램의 요구사항을 충족하는 최소 기능을 구현한다.

## Fixed Decisions

- Backend: FastAPI
- Frontend: Jinja2 server-rendered pages
- ORM: SQLAlchemy 2.x
- Database: SQLite for MVP
- SAST engine: Semgrep
- Source input: ZIP upload only
- Authentication: signed cookie session
- Roles: ADMIN and USER
- Test framework: pytest
- Python: 3.12
- Database initialization: SQLAlchemy `create_all()`
- Schema history: repo-local ordered migrations recorded in `schema_versions`
- Configuration: environment variables loaded from `.env`
- Account identifier: company email ending in `@company.com`
- Bootstrap administrator: `admin@company.com` / `admin`, password stored as bcrypt hash
- Semgrep timeout: 60 seconds
- Session secret: at least 32 bytes and never the example placeholder
- Semgrep resource limits: 2 jobs, 1,024 MiB memory, 1,000,000-byte target, 20 MiB JSON output

## Rules

1. `docs/`의 문서를 구현 기준으로 삼는다.
2. 한 번에 하나의 Phase만 구현한다.
3. 요구사항에 없는 기능과 의존성을 추가하지 않는다.
4. React, Next.js, Redis, Celery, WebSocket, 추가 SAST 엔진은 도입하지 않는다.
5. 업로드 파일은 신뢰하지 않고 ZIP Slip, 심볼릭 링크, 경로 탈출을 방어한다.
6. 분석 실행에는 timeout과 작업 영역 격리를 적용한다.
7. 각 Phase 완료 후 관련 테스트와 실행 확인을 수행한다.
8. 설계 변경이 필요하면 먼저 문서를 수정하고 승인을 받는다.
9. Enum, 환경변수 및 업로드 제한은 `docs/configuration.md`를 따른다.
10. UI 구현은 `docs/ui-design.md`와 제공된 디자인 자료를 따른다.
11. KISA 카탈로그는 `docs/kisa-catalog.md`를 따른다.
12. KISA 49개 항목은 사용자가 제공한 공식 자료 없이 추측하여 작성하지 않는다.
13. Python 패키지 버전은 루트 `requirements.txt`에 고정한다.
14. ZIP 소스 업로드, 프로젝트 변경, 분석 실행 및 분석 오류 원문 조회는 ADMIN만 수행한다.
15. 일반 USER는 할당된 프로젝트의 분석 이력과 Finding만 읽기 전용으로 조회한다.
16. `create_all()` 이후 `app/db/migrations.py`의 버전 마이그레이션을 적용하고 성공한 버전을 `schema_versions`에 기록한다.
17. 보안 통제와 외부 구성요소 관리 절차는 `docs/security.md`를 따른다.
18. RFP 시험 기준, 정상·취약 샘플 및 기대 결과는 `docs/testing.md`와 `tests/samples/`를 따른다.
19. 모듈 소유권, 진단 항목 독립성, 확장 및 데이터 정합성은 `docs/quality.md`를 따른다.

## First Instruction

Read this file and every file under `docs/`. Implement only the Phase explicitly requested by the user. After implementation, report changed files, tests, and verification results, then stop.
