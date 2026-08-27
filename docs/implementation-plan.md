# Implementation Plan

## Phase 1 — Bootstrap

FastAPI 실행, Jinja2 설정, 환경변수 로딩, SQLite 연결, SQLAlchemy Base, `create_all()`, 기본 디렉터리 및 health check를 만든다.

Python 패키지 버전을 루트 `requirements.txt`에 고정하고 `.env.example`을 제공한다.

완료조건:

- 서버 실행
- `/health` 정상 응답
- DB 파일 생성
- `.env.example` 생성
- `requirements.txt` 버전 고정
- 실제 `.env`가 Git에서 제외됨

## Phase 2 — Database

6개 테이블과 SQLAlchemy 모델, 초기 테이블 생성 테스트를 만든다.

완료조건: 모든 테이블과 FK 확인.

## Phase 3 — Authentication

서명된 쿠키 세션 로그인·로그아웃, bcrypt 비밀번호 해시, ADMIN / USER 권한 검사를 구현한다. 쿠키에는 `user_id`만 저장하고 사용자 역할과 활성 상태는 요청마다 DB에서 조회한다. Phase 3 시작 시 `bcrypt`, `itsdangerous`, `python-multipart`를 루트 `requirements.txt`에 정확한 버전으로 추가하고, 새 가상환경에서 설치를 확인한다.

FastAPI 의존성으로 요청마다 DB Session을 만들고, 예외 시 rollback·요청 종료 시 close한다. 모든 상태 변경 `POST` 폼(로그인·로그아웃 포함)에 세션 기반 CSRF 토큰을 적용하고, 누락 또는 불일치는 `403`으로 처리한다.

사용자 테이블이 비어 있으면 최초 관리자 `admin` / `admin`을 한 번만 생성한다. 비밀번호는 bcrypt 해시로만 저장한다.

ADMIN 전용 사용자 관리 기능을 구현한다.

- 사용자 목록
- 사용자 생성
- 사용자 역할 수정
- 사용자 활성화·비활성화
- ADMIN이 새 비밀번호와 확인값을 입력하는 비밀번호 초기화
- 사용자 물리 삭제 금지
- 자기 자신 비활성화 금지
- 마지막 활성 ADMIN 비활성화 및 USER 역할 변경 금지
- 임시 비밀번호 자동 생성 및 이메일 발송 제외

마지막 활성 ADMIN 보호는 서비스 계층의 하나의 쓰기 트랜잭션 안에서 대상 사용자 상태와 활성 ADMIN 수를 확인한 뒤 변경한다. 비활성화와 USER 역할 변경 모두 이 정책을 적용한다.

완료조건:

- 최초 관리자 자동 생성
- 평문 비밀번호가 DB에 저장되지 않음
- 로그인 성공·실패 테스트 통과
- 역할 제한 테스트 통과
- 일반 USER의 사용자 관리 접근 차단
- 중복 username 생성 차단
- 비밀번호 초기화 시 bcrypt 해시 저장
- 자기 자신과 마지막 활성 ADMIN 보호
- CSRF 누락·위조 POST 요청이 403으로 거부됨
- DB Session rollback 및 close 동작 테스트 통과

## Phase 4 — Projects

프로젝트 CRUD, 프로젝트 사용자 할당, 접근 권한 검사를 구현한다.

완료조건: 프로젝트 CRUD 및 사용자별 접근 테스트 통과.

## Phase 5 — Source Upload

ZIP 업로드, 크기 제한, 안전한 압축 해제, 작업 디렉터리 격리를 구현한다.

완료조건: 정상 ZIP 처리와 ZIP Slip·심볼릭 링크 차단 테스트 통과.

## Phase 6 — Semgrep

Semgrep subprocess 실행, timeout, JSON 수집, 실행 상태 전이를 구현한다.

완료조건: 성공·실패·timeout 상태 테스트 통과.

## Phase 7 — Findings

Semgrep 결과 정규화, DB 저장, 목록·상세·severity 필터를 구현한다.

완료조건: 위치·메타데이터·원본 결과 확인 테스트 통과.

## Phase 8 — Rules

사용자가 제공한 공식 자료를 기준으로 KISA 49개 카탈로그, 구현 상태 및 Semgrep 규칙 매핑을 seed한다.

공식 자료가 없으면 카탈로그 정보를 추측하지 않고 Phase를 중단한 뒤 사용자에게 자료를 요청한다.

완료조건:

- 공식 자료와 DB seed 내용 일치
- 49개 항목 등록 확인
- 구현 상태 조회 테스트 통과
- 언어별 지원 상태 확인

## Phase 9 — Verification

인증, 권한, 업로드 보안, 분석, 결과 관리, 오류 처리를 통합 검증한다.

완료조건: 전체 테스트 통과 및 요구사항 추적표 작성.
