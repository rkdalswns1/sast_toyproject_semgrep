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

핵심 6개 도메인 테이블과 스키마 이력용 `schema_versions` 테이블, SQLAlchemy 모델, 초기 테이블 생성 테스트를 만든다. 기존 DB 변경은 `create_all()` 이후 저장소 내부 버전 마이그레이션으로 적용한다.

완료조건: 모든 테이블과 FK, 마이그레이션 이력 및 기존 DB 업그레이드 확인.

## Phase 3 — Authentication

> Phase 3의 `ADMIN`·관리자 비밀번호 초기화 정책은 Phase 10에서 3단계 역할과 본인 비밀번호 변경 정책으로 대체한다. 아래 내용은 최초 구현 이력이다.

서명된 쿠키 세션 로그인·로그아웃, bcrypt 비밀번호 해시, ADMIN / USER 권한 검사를 구현한다. 쿠키에는 `user_id`만 저장하고 사용자 역할과 활성 상태는 요청마다 DB에서 조회한다. Phase 3 시작 시 `bcrypt`, `itsdangerous`, `python-multipart`를 루트 `requirements.txt`에 정확한 버전으로 추가하고, 새 가상환경에서 설치를 확인한다.

FastAPI 의존성으로 요청마다 DB Session을 만들고, 예외 시 rollback·요청 종료 시 close한다. 모든 상태 변경 `POST` 폼(로그인·로그아웃 포함)에 세션 기반 CSRF 토큰을 적용하고, 누락 또는 불일치는 `403`으로 처리한다.

사용자 테이블이 비어 있으면 최초 관리자 `admin@company.com` / `admin`을 한 번만 생성한다. 비밀번호는 bcrypt 해시로만 저장한다. 기존 MVP의 `admin` 식별자는 시작 시 `admin@company.com`으로 전환한다.

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
- `@company.com` 형식 검증과 중복 회사 이메일 생성 차단
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

SEC 검증에는 세션 발급·위변조·만료, 프로젝트 소속 기반 `404`, 프로젝트별 소스 경계, ZIP 경로·링크·암호화 방어, Semgrep 자원·출력·timeout 통제와 외부 구성요소 관리 문서를 포함한다.

TST-001~008은 각각 구현 위치와 독립적인 자동 검증 근거를 가져야 한다. TST-005는 `tests/samples/`의 Java, JavaScript, Python 취약·정상 예제와 `expected_findings.json`을 사용하며, TST-008은 실패 기록을 유지한 상태에서 원인 수정 후 새 분석이 성공하는지 확인한다.

QLT-001~005는 책임별 라우트·서비스 소유권, 진단 항목별 독립 규칙 파일, 공통 언어 registry·분석 흐름·Finding 계약, 프로젝트-실행-결과-Rule 정합성의 자동 구조 시험으로 검증한다.

완료조건: 전체 테스트 통과 및 요구사항 추적표 작성.

## Phase 10 — Role and Password Policy

역할을 `SUPER_ADMIN`, `PROJECT_MANAGER`, `USER`로 개편하고 기존 `ADMIN`은 스키마 마이그레이션으로 `SUPER_ADMIN`으로 변환한다.

- SUPER_ADMIN은 사용자·규칙 관리, 프로젝트 생성 및 모든 프로젝트에 접근한다.
- PROJECT_MANAGER는 할당된 프로젝트의 수정, 사용자 배정, ZIP 업로드, 분석 실행, 분석 오류와 결과 조회를 수행한다.
- USER는 할당된 프로젝트의 분석 이력과 Finding을 읽기 전용으로 조회한다.
- SUPER_ADMIN이 지정한 초기 비밀번호로 생성된 신규 계정은 최초 로그인 후 `/account/password`에서 개인 비밀번호를 반드시 변경한다.
- 이후 사용자는 현재 비밀번호 확인 후 자신의 비밀번호만 변경할 수 있다.
- 기존 ADMIN의 임의 비밀번호 초기화 경로는 제거한다.

완료조건:

- 기존 ADMIN·관계 데이터가 SUPER_ADMIN으로 손실 없이 마이그레이션됨
- 신규 계정의 최초 비밀번호 변경 강제 및 직접 보호 URL 우회 차단
- 본인 비밀번호 변경 시 현재 비밀번호 검증과 bcrypt 해시 교체
- SUPER_ADMIN, 할당된 PROJECT_MANAGER, USER의 역할별 허용·거부 기능 검증
- 미할당 PROJECT_MANAGER와 USER의 프로젝트·분석·Finding 404 유지
- 기존 관리자 비밀번호 초기화 경로 제거
- 전체 자동 테스트와 애플리케이션 기동 확인

## Phase 11 — KISA Diagnostic Rule Expansion

현재 `NOT_IMPLEMENTED`인 KISA 항목 중 Semgrep Community Edition의 로컬 규칙으로 명확하게 표현할 수 있고, Java·JavaScript·Python 취약/정상 고정 샘플로 재현 가능한 항목만 단계적으로 확대한다.

후보 조사 결과와 우선순위는 `phase-11-rule-candidates.md`를 따른다. 공개 Semgrep 규칙은 설계 참고 자료로 사용하되, 실행 중 Registry에서 규칙을 내려받지 않는다. 채택한 규칙은 기존 구조에 맞춰 KISA metadata를 포함한 로컬 YAML로 관리하고 라이선스와 출처를 확인한다.

이 Phase는 다음 순서로 분리한다.

1. 후보 조사와 범위 승인
2. 승인된 1차 후보만 독립 YAML과 언어별 매핑으로 구현
3. 취약·정상 샘플 및 기대 Finding 추가
4. 실제 Semgrep 실행, 오탐 검토와 전체 회귀 시험

승인된 1차 범위는 `제2절-11 부적절한 인증서 유효성 검증`의 Java·JavaScript·Python과 `제5절-5 신뢰할 수 없는 데이터의 역직렬화`의 Java·Python이다. 후보 조사만으로 카탈로그의 구현 상태를 변경하지 않으며, 실제 규칙과 자동 시험이 모두 존재하는 승인 범위만 `PARTIAL`로 전환한다. 지원 언어와 주요 API 범위가 제한되므로 `IMPLEMENTED`로 표시하지 않는다.

완료조건:

- 사용자가 승인한 후보와 언어만 구현됨
- KISA 항목별 독립 YAML 및 고유한 언어별 Rule ID 유지
- 각 언어의 취약 샘플은 기대 Finding을 만들고 정상 샘플은 탐지되지 않음
- 공개 규칙을 참고하거나 변형한 경우 출처와 라이선스 기록
- 기존 8개 진단 항목과 전체 자동 테스트 회귀 없음
- 승인된 두 항목이 언어별 취약 샘플에서 탐지되고 정상 샘플에서는 탐지되지 않음
- 기존 DB는 마이그레이션 버전 7로 상태·지원 언어·대표 Rule ID가 동기화되고 관리자 활성 설정은 보존됨
- 정적 분석으로 신뢰성 있게 판단하기 어려운 항목은 `NOT_IMPLEMENTED` 유지

## Phase 12 — Multi-language Project Analysis

프로젝트는 기존 기준 언어를 유지하면서 `지원 언어 자동 감지 및 통합 분석` 모드를 선택할 수 있다. 통합 분석 모드에서는 업로드된 ZIP에서 Java, JavaScript, Python을 자동 감지하고, 감지된 언어의 활성 규칙을 합쳐 하나의 격리된 Semgrep 프로세스로 실행한다.

Semgrep 프로세스를 언어별로 추가 생성하지 않고 기존 `--jobs` 내부 병렬화를 사용한다. timeout, 메모리, 대상 파일 및 출력 제한은 통합 프로세스 전체에 동일하게 적용한다.

혼합 분석에서도 `AnalysisRun.language`는 프로젝트의 기준 언어를 보존한다. 실제 분석 언어 목록은 `summary.provenance.scanned_languages`에 기록하고, 각 Finding의 언어는 매칭된 활성 `DiagnosticRule`의 언어에서 결정한다. 단일 언어 모드는 기존 동작과 결과 계약을 유지한다.

완료조건:

- 프로젝트 생성·수정에서 단일 언어 또는 자동 감지 통합 분석을 선택할 수 있음
- 기존 프로젝트는 단일 언어 모드를 유지하고 신규 DB·기존 DB 모두 마이그레이션됨
- 혼합 ZIP의 지원 언어를 모두 감지하고 하나의 Semgrep 프로세스로 분석함
- 감지된 언어에 해당하는 활성 규칙만 실행 및 스냅샷에 기록함
- Finding마다 실제 언어별 Rule ID와 일치하는 언어를 저장함
- 분석 상세에서 분석 모드, 감지 언어 및 실제 분석 언어를 확인할 수 있음
- 단일 언어 회귀, 혼합 언어 취약·정상 샘플, timeout·자원 제한 시험 통과
- 비동기 Queue와 언어별 외부 프로세스 병렬 실행은 추가하지 않음

## Phase 13 — Finding Remediation Status

탐지된 Finding의 후속 조치 상태를 관리한다. 상태는 `OPEN`, `IN_PROGRESS`, `RESOLVED`, `FALSE_POSITIVE`, `ACCEPTED_RISK`로 고정하고, 상태 변경 의견·변경 계정·변경 시각을 Finding과 1:1인 워크플로 데이터로 저장한다.

SUPER_ADMIN과 해당 프로젝트에 할당된 PROJECT_MANAGER만 상태를 변경할 수 있다. USER는 상태와 의견을 읽기 전용으로 조회한다. `FALSE_POSITIVE`와 `ACCEPTED_RISK`는 판단 근거를 남기기 위해 의견을 필수로 한다. 이번 Phase는 최신 상태만 관리하며 담당자·조치 기한·상태 변경 전체 이력과 후속 분석 자동 제외는 구현하지 않는다.

분석 실행 계정은 이미 `analysis_runs.executed_by`에 저장되므로 분석 이력과 상세 화면에 표시한다.

완료조건:

- 모든 신규·기존 Finding에 기본 `OPEN` 상태가 존재함
- 운영 권한이 있는 사용자만 상태와 의견을 변경할 수 있음
- 오탐·위험 수용은 의견 없이는 저장되지 않음
- 변경 계정과 변경 시각이 기록되고 화면에 표시됨
- USER 읽기 전용 및 미할당 프로젝트 404 정책 유지
- 분석 이력·상세에 실행 계정 표시
- DB 마이그레이션, CSRF, 권한 및 전체 회귀 시험 통과

## Phase 14 — ZIP Source Metadata

ZIP 소스를 업로드할 때 선택적으로 소스 버전, 배포 버전과 설명을 입력하고 프로젝트의 최신 소스 정보로 저장한다. 현재 MVP는 프로젝트마다 최신 소스 작업공간 하나를 분석 대상으로 사용하므로 별도 업로드 이력 테이블은 추가하지 않는다.

분석 실행 시점의 세 값은 `AnalysisRun.summary.provenance.source_metadata`에 복사한다. 이후 새 ZIP과 메타데이터를 업로드해도 과거 분석 기록의 버전 정보는 변경되지 않는다. 버전 값은 앞뒤 공백을 제거해 각각 최대 100자, 설명은 최대 2,000자로 저장한다. 세 값은 모두 선택 입력이며 ZIP 검증 또는 입력 검증이 실패하면 기존 소스 경로와 메타데이터를 변경하지 않는다.

완료조건:

- SUPER_ADMIN과 담당 PROJECT_MANAGER가 ZIP 업로드 시 소스 버전·배포 버전·설명을 입력할 수 있음
- 입력 길이와 CSRF·프로젝트 권한을 서버에서 검증함
- 기존 프로젝트는 세 값이 없는 상태로 손실 없이 마이그레이션됨
- 프로젝트 상세에 최신 소스 메타데이터가 표시됨
- 분석 실행 이력과 상세에 실행 시점의 소스 메타데이터가 보존·표시됨
- 업로드 실패 시 기존 소스와 메타데이터가 유지됨
- DB 마이그레이션과 전체 회귀 시험 통과

## Phase 15 — Analysis Result Reports

분석 실행 단위로 CSV와 PDF 보고서를 요청 시 메모리에서 생성해 내려받는다. 별도 보고서 파일, 다운로드 이력 또는 신규 DB 컬럼은 저장하지 않는다. 인증된 사용자가 해당 분석의 프로젝트에 접근할 수 있는지 기존 프로젝트 관계로 확인하고, 미할당 프로젝트는 화면 조회와 동일하게 `404`로 처리한다.

CSV는 UTF-8 BOM을 포함한 Finding 1건당 1행의 상세 자료로 구성한다. 프로젝트·분석 정보와 심각도별 집계를 각 행에 포함하고, Finding이 없어도 분석 요약 1행을 제공한다. 스프레드시트 수식 주입을 막기 위해 `=`, `+`, `-`, `@`로 시작하는 외부 유래 셀은 텍스트로 이스케이프한다.

PDF는 고객 보고용 A4 문서로 프로젝트·분석·소스 버전 요약, 심각도별 집계와 Finding 목록을 제공한다. 한글 글꼴을 사용하고 긴 파일 위치·메시지·검토 의견은 페이지 안에서 줄바꿈한다. 두 형식 모두 DB에 정규화된 상대 파일 경로만 사용하며 원본 Semgrep JSON, 근거 코드, 내부 오류와 시스템 절대경로는 포함하지 않는다.

완료조건:

- 분석 상세에서 CSV와 PDF 다운로드 가능
- 두 형식에 요구된 프로젝트·분석·Finding·조치 필드와 심각도별 요약 포함
- Finding 0건과 긴 한글 메시지도 유효한 보고서로 생성됨
- 원본 Semgrep JSON, 시스템 절대경로 및 분석 오류 원문 제외
- SUPER_ADMIN, 담당 PROJECT_MANAGER, 할당 USER는 다운로드 가능
- 미할당 사용자는 CSV와 PDF 모두 `404`
- PDF를 실제 렌더링하여 한글, 줄바꿈, 표와 페이지 번호 확인
- 전체 자동 테스트와 애플리케이션 기동 확인

## Phase 16 — Finding Assignment and Due Date

Finding의 최신 조치 정보에 담당자와 조치 기한을 추가한다. 담당자는 해당 Finding이 속한 프로젝트에 할당된 활성 사용자만 선택할 수 있으며, SUPER_ADMIN과 해당 프로젝트에 할당된 PROJECT_MANAGER만 상태·의견과 함께 변경한다. USER는 담당자와 기한을 읽기 전용으로 조회한다.

조치 기한은 날짜만 저장한다. 기한 초과 여부는 별도 상태로 저장하거나 자동 변경하지 않고, 조회 시 `due_date < 오늘`이면서 상태가 `OPEN` 또는 `IN_PROGRESS`인 경우에만 계산한다. 이메일·알림, 상태 변경 전체 이력과 자동 재할당은 이번 Phase에 포함하지 않는다.

완료조건:

- 기존 FindingWorkflow가 담당자·조치 기한이 없는 상태로 손실 없이 마이그레이션됨
- 담당자는 해당 프로젝트에 할당된 활성 사용자만 지정 가능
- SUPER_ADMIN과 담당 PROJECT_MANAGER만 담당자·기한을 변경 가능
- USER는 담당자·기한·기한 초과 여부를 읽기 전용으로 조회
- Finding 목록에서 담당자와 기한 초과 여부를 필터링 가능
- 완료·오탐·위험 수용 상태는 기한이 지나도 기한 초과로 표시하지 않음
- DB 마이그레이션, CSRF, 권한 및 전체 회귀 시험 통과

## Phase 17 — Finding Revalidation

기존 Finding 상세에서 최신 업로드 소스를 대상으로 새 Semgrep 분석을 실행하고, 새 AnalysisRun의 Finding과 원본 Finding을 비교해 재검증 결과를 기록한다. 비교 기준은 `KISA ID + 언어 + Semgrep Rule ID + 상대 파일 경로`이며 줄 번호 변화는 동일 취약점 판단에 사용하지 않는다.

- 모든 비교 키가 일치하면 `STILL_DETECTED`(여전히 탐지됨)
- 정확히 일치하지 않지만 새 실행에 같은 KISA 항목이 있으면 `REVIEW_REQUIRED`(확인 필요)
- 새 실행에 같은 KISA 항목이 없으면 `LIKELY_RESOLVED`(해결 추정)
- 새 분석이 실패하면 `REVIEW_REQUIRED`

재검증은 기존 Finding의 조치 상태를 자동으로 변경하지 않는다. 해결 추정은 사람이 새 분석과 소스 변경을 확인한 뒤 조치 상태를 변경하기 위한 참고 결과다. 새 분석에서 발견된 다른 취약점은 일반 Finding으로 저장한다. SUPER_ADMIN과 해당 프로젝트에 할당된 PROJECT_MANAGER만 실행하고, 프로젝트 접근 권한이 있는 USER는 재검증 이력을 읽기 전용으로 조회한다.

완료조건:

- 재검증마다 새 AnalysisRun과 원본 Finding 연결, 결과, 실행 계정, 실행 시각 저장
- 동일 위치 재탐지·위치 변경·미탐지·분석 실패 결과 구분
- 재검증 과정의 신규 취약점도 새 AnalysisRun의 일반 Finding으로 보존
- 기존 FindingWorkflow 상태를 자동 변경하지 않음
- SUPER_ADMIN과 담당 PROJECT_MANAGER만 실행 가능하며 CSRF 적용
- USER 읽기 전용 및 미할당 사용자 404 유지
- 기존 DB 마이그레이션, 비교 로직, 권한과 전체 회귀 시험 통과
