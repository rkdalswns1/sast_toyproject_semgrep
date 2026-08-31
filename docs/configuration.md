# Configuration Contract

이 문서는 구현 시 사용하는 고정 설정, Enum, 환경변수 및 보안 제한을 정의한다.

## Runtime and Dependencies

- Python: 3.12
- Python 패키지의 정확한 버전은 프로젝트 루트의 `requirements.txt`에 고정한다.
- Semgrep 버전도 `requirements.txt`에 고정한다.
- DB 테이블은 SQLAlchemy `create_all()`로 생성한다.
- MVP에서는 Alembic을 사용하지 않는다.
- `create_all()`이 기존 테이블을 변경하지 못하는 한계를 보완하기 위해 저장소 내부의 순차 마이그레이션을 사용하고 `schema_versions`에 적용 이력을 저장한다.

`docs/requirements.md`는 기능 요구사항 문서이며 Python 패키지 버전을 관리하는 파일이 아니다.

## Environment Variables

Phase 1에서 프로젝트 루트에 `.env.example`을 생성한다. 실제 `.env`는 Git에 커밋하지 않는다.

| 환경변수 | 필수 | 개발 기본값 | 용도 |
|---|---:|---|---|
| `APP_ENV` | 아니요 | `development` | 실행 환경 |
| `DATABASE_URL` | 아니요 | `sqlite:///./sast.db` | DB 연결 주소 |
| `SESSION_SECRET` | 예 | 없음 | 세션 보호용 비밀값 |
| `ACCOUNT_EMAIL_DOMAIN` | 아니요 | `company.com` | 로그인 계정에 허용할 사내 이메일 도메인 |
| `UPLOAD_DIR` | 아니요 | `./uploads` | 업로드 저장 위치 |
| `MAX_UPLOAD_BYTES` | 아니요 | `20971520` | ZIP 최대 20 MiB |
| `MAX_EXTRACTED_BYTES` | 아니요 | `104857600` | 압축 해제 후 최대 100 MiB |
| `MAX_ARCHIVE_FILES` | 아니요 | `2000` | ZIP 내부 최대 파일 수 |
| `MAX_SINGLE_FILE_BYTES` | 아니요 | `10485760` | 개별 파일 최대 10 MiB |
| `SEMGREP_TIMEOUT_SECONDS` | 아니요 | `60` | Semgrep 실행 제한 시간 |
| `SEMGREP_JOBS` | 아니요 | `2` | Semgrep 동시 분석 작업 수 |
| `SEMGREP_MAX_MEMORY_MB` | 아니요 | `1024` | Semgrep 규칙별 최대 메모리 MiB |
| `SEMGREP_MAX_TARGET_BYTES` | 아니요 | `1000000` | Semgrep이 스캔할 개별 대상 파일 최대 크기 |
| `MAX_SEMGREP_OUTPUT_BYTES` | 아니요 | `20971520` | Semgrep JSON 출력 최대 20 MiB |
| `MAX_SEMGREP_ERROR_BYTES` | 아니요 | `65536` | ADMIN 확인용 Semgrep 오류 로그 최대 64 KiB |

`SESSION_SECRET`은 코드에 기본값을 두지 않고 UTF-8 기준 최소 32바이트를 요구한다. `.env.example`의 예시 문자열은 실제 비밀키로 사용할 수 없다. 테스트에서는 별도 테스트 값을 주입한다. 새 비밀키는 다음과 같이 생성할 수 있다.

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

## Authentication Session

- 세션 방식은 서명된 쿠키 세션을 사용한다.
- 쿠키에는 인증된 사용자의 `user_id`만 저장한다.
- 비밀번호, 역할, 사용자명 등은 쿠키에 저장하지 않고 요청마다 DB에서 조회한다.
- `SESSION_SECRET`으로 쿠키의 위변조를 방지한다.
- 쿠키에는 `HttpOnly`와 `SameSite=Lax`를 적용한다.
- 세션 유효시간은 8시간이다.
- `Secure`는 운영 환경에서 활성화하고 로컬 HTTP 개발 환경에서는 비활성화한다.
- 로그아웃 시 세션 쿠키를 제거한다.

## CSRF Protection

Phase 3부터 로그인, 로그아웃을 포함한 모든 상태 변경 `POST` 폼은 CSRF 토큰을 사용한다. 토큰은 서명된 세션 안에 발급·보관하고, Jinja2 폼의 hidden input으로 전송한다. 서버는 비교 시 누락되거나 유효하지 않은 토큰을 `403`으로 거부한다.

## Enum Values

DB에는 아래 문자열을 대문자로 저장한다.

```text
UserRole: ADMIN, USER
AnalysisStatus: PENDING, RUNNING, COMPLETED, FAILED
ImplementationStatus: IMPLEMENTED, PARTIAL, NOT_IMPLEMENTED
Severity: INFO, LOW, MEDIUM, HIGH, CRITICAL
Confidence: LOW, MEDIUM, HIGH
Language: JAVA, JAVASCRIPT, PYTHON
SourceType: ZIP
```

Python에서는 `str, Enum`을 상속한 Enum으로 정의한다. SQLAlchemy 모델, 폼 검증, 필터 및 테스트는 동일한 Enum 정의를 사용한다.

`rules.supported_languages`는 JSON 배열로 저장하되, 배열의 각 값은 `Language` Enum 값만 허용한다. SQLAlchemy의 변경 추적을 적용해 배열 항목 추가·삭제도 저장된다.

`diagnostic_rules.language`도 `Language` Enum 값을 사용한다. 같은 KISA 카탈로그 항목에는 언어별 Semgrep Rule ID를 하나씩만 연결하고, Semgrep Rule ID는 전체에서 중복될 수 없다.

## Bootstrap Administrator

```text
username: admin@company.com
password: admin
role: ADMIN
is_active: true
```

애플리케이션 시작 시 사용자 테이블이 비어 있으면 최초 관리자 계정을 한 번만 생성한다.

기존 MVP DB에 `admin` 계정이 남아 있으면 시작 시 `admin@company.com`으로 한 번 전환한다.

비밀번호는 bcrypt로 해시하여 `password_hash`에만 저장한다. 평문 비밀번호를 DB 또는 로그에 기록하지 않는다.

기본 계정은 로컬 MVP 및 시연용이다. 외부에 공개되는 환경에서는 초기 비밀번호를 변경해야 한다.

## Account Identifier Policy

- 로그인 계정 식별자는 이메일 형식이어야 한다.
- 기본 허용 도메인은 정확히 `@company.com`이다.
- 로컬 파트는 영문자, 숫자, `.`, `_`, `%`, `+`, `-`만 허용한다.
- 계정 식별자는 앞뒤 공백을 제거하고 소문자로 정규화하여 저장한다.
- `@company.com.evil`과 같은 접미사 위장 도메인은 허용하지 않는다.
- 허용 도메인은 `ACCOUNT_EMAIL_DOMAIN` 환경변수로 기관 정책에 맞게 변경할 수 있다.

## Upload Security Limits

- ZIP 파일만 업로드할 수 있다.
- 압축 파일 최대 크기는 20 MiB이다.
- 압축 해제된 전체 크기는 100 MiB 이하이다.
- ZIP 내부 파일은 최대 2,000개이다.
- 개별 파일은 최대 10 MiB이다.
- 절대 경로와 `..`이 포함된 경로를 거부한다.
- 대상 작업 디렉터리를 벗어나는 경로를 거부한다.
- 심볼릭 링크와 특수 파일을 거부한다.
- 압축 해제 전에 모든 ZIP 항목을 검증한다.
- 제한 위반 시 ZIP의 일부 파일도 분석에 사용하지 않는다.
- 분석 실행마다 별도 임시 디렉터리를 사용한다.
- 분석 종료 후 임시 디렉터리를 삭제한다.
- Semgrep에는 PATH, 작업공간용 HOME·임시·캐시 위치, locale 및 Semgrep 로컬 설정만 전달하며 세션 비밀값, DB 주소와 프록시 환경변수는 전달하지 않는다.
- 업로드 루트와 분석 작업 디렉터리는 POSIX 환경에서 소유자만 접근하도록 `0700` 권한을 사용한다.
- 저장된 소스 경로는 해당 프로젝트의 `projects/{project_id}/sources/` 경계 안에 있어야 한다.
- Semgrep은 기본 2개 작업, 규칙별 1,024 MiB 메모리, 대상 파일 1,000,000바이트, JSON 출력 20 MiB로 제한한다.
- Semgrep 오류 출력은 최대 64 KiB까지만 보존하며 일반 USER에게 노출하지 않는다.
- Semgrep 전체 실행 제한 시간은 60초이며 timeout 또는 출력 초과 시 전체 프로세스 그룹을 종료한다.
- 모든 제한은 양의 정수 환경변수로 조정할 수 있다.

## Analysis State Transition

```text
PENDING → RUNNING → COMPLETED
                  ↘ FAILED
```

시간초과, Semgrep 비정상 종료 및 결과 파싱 실패는 `FAILED`로 기록한다.

내부 오류 메시지나 시스템 경로를 사용자 화면에 그대로 노출하지 않는다.
