# Security Controls

이 문서는 RFP SEC-001~010의 운영 기준과 외부 구성요소 관리 절차를 정의한다. 구체적인 수치 기본값은 `configuration.md`를 따른다.

## Authentication and Authorization

- 비밀번호는 bcrypt 해시로만 저장하고 평문을 DB, 세션, 응답 또는 로그에 기록하지 않는다.
- 서명 쿠키에는 `user_id`, CSRF 토큰, 만료 시각만 저장한다.
- 서명이 올바르지 않거나 만료된 세션은 인증되지 않은 요청으로 처리한다.
- 인증 성공 시 CSRF 토큰과 만료 시각을 새로 발급한다.
- 쿠키는 `HttpOnly`, `SameSite=Lax`를 사용하고 운영 환경에서는 `Secure`를 적용한다.
- 모든 상태 변경 POST 요청은 CSRF 검증을 통과해야 한다.
- 사용자 역할과 활성 상태는 요청마다 DB에서 다시 조회한다.
- 신규 계정은 최초 로그인 후 본인이 현재 초기 비밀번호를 검증하고 개인 비밀번호로 변경하기 전까지 비밀번호 변경과 로그아웃 외의 보호 기능을 사용할 수 없다.
- SUPER_ADMIN만 계정·역할·규칙을 관리하며 다른 사용자의 비밀번호를 직접 초기화하지 않는다.
- 프로젝트 자원은 SUPER_ADMIN 여부 또는 `project_users` 관계를 확인한 후 접근한다. PROJECT_MANAGER의 쓰기 작업도 프로젝트 할당 관계를 확인한다.
- Finding 담당자 지정은 요청의 사용자 ID를 그대로 신뢰하지 않고 해당 Finding의 프로젝트에 연결된 활성 `project_users` 관계를 다시 확인한다.
- Finding 재검증도 원본 Finding ID만 신뢰하지 않고 원본 분석의 프로젝트 접근·운영 권한을 확인하며 기존 격리·자원 제한을 적용한 새 분석으로 실행한다.
- 권한 없는 프로젝트, 분석 실행, Finding은 존재 여부가 드러나지 않도록 `404`를 반환한다.
- 프로젝트 삭제는 SUPER_ADMIN만 수행하며 CSRF와 사용자 확인을 적용한다. 파일 삭제 대상은 DB 경로가 아니라 설정된 업로드 루트 아래 `projects/{project_id}`로 계산하고 경계 안인지 재검증한다.
- CSV/PDF 보고서도 분석 화면과 동일한 프로젝트 접근 검사를 적용한다. 파일명에는 프로젝트명 등 사용자 입력을 사용하지 않는다.
- CSV의 외부 유래 문자열이 스프레드시트 수식 접두사로 시작하면 텍스트로 이스케이프한다.
- 보고서에는 정규화된 상대 파일 경로만 사용하고 Semgrep 원본 JSON, 내부 오류 원문과 시스템 절대경로를 포함하지 않는다.

## Source and Analysis Isolation

- ZIP 확장자와 실제 ZIP 구조를 모두 검증한다.
- 전체 업로드를 고유한 staging 영역에서 검증한 후에만 프로젝트 소스로 이동한다.
- 소스 요약은 staging 영역의 안전한 압축 해제가 끝난 후 실제 정규 파일만 대상으로 계산한다. 원본 파일명에서는 경로 성분을 제거하고 파일 위치는 소스 상대경로로 제한하며 파일 내용과 시스템 절대경로는 저장하지 않는다.
- 절대 경로, `..`, 역슬래시, NUL, 중복 경로, 심볼릭 링크, 특수 파일 및 암호화 ZIP을 거부한다.
- 선언된 압축 해제 크기와 실제 복사한 바이트를 모두 제한한다.
- DB의 `source_path`가 해당 프로젝트의 소스 루트 하위인지 분석 직전에 다시 검증한다.
- 분석 실행마다 별도 작업 디렉터리를 만들고 정규 파일만 복사한다.
- Semgrep 자식 프로세스에는 허용 목록 환경변수만 전달한다. 세션 비밀값, DB 주소, 프록시 및 애플리케이션 구성은 상속하지 않는다.
- timeout과 출력 제한 초과 시 Semgrep 프로세스 그룹 전체를 종료한다.
- Semgrep 표준 오류는 64 KiB 상한 안에서 분석 실행의 오류 정보로 보존하고 SUPER_ADMIN과 해당 프로젝트의 PROJECT_MANAGER에게만 표시한다. USER에게는 내부 경로와 오류 원문을 노출하지 않는다.
- 분석 작업 디렉터리는 성공·실패 여부와 관계없이 삭제한다.

## External Component Management

직접 의존성 버전은 루트 `requirements.txt`에 정확히 고정한다. GitHub Dependabot은 매주 Python 의존성을 확인하고 업데이트 제안과 알려진 보안 취약점을 PR로 알린다. 자동 병합은 사용하지 않는다.

Phase 11 규칙은 Semgrep 공식 보안 가이드와 Community 규칙을 탐지 범위의 참고 자료로 확인했지만 원문을 복사하지 않고 이 저장소의 KISA metadata와 고정 샘플에 맞춰 직접 작성했다. 실행 중 Registry나 외부 네트워크에서 규칙을 내려받지 않으며, 실제 분석에는 저장소에 포함된 로컬 YAML만 사용한다.

업데이트 PR은 다음 순서로 검토한다.

1. 보안 공지, 변경 기록과 라이선스 변경 여부를 확인한다.
2. `python -m pip check`와 전체 pytest를 실행한다.
3. 실제 Semgrep 실행 테스트와 취약 샘플 탐지 결과를 확인한다.
4. 호환성과 요구사항 추적표에 영향이 없을 때만 병합한다.

Critical 또는 High 취약점은 배포를 중단하고 수정 버전으로 갱신한 후 재검증한다. Medium은 30일 안에 검토하고, Low는 다음 정기 유지보수에서 처리한다. 수정 버전이 없으면 영향 범위, 임시 완화책과 수용 여부를 문서화한다.

## Direct Dependency License Inventory

| 구성요소 | 고정 버전 | 라이선스 |
|---|---:|---|
| bcrypt | 3.2.2 | Apache-2.0 |
| FastAPI | 0.141.1 | MIT |
| HTTPX | 0.28.1 | BSD-3-Clause |
| ItsDangerous | 2.2.0 | BSD-3-Clause |
| Jinja2 | 3.1.6 | BSD-3-Clause |
| python-dotenv | 1.2.3 | BSD-3-Clause |
| python-multipart | 0.0.32 | Apache-2.0 |
| pypdf | 6.10.0 | BSD-3-Clause |
| pytest | 9.1.1 | MIT |
| ReportLab | 4.4.9 | BSD-3-Clause |
| Semgrep | 1.175.0 | LGPL-2.1-or-later |
| SQLAlchemy | 2.0.52 | MIT |
| Uvicorn | 0.52.4 | BSD-3-Clause |

배포 전에 설치된 전이 의존성의 라이선스도 패키지 메타데이터와 원 프로젝트의 LICENSE에서 확인한다. 새로운 구성요소를 추가할 때는 버전, 용도, 라이선스와 보안 업데이트 경로를 이 문서에 먼저 기록한다.

## Deployment Checklist

- `.env`와 SQLite DB, 업로드 소스가 Git에 포함되지 않았는지 확인한다.
- `SESSION_SECRET`을 환경별로 고유하게 생성하고 최소 32바이트인지 확인한다.
- 시연용 최초 관리자 비밀번호 `admin`을 외부 공개 전에 변경한다.
- 운영 환경은 `APP_ENV=production`으로 실행하여 세션 쿠키에 `Secure`를 적용한다.
- Dependabot 경고와 보류 중인 High/Critical 취약점이 없는지 확인한다.
- 전체 테스트와 실제 Semgrep 분석을 통과한 커밋만 배포한다.
