# Routes

## Authentication

```text
GET  /login
POST /login
POST /logout
GET  /account/password
POST /account/password
```

신규 계정은 로그인 후 `/account/password`로 이동하며 현재 초기 비밀번호와 새 비밀번호를 입력한다. 변경 전에는 로그아웃과 비밀번호 변경 경로만 사용할 수 있다. 변경을 완료한 사용자도 같은 경로에서 현재 비밀번호 확인 후 자신의 비밀번호를 변경할 수 있다.

## Users — SUPER_ADMIN only

```text
GET  /users
GET  /users/new
POST /users
GET  /users/{user_id}/edit
POST /users/{user_id}/edit
POST /users/{user_id}/toggle-active
```

사용자 물리 삭제와 관리자의 임의 비밀번호 초기화 경로는 제공하지 않는다. PROJECT_MANAGER와 USER가 `/users` 경로에 접근하면 403으로 처리하고, 로그인하지 않은 사용자는 `/login`으로 이동한다.

모든 `POST` 경로는 CSRF 토큰이 필요하며, 토큰이 없거나 유효하지 않으면 `403`으로 처리한다.

## Projects

```text
GET  /projects
GET  /projects/new
POST /projects
GET  /projects/{project_id}
GET  /projects/{project_id}/edit
POST /projects/{project_id}/edit
GET  /projects/{project_id}/users
POST /projects/{project_id}/users
```

## Analysis

```text
POST /projects/{project_id}/analysis
GET  /projects/{project_id}/analysis
GET  /analysis/{analysis_id}
GET  /analysis/{analysis_id}/report.csv
GET  /analysis/{analysis_id}/report.pdf
```

`POST /projects/{project_id}/analysis`는 SUPER_ADMIN 또는 해당 프로젝트에 할당된 PROJECT_MANAGER만 사용할 수 있다. USER는 할당된 프로젝트의 분석 이력과 완료된 결과를 읽기 전용으로 조회할 수 있다. 분석 실패 원문은 SUPER_ADMIN과 담당 PROJECT_MANAGER에게만 표시한다.

ZIP 파일이 포함된 POST는 선택 입력인 `source_version`, `deployment_version`, `source_description`을 함께 받아 최신 프로젝트 소스 정보로 저장한다. 파일이 없는 POST는 현재 저장된 소스와 메타데이터를 스냅샷하여 분석을 실행한다.

두 보고서 GET은 SUPER_ADMIN 또는 해당 프로젝트에 할당된 PROJECT_MANAGER·USER가 사용할 수 있다. 접근할 수 없는 분석 ID는 `404`로 처리한다. 응답 파일명은 사용자 입력을 사용하지 않고 분석 ID만 사용하며 `Content-Disposition: attachment`로 제공한다.

## Findings

```text
GET /analysis/{analysis_id}/findings
GET /findings/{finding_id}
POST /findings/{finding_id}/status
POST /findings/{finding_id}/revalidate
```

Finding 목록은 `severity`, `confidence`, `status`, `assignee_id`, `overdue` query parameter를 지원한다. `overdue`는 `true` 또는 `false`만 허용한다. 권한이 없는 프로젝트나 분석 ID는 정보 노출을 막기 위해 404로 처리한다. 상태 변경 POST는 상태·의견·담당자·조치 기한을 함께 갱신하며 SUPER_ADMIN 또는 해당 프로젝트에 할당된 PROJECT_MANAGER만 사용할 수 있고 CSRF 검증을 적용한다. 담당자는 해당 프로젝트에 할당된 활성 사용자만 선택할 수 있다.

재검증 POST는 현재 프로젝트에 저장된 최신 소스로 새 AnalysisRun을 실행한 뒤 원본 Finding과 비교한다. SUPER_ADMIN 또는 해당 프로젝트의 PROJECT_MANAGER만 사용할 수 있고 CSRF 검증을 적용한다. 완료 후 원본 Finding 상세로 돌아가며 재검증 이력에서 새 분석과 일치 Finding을 조회할 수 있다.

## Rules

```text
GET  /rules
GET  /rules/new
POST /rules
GET  /rules/{rule_id}
GET  /rules/{rule_id}/edit
POST /rules/{rule_id}/edit
POST /rules/{rule_id}/toggle-active
```

`/rules`와 `/rules/{rule_id}`는 인증된 모든 역할이 조회할 수 있다. 검색어, 분류, 구현 상태, 지원 언어, 활성 상태 필터를 지원한다.

`/rules/new`, `POST /rules`, `/rules/{rule_id}/edit`, `POST /rules/{rule_id}/edit`, `POST /rules/{rule_id}/toggle-active`는 SUPER_ADMIN 전용이다. SUPER_ADMIN은 아직 언어별 규칙이 연결되지 않은 KISA 카탈로그 항목을 선택하고 Java, JavaScript, Python의 Semgrep Rule ID를 직접 입력한다. 공식 KISA ID·명칭·분류·항목 번호와 YAML 내용은 웹에서 만들거나 수정하지 않는다.

모든 `POST` 경로는 CSRF 토큰이 필요하다. PROJECT_MANAGER와 USER에게 규칙 관리 버튼을 표시하지 않고, 직접 관리 URL에 접근하면 `403`으로 처리한다.
