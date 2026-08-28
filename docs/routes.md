# Routes

## Authentication

```text
GET  /login
POST /login
POST /logout
```

## Users — ADMIN only

```text
GET  /users
GET  /users/new
POST /users
GET  /users/{user_id}/edit
POST /users/{user_id}/edit
POST /users/{user_id}/toggle-active
POST /users/{user_id}/reset-password
```

사용자 물리 삭제 경로는 제공하지 않는다. 인증된 일반 USER가 `/users` 경로에 접근하면 403으로 처리하고, 로그인하지 않은 사용자는 `/login`으로 이동한다.

비밀번호 초기화는 ADMIN이 새 비밀번호와 확인값을 직접 입력하는 방식으로 처리한다. 임시 비밀번호 자동 생성과 이메일 발송은 구현하지 않는다.

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
```

`POST /projects/{project_id}/analysis`는 ZIP 업로드와 분석 실행 모두 ADMIN 전용이다. 일반 USER는 할당된 프로젝트의 분석 이력과 완료된 결과를 읽기 전용으로 조회할 수 있다. 분석 실패 원문은 ADMIN에게만 표시한다.

## Findings

```text
GET /analysis/{analysis_id}/findings
GET /findings/{finding_id}
```

Finding 목록은 `severity`와 `confidence` query parameter를 지원한다. 권한이 없는 프로젝트나 분석 ID는 정보 노출을 막기 위해 404로 처리한다.

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

`/rules`와 `/rules/{rule_id}`는 인증된 ADMIN과 USER가 조회할 수 있다. 검색어, 분류, 구현 상태, 지원 언어, 활성 상태 필터를 지원한다.

`/rules/new`, `POST /rules`, `/rules/{rule_id}/edit`, `POST /rules/{rule_id}/edit`, `POST /rules/{rule_id}/toggle-active`는 ADMIN 전용이다. 등록은 기존 KISA 카탈로그 항목에 언어별 Semgrep Rule ID를 연결하는 동작이며, 공식 KISA ID·명칭·분류·항목 번호를 새로 만들거나 수정하지 않는다.

모든 `POST` 경로는 CSRF 토큰이 필요하다. USER에게 관리 버튼을 표시하지 않고, 직접 관리 URL에 접근하면 `403`으로 처리한다.
