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

## Findings

```text
GET /analysis/{analysis_id}/findings
GET /findings/{finding_id}
```

Finding 목록은 `severity`와 `confidence` query parameter를 지원한다. 권한이 없는 프로젝트나 분석 ID는 정보 노출을 막기 위해 404로 처리한다.
