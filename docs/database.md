# Database Schema

## Tables

### users

`id` PK, `username` UNIQUE NOT NULL, `password_hash` NOT NULL, `role` NOT NULL, `is_active` NOT NULL, `created_at`, `updated_at`.

### projects

`id` PK, `name` NOT NULL, `description`, `source_type` NOT NULL, `language` NOT NULL, `source_path` NOT NULL, `created_by` FK users.id, `created_at`, `updated_at`.

### project_users

`project_id` FK projects.id와 `user_id` FK users.id의 복합 PK. 사용자와 프로젝트의 N:M 관계를 표현한다.

### analysis_runs

`id` PK, `project_id` FK projects.id, `engine`, `language`, `status`, `executed_by` FK users.id, `started_at`, `finished_at`, `error_message`, `summary`.

### rules

`id` PK, `name`, `description`, `standard_id`, `category`, `severity`, `supported_languages`, `implementation_status`, `semgrep_rule_id`.

### findings

`id` PK, `analysis_run_id` FK analysis_runs.id, `rule_id` FK rules.id, `rule_name`, `kisa_id`, `language`, `severity`, `confidence`, `file_path`, `start_line`, `start_column`, `end_line`, `end_column`, `message`, `evidence`, `recommendation`, `raw_result`.

## Relationships

- User N:M Project through project_users
- User 1:N Project through projects.created_by
- Project 1:N AnalysisRun
- User 1:N AnalysisRun through executed_by
- AnalysisRun 1:N Finding
- Rule 1:N Finding

## Integrity Rules

SQLite 연결마다 `PRAGMA foreign_keys=ON`을 적용한다.

Finding은 반드시 하나의 AnalysisRun과 Rule에 연결된다.

## Deletion Policy

- User는 일반 기능에서 물리 삭제하지 않고 `is_active=False`로 비활성화한다.
- Project 삭제 시 연결된 ProjectUser를 함께 삭제한다.
- Project 삭제 시 연결된 AnalysisRun과 Finding을 함께 삭제한다.
- AnalysisRun 삭제 시 연결된 Finding을 함께 삭제한다.
- ProjectUser는 연결된 Project가 삭제되면 함께 삭제한다.
- 사용 중인 Rule은 삭제할 수 없다.
- Finding이 참조하는 Rule에는 `RESTRICT` 정책을 사용한다.
- `projects.created_by`와 `analysis_runs.executed_by`의 기록 보존을 위해 참조 중인 User의 물리 삭제를 제한한다.
