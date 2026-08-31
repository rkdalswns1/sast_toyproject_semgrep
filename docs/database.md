# Database Schema

## Tables

### users

`id` PK, `username` UNIQUE NOT NULL, `password_hash` NOT NULL, `role` NOT NULL, `is_active` NOT NULL, `created_at`, `updated_at`. `username`에는 정규화된 사내 이메일 계정 식별자를 저장한다.

### projects

`id` PK, `name` NOT NULL, `description`, `source_type` NOT NULL, `language` NOT NULL, `source_path` NOT NULL, `created_by` FK users.id, `created_at`, `updated_at`.

### project_users

`project_id` FK projects.id와 `user_id` FK users.id의 복합 PK. 사용자와 프로젝트의 N:M 관계를 표현한다.

### analysis_runs

`id` PK, `project_id` FK projects.id, `engine`, `language`, `status`, `executed_by` FK users.id, `started_at`, `finished_at`, `error_message`, `summary`.

### rules

`id` PK, `name`, `description`, `standard_id`, `category`, `item_number`, `reference_info`, `is_active`, `severity`, `supported_languages`, `implementation_status`, `semgrep_rule_id`.

- `item_number`: 공식 가이드의 절 내부 항목 번호
- `reference_info`: 공식 문서명과 절·항목 참조 정보
- `is_active`: 분석 규칙 세트에서 사용할 수 있는 활성 상태

### findings

`id` PK, `analysis_run_id` FK analysis_runs.id, `rule_id` FK rules.id, `rule_name`, `kisa_id`, `language`, `severity`, `confidence`, `file_path`, `start_line`, `start_column`, `end_line`, `end_column`, `message`, `evidence`, `recommendation`, `raw_result`.

### diagnostic_rules

`id` PK, `catalog_rule_id` FK rules.id, `language`, `semgrep_rule_id` UNIQUE, `is_active`, `created_at`, `updated_at`.

KISA 카탈로그 항목과 언어별 Semgrep Rule ID를 분리한다. 하나의 카탈로그 항목에는 언어별 진단 규칙을 여러 개 둘 수 있으며, 같은 카탈로그 항목에 같은 언어를 중복 등록할 수 없다.

### schema_versions

`version` PK, `description` NOT NULL, `applied_at` NOT NULL. 저장소 내부 스키마 마이그레이션의 성공 이력을 순서대로 저장한다.

## Relationships

- User N:M Project through project_users
- User 1:N Project through projects.created_by
- Project 1:N AnalysisRun
- User 1:N AnalysisRun through executed_by
- AnalysisRun 1:N Finding
- Rule 1:N Finding
- Rule 1:N DiagnosticRule

## Integrity Rules

SQLite 연결마다 `PRAGMA foreign_keys=ON`을 적용한다.

Finding은 반드시 하나의 AnalysisRun과 Rule에 연결된다.

Rule의 `standard_id`는 고유하며 `item_number`는 1 이상의 공식 항목 번호를 저장한다. 비활성 Rule은 기존 Finding 관계를 유지하며 물리 삭제하지 않는다.

DiagnosticRule은 카탈로그의 공식 ID·명칭을 복제하지 않는다. 카탈로그 상세와 분석 결과의 기준 정보는 항상 `rules`에서 가져오며, DiagnosticRule은 언어별 엔진 매핑만 관리한다.

## Schema Change Policy

- 신규 설치: `create_all()`로 최신 스키마를 생성한 뒤 현재 마이그레이션 버전을 기록한다.
- 기존 설치: 없는 컬럼과 테이블만 추가하고 적용 성공 후 버전을 기록한다.
- 마이그레이션은 버전 오름차순으로 실행하고 하나의 버전을 중복 적용하지 않는다.
- 마이그레이션 실패 시 해당 버전을 기록하지 않는다.
- 버전 4는 기존 DB에서 새로 구현된 경로 조작, XSS, 위험한 파일 업로드, XXE 카탈로그 행의 구현 상태·지원 언어·대표 Semgrep Rule ID를 동기화한다. 관리자가 변경한 카탈로그 활성 상태는 보존한다.
- 버전 5는 기존 Finding의 `raw_result.path`를 이미 정규화된 `file_path`와 동일한 소스 상대경로로 변경한다. 나머지 Semgrep 원본 필드는 유지한다.

## Deletion Policy

- User는 일반 기능에서 물리 삭제하지 않고 `is_active=False`로 비활성화한다.
- Project 삭제 시 연결된 ProjectUser를 함께 삭제한다.
- Project 삭제 시 연결된 AnalysisRun과 Finding을 함께 삭제한다.
- AnalysisRun 삭제 시 연결된 Finding을 함께 삭제한다.
- ProjectUser는 연결된 Project가 삭제되면 함께 삭제한다.
- 사용 중인 Rule은 삭제할 수 없다.
- Finding이 참조하는 Rule에는 `RESTRICT` 정책을 사용한다.
- `projects.created_by`와 `analysis_runs.executed_by`의 기록 보존을 위해 참조 중인 User의 물리 삭제를 제한한다.
