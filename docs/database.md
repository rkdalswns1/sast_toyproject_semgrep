# Database Schema

## Tables

### users

`id` PK, `username` UNIQUE NOT NULL, `password_hash` NOT NULL, `role` NOT NULL, `is_active` NOT NULL, `must_change_password` NOT NULL, `created_at`, `updated_at`. `username`에는 정규화된 사내 이메일 계정 식별자를 저장한다. 신규 계정은 `must_change_password=true`, 기존 계정 마이그레이션은 `false`로 저장한다.

### projects

기존 프로젝트 필드에 nullable DATE `expires_on`을 추가한다. 애플리케이션 로컬 날짜가 이 값에 도달하면 프로젝트는 만료되어 자동 삭제 대상이 된다.

`id` PK, `name` NOT NULL, `description`, `source_type` NOT NULL, `source_origin` NOT NULL, `repository_url`, `repository_ref`, `repository_commit`, `language` NOT NULL, `scan_all_languages` NOT NULL, `source_path` NOT NULL, `source_version`, `deployment_version`, `source_description`, `source_summary` JSON, `created_by` FK users.id, `created_at`, `updated_at`. `source_type`은 분석 입력 archive 형식인 `ZIP`을 유지하고 `source_origin`은 사용자가 직접 올린 `ZIP` 또는 공개 `GITHUB` 수집을 구분한다. GitHub 컬럼은 최신 저장소 URL·요청 ref·확정 commit SHA를 저장하며 ZIP 직접 업로드 시 비워 둔다. `language`은 기준 언어이며 `scan_all_languages=true`이면 안전하게 압축 해제된 소스에서 감지된 모든 지원 언어를 함께 분석한다.

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

`id` PK, `analysis_run_id` FK analysis_runs.id, `rule_id` FK rules.id, `rule_name`, `kisa_id`, `language`, `severity`, `confidence`, `primary_cwe_id`, `related_cwe_ids` JSON, `cwe_mapping_confidence`, `file_path`, `start_line`, `start_column`, `end_line`, `end_column`, `message`, `evidence`, `recommendation`, `raw_result`. CWE와 권고는 분석 당시 DiagnosticRule 값을 복사한 스냅샷이다.

### finding_workflows

`finding_id` PK/FK findings.id, `status`, `note`, `assignee_id` FK users.id, `due_date`, `updated_by` FK users.id, `updated_at`. Finding과 1:1 관계이며 최신 조치 상태·담당자·기한을 저장한다. 기본 상태는 `OPEN`이고 최초 탐지 시 담당자·기한·변경자·변경 시각은 비어 있다.

### finding_revalidations

`id` PK, `source_finding_id` FK findings.id, `analysis_run_id` FK analysis_runs.id, `matched_finding_id` nullable FK findings.id, `result`, `executed_by` FK users.id, `created_at`. 원본 Finding에 대한 재검증 실행과 새 분석 결과의 비교 판단을 이력으로 저장한다. 같은 원본 Finding과 AnalysisRun 조합은 한 번만 저장한다.

### finding_suppressions

`id` PK, `project_id` FK projects.id, `language`, `semgrep_rule_id`, `file_path`, `evidence_sha256`, `source_finding_id` nullable FK findings.id, `created_by` FK users.id, `is_active`, `created_at`, `updated_at`. 프로젝트·언어·Rule ID·상대경로·코드 지문 조합은 UNIQUE이며 오탐 상태 해제 시 행을 삭제하지 않고 비활성화한다.

### finding_suppression_hits

`id` PK, `analysis_run_id` FK analysis_runs.id, `suppression_id` nullable FK finding_suppressions.id, `source_finding_id` nullable FK findings.id, `reviewed_by` nullable FK users.id, `kisa_id`, `rule_name`, `language`, `semgrep_rule_id`, `file_path`, `start_line`, `start_column`, `end_line`, `end_column`, `message`, `review_note`, `reviewed_at`, `created_at`. 후속 분석에서 실제 제외된 결과와 최초 오탐 판정 정보를 실행 시점 스냅샷으로 보존하며 코드 원문·지문·원본 엔진 결과는 저장하지 않는다.

### diagnostic_rules

`id` PK, `catalog_rule_id` FK rules.id, `language`, `semgrep_rule_id` UNIQUE, `primary_cwe_id`, `related_cwe_ids` JSON, `cwe_mapping_confidence`, `remediation_guidance`, `is_active`, `created_at`, `updated_at`.

KISA 카탈로그 항목과 언어별 Semgrep Rule ID를 분리한다. 하나의 카탈로그 항목에는 언어별 진단 규칙을 여러 개 둘 수 있으며, 같은 카탈로그 항목에 같은 언어를 중복 등록할 수 없다.

### schema_versions

`version` PK, `description` NOT NULL, `applied_at` NOT NULL. 저장소 내부 스키마 마이그레이션의 성공 이력을 순서대로 저장한다.

## Relationships

- User N:M Project through project_users
- User 1:N Project through projects.created_by
- Project 1:N AnalysisRun
- User 1:N AnalysisRun through executed_by
- AnalysisRun 1:N Finding
- AnalysisRun 1:N FindingSuppressionHit
- Rule 1:N Finding
- Rule 1:N DiagnosticRule
- Finding 1:1 FindingWorkflow
- User 1:N FindingWorkflow through updated_by
- User 1:N FindingWorkflow through assignee_id
- Finding 1:N FindingRevalidation through source_finding_id
- Finding 1:N FindingSuppressionHit through source_finding_id
- AnalysisRun 1:N FindingRevalidation
- User 1:N FindingRevalidation through executed_by

## Integrity Rules

SQLite 연결마다 `PRAGMA foreign_keys=ON`을 적용한다.

Finding은 반드시 하나의 AnalysisRun과 Rule에 연결된다.

FindingWorkflow의 담당자는 해당 Finding이 속한 프로젝트의 활성 `project_users` 관계에 포함된 사용자만 지정한다. 기한 초과 여부는 저장하지 않고 `due_date`와 최신 상태를 조회 시 비교한다.

FindingRevalidation의 원본 Finding과 새 AnalysisRun은 같은 프로젝트에 속해야 한다. `matched_finding_id`는 새 AnalysisRun에서 비교 키가 정확히 일치한 Finding만 참조한다. 재검증 결과는 FindingWorkflow 상태를 변경하지 않는다.

혼합 언어 AnalysisRun에서도 Finding의 `language`는 매칭된 활성 DiagnosticRule의 실제 언어와 일치해야 한다. AnalysisRun의 기준 언어를 모든 Finding에 복사하지 않는다.

Rule의 `standard_id`는 고유하며 `item_number`는 1 이상의 공식 항목 번호를 저장한다. 비활성 Rule은 기존 Finding 관계를 유지하며 물리 삭제하지 않는다.

DiagnosticRule은 카탈로그의 공식 ID·명칭을 복제하지 않는다. 카탈로그 상세와 분석 결과의 기준 정보는 항상 `rules`에서 가져오며, DiagnosticRule은 언어별 엔진 매핑과 그 탐지 패턴에 직접 대응하는 CWE·조치 권고를 관리한다. CWE 형식은 `CWE-숫자`이며 관련 CWE는 근거가 있을 때만 중복 없이 저장한다.

## Schema Change Policy

- 신규 설치: `create_all()`로 최신 스키마를 생성한 뒤 현재 마이그레이션 버전을 기록한다.
- 기존 설치: 없는 컬럼과 테이블만 추가하고 적용 성공 후 버전을 기록한다.
- 마이그레이션은 버전 오름차순으로 실행하고 하나의 버전을 중복 적용하지 않는다.
- 마이그레이션 실패 시 해당 버전을 기록하지 않는다.
- 버전 4는 기존 DB에서 새로 구현된 경로 조작, XSS, 위험한 파일 업로드, XXE 카탈로그 행의 구현 상태·지원 언어·대표 Semgrep Rule ID를 동기화한다. 관리자가 변경한 카탈로그 활성 상태는 보존한다.
- 버전 5는 기존 Finding의 `raw_result.path`를 이미 정규화된 `file_path`와 동일한 소스 상대경로로 변경한다. 나머지 Semgrep 원본 필드는 유지한다.
- 버전 17은 분석 실행별 오탐 자동 제외 이력 테이블을 추가하며 기존 suppression과 Finding은 변경하지 않는다.
- 버전 6은 `users.role` 제약을 `SUPER_ADMIN`, `PROJECT_MANAGER`, `USER`로 교체하고 기존 `ADMIN`을 `SUPER_ADMIN`으로 변환하며 `must_change_password` 컬럼을 추가한다. 기존 사용자 관계와 식별자·해시·활성 상태·시각은 보존한다.
- 버전 7은 기존 DB의 인증서 유효성 검증과 신뢰할 수 없는 데이터의 역직렬화 카탈로그 행을 `PARTIAL`로 전환하고 지원 언어·대표 Semgrep Rule ID·기본 심각도를 동기화한다. 관리자가 변경한 활성 상태는 보존한다.
- 버전 8은 `projects.scan_all_languages`를 추가한다. 기존 프로젝트는 기존 동작을 보존하기 위해 `false`로 이전하며 신규 프로젝트는 화면에서 통합 분석을 선택할 수 있다.
- 버전 9는 `finding_workflows` 테이블을 생성하고 기존 Finding에 기본 `OPEN` 상태를 추가한다. 기존 분석 결과와 Rule 관계는 변경하지 않는다.
- 버전 10은 `projects`에 nullable `source_version`, `deployment_version`, `source_description`을 추가한다. 기존 프로젝트와 분석 실행은 값이 없는 상태로 유지한다.
- 버전 11은 `finding_workflows`에 nullable `assignee_id`와 `due_date`를 추가한다. 기존 조치 상태·의견·변경 정보는 유지하고 기존 행은 담당자와 기한이 없는 상태로 둔다.
- 버전 12는 `finding_revalidations` 테이블과 FK·고유 제약을 생성한다. 기존 Finding과 조치 상태는 변경하지 않는다.
- 버전 13은 `projects`에 nullable JSON `source_summary`를 추가한다. 기존 프로젝트는 요약이 없는 상태로 유지하며 다음 ZIP 업로드 성공 시 생성한다.
- 버전 14는 `diagnostic_rules`와 `findings`에 CWE 필드를 추가하고 DiagnosticRule에 조치 권고를 추가한다. 승인된 29개 Rule ID를 seed하고 기존 Finding은 원본 결과의 Rule ID가 정확히 일치할 때만 CWE 스냅샷을 채운다.
- 버전 15는 `projects`에 `source_origin`, `repository_url`, `repository_ref`, `repository_commit`을 추가한다. 기존 프로젝트는 `source_origin=ZIP`이고 GitHub 식별 정보는 없는 상태로 유지한다.
- 버전 16은 `projects.expires_on`과 `finding_suppressions`를 추가한다. 기존 프로젝트는 만료일이 없고 기존 오탐 Finding은 자동 suppression으로 역변환하지 않아 관리자가 이후 상태를 다시 저장할 때부터 적용한다.
- 버전 18은 두 번째 KISA 규칙 확대의 다섯 카탈로그 행을 `PARTIAL`로 전환하고 승인 언어·대표 Rule ID·심각도를 동기화한다. 기존 카탈로그 활성 상태와 Finding은 변경하지 않는다.

## Deletion Policy

- User는 일반 기능에서 물리 삭제하지 않고 `is_active=False`로 비활성화한다.
- Project 삭제 시 연결된 ProjectUser를 함께 삭제한다.
- Project 삭제 시 연결된 AnalysisRun과 Finding을 함께 삭제한다.
- AnalysisRun 삭제 시 연결된 Finding을 함께 삭제한다.
- ProjectUser는 연결된 Project가 삭제되면 함께 삭제한다.
- 사용 중인 Rule은 삭제할 수 없다.
- Finding이 참조하는 Rule에는 `RESTRICT` 정책을 사용한다.
- Finding 삭제 시 FindingWorkflow를 함께 삭제하고, 상태 변경자 또는 담당자로 참조 중인 User 삭제는 제한한다.
- 원본 Finding 또는 새 AnalysisRun 삭제 시 연결된 FindingRevalidation을 함께 삭제하고, 일치 Finding 삭제 시 `matched_finding_id`만 NULL로 변경한다. 실행자를 참조 중인 User 삭제는 제한한다.
- `projects.created_by`와 `analysis_runs.executed_by`의 기록 보존을 위해 참조 중인 User의 물리 삭제를 제한한다.
- Project 삭제 시 연결된 FindingSuppression을 함께 삭제하고, 원본 Finding만 삭제되면 `source_finding_id`를 NULL로 변경한다.
