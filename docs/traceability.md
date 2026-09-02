# Requirements Traceability

Phase 9 verification matrix. Test files use a temporary SQLite database and an
isolated upload directory; no test uses the developer's local project data.

## System Functional Requirement Status

| RFP ID | Status | Implementation / evidence |
|---|---|---|
| SFR-001 | Implemented | Company email validation in `app/auth/identifiers.py`; bootstrap and rejection tests in `tests/test_authentication.py` |
| SFR-003 | Implemented | SUPER_ADMIN/PROJECT_MANAGER/USER checks in auth and project routes; role integration assertions in `tests/test_authentication.py`, `tests/test_projects.py`, and `tests/test_end_to_end.py` |
| SFR-008 | Implemented | ZIP upload and Semgrep execution POST are limited to SUPER_ADMIN or the assigned PROJECT_MANAGER in `app/analysis/routes.py` |
| SFR-009 | Implemented | Per-run source/ruleset hashes, active-rule list/hash, source snapshot, engine version and detected language in `AnalysisRun.summary.provenance` |
| SFR-010 | Implemented | Central registry and extension-based detection in `app/analysis/languages.py`; project forms and scanner support single-language and detected multi-language modes |
| SFR-011 | Implemented (PARTIAL rules) | Java, JavaScript and Python share nine KISA items; Java and Python additionally map unsafe deserialization. Real-engine tests are in `tests/test_rule_catalog.py` and `tests/test_diagnostic_examples.py` |
| SFR-012 | Implemented | Developers maintain Semgrep YAML files; SUPER_ADMIN registers and edits KISA item, language and Rule ID mappings through `/rules/new`, and persisted mappings control Finding storage. |
| SFR-013 | Implemented | Authenticated catalog list/detail, filters and SUPER_ADMIN management separation in `app/rules/routes.py` and rule templates |
| Phase 15 report export | Implemented | Per-analysis CSV/PDF generation and protected download routes in `app/analysis/reports.py` and `app/analysis/routes.py` |
| Phase 16 assignment and due date | Implemented | Project-member assignee validation, due date and overdue filters in Finding service/routes and workflow tests |
| Phase 17 Finding revalidation | Implemented | New-run comparison history, protected revalidation route and deterministic comparison tests |
| Phase 18 source confirmation | Implemented | Safe-extraction source summary on project detail and persistence tests |

## Data Requirement Status

| RFP ID | Status | Implementation / evidence |
|---|---|---|
| DAR-001 | Implemented | SQLite transactions/FKs plus ordered migrations in `app/db/migrations.py` and applied history in `schema_versions` |
| DAR-002 | Implemented | `User` model includes three roles and `must_change_password`; schema/migration/authentication tests |
| DAR-003 | Implemented | `Project` model stores the baseline language and multi-language scan setting; project and migration tests |
| DAR-004 | Implemented | `ProjectUser` composite relationship and access tests |
| DAR-005 | Implemented | `AnalysisRun` model, lifecycle service and execution tests |
| DAR-006 | Implemented | normalized `Finding` model/service and Finding tests |
| DAR-007 | Implemented | `Rule` model includes item number, reference info, active state and default severity; official catalog seed tests |
| DAR-008 | Implemented | Finding snapshots rule name, KISA ID, language, severity and confidence at analysis time |
| DAR-009 | Implemented | JSON `AnalysisRun.summary`, `Finding.evidence` and `Finding.raw_result`; transient workspace paths are normalized to source-relative paths before persistence |
| DAR-010 | Implemented | SQLite FK enforcement and CASCADE/RESTRICT relationship tests |
| DAR-011 | Implemented | FindingWorkflow 1:1 model stores latest remediation status, note, updater and timestamp; migration and Finding tests |
| DAR-012 | Implemented | Project stores current ZIP source/deployment versions and description; AnalysisRun provenance snapshots them for immutable history |
| DAR-013 | Implemented | FindingWorkflow stores an optional active project-member assignee and due date; service validation and migration tests |
| DAR-014 | Implemented | FindingRevalidation stores source/new-run/matched Finding links, result, executor and timestamp |
| DAR-015 | Implemented | Project JSON stores a bounded summary derived from the latest safely extracted source |

## Security Requirement Status

| RFP ID | Status | Implementation / evidence |
|---|---|---|
| SEC-001 | Implemented | Required bcrypt dependency and fail-closed password helpers in `app/auth/security.py`; hash and response-boundary tests in `tests/test_authentication.py` |
| SEC-002 | Implemented | Signed, expiring cookie session and CSRF rotation in `app/auth/session.py`; missing, tampered and expired session tests in `tests/test_authentication.py` |
| SEC-003 | Implemented | SUPER_ADMIN-only system management plus assigned PROJECT_MANAGER project mutation, membership, upload, analysis and error-detail checks; integration tests |
| SEC-004 | Implemented | Assigned USER read-only routes and unassigned manager/member restrictions in project/end-to-end tests |
| SEC-005 | Implemented | `_accessible_project_or_404` verifies `project_users` instead of trusting route IDs; project/analysis/Finding access tests |
| SEC-006 | Implemented | Inaccessible project, analysis and Finding resources consistently return `404`; outsider end-to-end assertions |
| SEC-007 | Implemented | Project-bound source validation, owner-only per-run workspaces, regular-file copy, cleanup and allowlisted Semgrep child environment |
| SEC-008 | Implemented | ZIP signature, traversal, absolute path, link, special file, duplicate path, encrypted archive and byte-limit checks in `app/projects/upload.py` |
| SEC-009 | Implemented | Upload limits plus Semgrep jobs, memory, target, JSON output, bounded stderr and wall-time limits; process-group termination and operator-only error detail tests |
| SEC-010 | Implemented | Exact pins in `requirements.txt`, weekly Dependabot configuration, license inventory and update response policy in `docs/security.md` |
| SEC-011 | Implemented | SUPER_ADMIN/assigned PROJECT_MANAGER remediation updates, USER read-only and inaccessible-resource 404 tests |
| SEC-012 | Implemented | Report routes reuse project access checks; CSV formula escaping and report-field exclusion tests prevent unsafe or internal data export |
| SEC-013 | Implemented | Only SUPER_ADMIN/assigned PROJECT_MANAGER can assign active project members and set due dates; USER remains read-only |
| SEC-014 | Implemented | Revalidation reuses project-operation authorization, CSRF and isolated Semgrep execution; USER remains read-only |
| SEC-015 | Implemented | Source summary is generated after safe extraction and excludes content and absolute paths |

## Test Requirement Status

| RFP ID | Status | Implementation / evidence |
|---|---|---|
| TST-001 | Implemented | Three-role login, forced initial password change, self-service password change, signed-cookie rotation, logout and unauthenticated blocking in `tests/test_authentication.py` |
| TST-002 | Implemented | SUPER_ADMIN full management, assigned PROJECT_MANAGER operations, USER read-only restrictions in project/end-to-end tests |
| TST-003 | Implemented | Assigned-user project/result access and unassigned-user project, run and Finding `404` assertions in project/end-to-end tests |
| TST-004 | Implemented | ZIP upload, language provenance, real Semgrep rule execution and normalized Finding persistence in end-to-end/diagnostic tests |
| TST-005 | Implemented | Fixed vulnerable/safe Java, JavaScript and Python samples with expected rule, line, severity and confidence in `tests/samples/` |
| TST-006 | Implemented | All 49 Rules have unique identifier, category, positive item number, name and implementation status in `tests/test_rule_catalog.py` |
| TST-007 | Implemented | Analysis status/summary, Finding storage, severity/confidence/workflow/assignee/overdue filters, detail data and Rule FK checks in Finding/end-to-end tests |
| TST-008 | Implemented | Invalid target, nonzero exit with bounded stderr preservation, timeout, operator-only error detail, correction/re-run and failed-history preservation in analysis tests |
| TST-009 | Implemented | Revalidation comparison outcomes, history, permissions and unchanged workflow status in revalidation tests |
| TST-010 | Implemented | Source summary persistence, bounded relative paths, language detection, UI and failed-replacement preservation tests |

| Requirement group | Implementation | Automated verification |
|---|---|---|
| Application startup, environment loading, SQLite schema | `app/config.py`, `app/db/database.py`, `app/main.py` | `tests/test_bootstrap.py`, `tests/test_database_schema.py` |
| Authentication, signed session, CSRF, password hashing | `app/auth/` | `tests/test_authentication.py` |
| Company email identifier policy and legacy admin migration | `app/auth/identifiers.py`, `app/auth/services.py` | `tests/test_authentication.py` |
| SUPER_ADMIN user management, protected super-administrator state and self-service password changes | `app/auth/services.py`, `app/auth/routes.py` | `tests/test_authentication.py` |
| Project CRUD, membership, and project visibility | `app/projects/services.py`, `app/projects/routes.py` | `tests/test_projects.py`, `tests/test_end_to_end.py` |
| ZIP-only upload and safe extraction | `app/projects/upload.py` | `tests/test_source_upload.py` |
| ZIP Slip, symbolic link, path traversal, and size limits | `app/projects/upload.py` | `tests/test_source_upload.py` |
| SUPER_ADMIN/assigned PROJECT_MANAGER source mutation and analysis; USER read-only results | `app/analysis/routes.py`, project/analysis templates | `tests/test_end_to_end.py` |
| Semgrep per-run workspace isolation, minimal child environment, timeout, error status, JSON collection, and per-run provenance | `app/analysis/service.py` | `tests/test_analysis_execution.py` |
| Registered-language detection and single/multi-language scanning | `app/analysis/languages.py`, `app/analysis/service.py` | `tests/test_analysis_execution.py`, `tests/test_rule_catalog.py` |
| Git-ignored upload source scanning | `app/analysis/service.py` (`--no-git-ignore`) | `tests/test_analysis_execution.py`, `tests/test_end_to_end.py` |
| Normalized Finding persistence, filters, details, and raw result preservation | `app/findings/services.py`, finding routes/templates | `tests/test_findings.py`, `tests/test_end_to_end.py` |
| Finding remediation workflow, assignee/due date, and analysis executor display | `app/findings/services.py`, finding/analysis routes and templates | `tests/test_findings.py`, `tests/test_end_to_end.py` |
| Finding revalidation and new-run comparison history | `app/findings/revalidation.py`, Finding routes/detail template | `tests/test_revalidation.py` |
| ZIP source metadata and per-analysis snapshot | `app/projects/services.py`, `app/analysis/service.py`, project/analysis templates | `tests/test_source_upload.py`, `tests/test_analysis_execution.py`, `tests/test_database_schema.py` |
| Pre-analysis latest-source summary | `app/projects/upload.py`, `app/projects/services.py`, project detail template | `tests/test_source_upload.py`, `tests/test_database_schema.py` |
| Per-analysis CSV/PDF reports | `app/analysis/reports.py`, report routes and analysis detail template | `tests/test_reports.py` |
| Finding/project access boundaries | `app/projects/access.py`, `app/findings/routes.py` | `tests/test_projects.py`, `tests/test_end_to_end.py` |
| KISA 2021 implementation-stage 49-item catalog | `app/rules/catalog.py`, `app/rules/services.py` | `tests/test_rule_catalog.py` |
| Implemented local Semgrep rules and supported language status | `app/rules/semgrep/kisa-2021/`, `app/rules/catalog.py` | `tests/test_rule_catalog.py`, `tests/test_end_to_end.py` |
| SEC control contract and external component governance | `docs/security.md`, `.github/dependabot.yml`, `requirements.txt` | `tests/test_security_controls.py` |
| TST fixed examples and expected diagnostic results | `docs/testing.md`, `tests/samples/expected_findings.json` | `tests/test_diagnostic_examples.py` |

## Quality Requirement Status

| RFP ID | Status | Implementation / evidence |
|---|---|---|
| QLT-001 | Implemented | Responsibility-owned routes/services in `app/auth/`, `app/projects/`, `app/analysis/`, `app/findings/`, and `app/rules/`; ownership assertions in `tests/test_quality_architecture.py` |
| QLT-002 | Implemented | One KISA item per YAML under `app/rules/semgrep/kisa-2021/`; file independence and whole-ruleset provenance tests |
| QLT-003 | Implemented | Central language registry plus shared AnalysisRun/Finding pipeline; all supported languages exercise the same flow in diagnostic tests |
| QLT-004 | Implemented | `app/findings/services.py` normalizes every result to the common Finding model, including relative paths in both normalized and raw-result fields; cross-language field assertions in diagnostic tests |
| QLT-005 | Implemented | FK constraints, DiagnosticRule-derived Finding language and Rule-language compatibility checks; schema and quality consistency tests |

## Verification Scope and Current Coverage

- The catalog contains all 49 implementation-stage items from the supplied
  KISA 2021 guide.
- Nine KISA items are intentionally `PARTIAL` for Python, Java, and JavaScript:
  SQL injection, path traversal/resource injection, cross-site scripting,
  operating system command injection, unrestricted file upload, XML external
  entity reference, hardcoded sensitive information, weak cryptographic algorithms,
  and improper certificate validation.
- Unsafe deserialization is additionally `PARTIAL` for Java and Python.
- The other 39 catalog items are `NOT_IMPLEMENTED`; the application does not
  claim automatic detection for them.
- Python, Java, and JavaScript use language-specific Semgrep rules mapped to
  catalog entries through `kisa_standard_id` metadata; unsupported language-item
  combinations are not advertised or executed.
- The end-to-end test performs login, project creation, membership assignment,
  ZIP upload, real Semgrep analysis, Finding storage and detail viewing, then
  verifies both assigned-user access and unassigned-user 404 behavior.
