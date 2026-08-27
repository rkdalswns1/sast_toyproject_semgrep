# Requirements Traceability

Phase 9 verification matrix. Test files use a temporary SQLite database and an
isolated upload directory; no test uses the developer's local project data.

| Requirement group | Implementation | Automated verification |
|---|---|---|
| Application startup, environment loading, SQLite schema | `app/config.py`, `app/db/database.py`, `app/main.py` | `tests/test_bootstrap.py`, `tests/test_database_schema.py` |
| Authentication, signed session, CSRF, password hashing | `app/auth/` | `tests/test_authentication.py` |
| ADMIN user management and protected administrator state | `app/auth/services.py`, `app/auth/routes.py` | `tests/test_authentication.py` |
| Project CRUD, membership, and project visibility | `app/projects/services.py`, `app/projects/routes.py` | `tests/test_projects.py`, `tests/test_end_to_end.py` |
| ZIP-only upload and safe extraction | `app/projects/upload.py` | `tests/test_source_upload.py` |
| ZIP Slip, symbolic link, path traversal, and size limits | `app/projects/upload.py` | `tests/test_source_upload.py` |
| Semgrep process isolation, timeout, error status, and JSON collection | `app/analysis/service.py` | `tests/test_analysis_execution.py` |
| Git-ignored upload source scanning | `app/analysis/service.py` (`--no-git-ignore`) | `tests/test_analysis_execution.py`, `tests/test_end_to_end.py` |
| Normalized Finding persistence, filters, details, and raw result preservation | `app/findings/services.py`, finding routes/templates | `tests/test_findings.py`, `tests/test_end_to_end.py` |
| Finding/project access boundaries | `app/projects/routes.py` | `tests/test_projects.py`, `tests/test_end_to_end.py` |
| KISA 2021 implementation-stage 49-item catalog | `app/rules/catalog.py`, `app/rules/services.py` | `tests/test_rule_catalog.py` |
| Implemented local Semgrep rules and supported language status | `app/rules/semgrep/kisa-2021.yml`, `app/rules/catalog.py` | `tests/test_rule_catalog.py`, `tests/test_end_to_end.py` |

## Verification Scope and Current Coverage

- The catalog contains all 49 implementation-stage items from the supplied
  KISA 2021 guide.
- Four Python rules are intentionally `PARTIAL`: SQL injection, operating
  system command injection, hardcoded sensitive information, and weak
  cryptographic algorithms.
- The other 45 catalog items are `NOT_IMPLEMENTED`; the application does not
  claim automatic detection for them.
- Java and JavaScript projects can be created and analyzed, but no local rule
  is currently mapped for those languages.
- The end-to-end test performs login, project creation, membership assignment,
  ZIP upload, real Semgrep analysis, Finding storage and detail viewing, then
  verifies both assigned-user access and unassigned-user 404 behavior.
