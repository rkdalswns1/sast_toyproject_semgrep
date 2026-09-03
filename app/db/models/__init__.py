"""SQLAlchemy models registered on the shared metadata."""

from app.db.models.analysis_run import AnalysisRun
from app.db.models.diagnostic_rule import DiagnosticRule
from app.db.models.finding import Finding
from app.db.models.finding_revalidation import FindingRevalidation
from app.db.models.finding_suppression import FindingSuppression
from app.db.models.finding_suppression_hit import FindingSuppressionHit
from app.db.models.finding_workflow import FindingWorkflow
from app.db.models.project import Project, ProjectUser
from app.db.models.rule import Rule
from app.db.models.schema_version import SchemaVersion
from app.db.models.user import User

__all__ = [
    "AnalysisRun",
    "DiagnosticRule",
    "Finding",
    "FindingRevalidation",
    "FindingSuppression",
    "FindingSuppressionHit",
    "FindingWorkflow",
    "Project",
    "ProjectUser",
    "Rule",
    "SchemaVersion",
    "User",
]
