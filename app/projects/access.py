"""Project membership access checks shared by project, analysis, and Finding routes."""

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.dependencies import is_admin
from app.db.models.project import Project, ProjectUser
from app.db.models.user import User


def accessible_project_or_404(
    session: Session, project_id: int, user: User
) -> Project:
    """Return an accessible project without revealing inaccessible IDs."""
    statement = select(Project).where(Project.id == project_id)
    if not is_admin(user):
        statement = statement.join(ProjectUser).where(ProjectUser.user_id == user.id)
    project = session.scalar(statement)
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return project
