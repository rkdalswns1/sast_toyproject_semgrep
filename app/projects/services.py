"""Transactional project and project-membership operations."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.enums import Language, SourceType
from app.db.models.project import Project, ProjectUser
from app.db.models.user import User


class ProjectManagementError(ValueError):
    """Raised when a project operation cannot be completed safely."""


def create_project(
    session: Session,
    *,
    name: str,
    description: str | None,
    language: Language,
    created_by: int,
) -> Project:
    normalized_name = name.strip()
    if not normalized_name:
        raise ProjectManagementError("프로젝트 이름은 필수입니다.")

    project = Project(
        name=normalized_name,
        description=description.strip() or None if description else None,
        source_type=SourceType.ZIP,
        language=language,
        source_path="",
        created_by=created_by,
    )
    with session.begin():
        session.add(project)
        session.flush()
        session.add(ProjectUser(project_id=project.id, user_id=created_by))
    return project


def update_project(
    session: Session,
    *,
    project_id: int,
    name: str,
    description: str | None,
    language: Language,
) -> Project:
    normalized_name = name.strip()
    if not normalized_name:
        raise ProjectManagementError("프로젝트 이름은 필수입니다.")

    with session.begin():
        project = session.get(Project, project_id)
        if project is None:
            raise ProjectManagementError("프로젝트를 찾을 수 없습니다.")
        project.name = normalized_name
        project.description = description.strip() or None if description else None
        project.language = language
    return project


def replace_project_members(
    session: Session, *, project_id: int, user_ids: list[int]
) -> None:
    """Replace project members while retaining the recorded project creator."""
    with session.begin():
        project = session.get(Project, project_id)
        if project is None:
            raise ProjectManagementError("프로젝트를 찾을 수 없습니다.")

        requested_user_ids = set(user_ids)
        requested_user_ids.add(project.created_by)
        existing_users = set(
            session.scalars(select(User.id).where(User.id.in_(requested_user_ids))).all()
        )
        if existing_users != requested_user_ids:
            raise ProjectManagementError("존재하지 않는 사용자를 할당할 수 없습니다.")

        session.query(ProjectUser).filter(ProjectUser.project_id == project_id).delete(
            synchronize_session=False
        )
        session.add_all(
            ProjectUser(project_id=project_id, user_id=user_id)
            for user_id in sorted(requested_user_ids)
        )


def update_project_source(session: Session, *, project_id: int, source_path: Path) -> None:
    """Persist only a workspace path created by the upload service."""
    with session.begin():
        project = session.get(Project, project_id)
        if project is None:
            raise ProjectManagementError("프로젝트를 찾을 수 없습니다.")
        project.source_path = str(source_path)
