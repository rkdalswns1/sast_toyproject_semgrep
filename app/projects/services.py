"""Transactional project and project-membership operations."""

from __future__ import annotations

from pathlib import Path
import shutil
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.enums import Language, SourceType
from app.db.models.project import Project, ProjectUser
from app.db.models.user import User


class ProjectManagementError(ValueError):
    """Raised when a project operation cannot be completed safely."""


SOURCE_VERSION_MAX_LENGTH = 100
SOURCE_DESCRIPTION_MAX_LENGTH = 2_000


def normalize_source_metadata(
    *,
    source_version: str | None,
    deployment_version: str | None,
    source_description: str | None,
) -> tuple[str | None, str | None, str | None]:
    """Normalize and validate optional metadata before storing a ZIP."""
    normalized_source_version = source_version.strip() if source_version else None
    normalized_deployment_version = (
        deployment_version.strip() if deployment_version else None
    )
    normalized_description = (
        source_description.strip() if source_description else None
    )
    if normalized_source_version and len(normalized_source_version) > SOURCE_VERSION_MAX_LENGTH:
        raise ProjectManagementError("소스 버전은 100자 이하여야 합니다.")
    if (
        normalized_deployment_version
        and len(normalized_deployment_version) > SOURCE_VERSION_MAX_LENGTH
    ):
        raise ProjectManagementError("배포 버전은 100자 이하여야 합니다.")
    if normalized_description and len(normalized_description) > SOURCE_DESCRIPTION_MAX_LENGTH:
        raise ProjectManagementError("소스 설명은 2,000자 이하여야 합니다.")
    return (
        normalized_source_version or None,
        normalized_deployment_version or None,
        normalized_description or None,
    )


def create_project(
    session: Session,
    *,
    name: str,
    description: str | None,
    language: Language,
    scan_all_languages: bool = False,
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
        scan_all_languages=scan_all_languages,
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
    scan_all_languages: bool = False,
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
        project.scan_all_languages = scan_all_languages
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


def update_project_source(
    session: Session,
    *,
    project_id: int,
    source_path: Path,
    source_version: str | None = None,
    deployment_version: str | None = None,
    source_description: str | None = None,
    source_summary: dict[str, Any] | None = None,
) -> None:
    """Persist only a workspace path created by the upload service."""
    normalized_metadata = normalize_source_metadata(
        source_version=source_version,
        deployment_version=deployment_version,
        source_description=source_description,
    )
    with session.begin():
        project = session.get(Project, project_id)
        if project is None:
            raise ProjectManagementError("프로젝트를 찾을 수 없습니다.")
        project.source_path = str(source_path)
        project.source_summary = source_summary
        (
            project.source_version,
            project.deployment_version,
            project.source_description,
        ) = normalized_metadata


def delete_project(
    session: Session, *, project_id: int, upload_dir: Path
) -> None:
    """Delete one project and only its computed upload-root workspace."""
    upload_root = upload_dir.resolve()
    projects_root = (upload_root / "projects").resolve()
    project_directory = projects_root / str(project_id)
    if project_directory.parent != projects_root:
        raise ProjectManagementError("프로젝트 저장 경로를 안전하게 확인하지 못했습니다.")

    quarantined_directory: Path | None = None
    try:
        if project_directory.exists() or project_directory.is_symlink():
            trash_root = upload_root / ".trash"
            trash_root.mkdir(mode=0o700, parents=True, exist_ok=True)
            quarantined_directory = trash_root / f"project-{project_id}-{uuid.uuid4().hex}"
            project_directory.rename(quarantined_directory)

        with session.begin():
            project = session.get(Project, project_id)
            if project is None:
                raise ProjectManagementError("프로젝트를 찾을 수 없습니다.")
            session.delete(project)
    except Exception:
        if quarantined_directory is not None and (
            quarantined_directory.exists() or quarantined_directory.is_symlink()
        ):
            project_directory.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            quarantined_directory.rename(project_directory)
        raise

    if quarantined_directory is not None and (
        quarantined_directory.exists() or quarantined_directory.is_symlink()
    ):
        if quarantined_directory.is_symlink():
            quarantined_directory.unlink()
        else:
            shutil.rmtree(quarantined_directory)
