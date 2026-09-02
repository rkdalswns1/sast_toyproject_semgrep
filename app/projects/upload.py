"""Safe ZIP source upload and extraction for project workspaces."""

from __future__ import annotations

import os
import shutil
import stat
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from fastapi import UploadFile

from app.analysis.languages import detect_source_languages
from app.config import Settings


COPY_CHUNK_BYTES = 1024 * 1024
SOURCE_SUMMARY_PATH_LIMIT = 20
SOURCE_ARCHIVE_NAME_MAX_LENGTH = 255


class SourceUploadError(ValueError):
    """Raised when an uploaded archive violates the upload contract."""


@dataclass(frozen=True, slots=True)
class StoredProjectSource:
    """Final source location and its bounded, safe-to-display summary."""

    path: Path
    summary: dict[str, Any]


def _safe_archive_name(filename: str | None) -> str:
    basename = PurePosixPath((filename or "").replace("\\", "/")).name
    return (basename or "source.zip")[:SOURCE_ARCHIVE_NAME_MAX_LENGTH]


def _build_source_summary(source_root: Path, archive_name: str | None) -> dict[str, Any]:
    """Summarize actual extracted regular files without content or absolute paths."""
    source_root = source_root.resolve()
    relative_paths: list[str] = []
    total_bytes = 0
    for candidate in source_root.rglob("*"):
        if candidate.is_symlink():
            raise SourceUploadError("압축 해제된 소스에 허용되지 않는 링크가 있습니다.")
        if not candidate.is_file():
            continue
        resolved = candidate.resolve()
        if not resolved.is_relative_to(source_root):
            raise SourceUploadError("압축 해제된 소스 경로가 작업 영역을 벗어납니다.")
        relative_paths.append(resolved.relative_to(source_root).as_posix())
        total_bytes += resolved.stat().st_size

    relative_paths.sort()
    detected_languages = sorted(
        language.value for language in detect_source_languages(source_root)
    )
    return {
        "archive_name": _safe_archive_name(archive_name),
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "file_count": len(relative_paths),
        "total_bytes": total_bytes,
        "detected_languages": detected_languages,
        "sample_paths": relative_paths[:SOURCE_SUMMARY_PATH_LIMIT],
    }


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix":
        path.chmod(0o700)


def _is_unsafe_zip_member(info: zipfile.ZipInfo) -> bool:
    name = info.filename
    if not name or "\x00" in name or "\\" in name:
        return True
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        return True
    mode = info.external_attr >> 16
    if stat.S_ISLNK(mode):
        return True
    file_type = stat.S_IFMT(mode)
    if file_type and file_type not in (stat.S_IFREG, stat.S_IFDIR):
        return True
    return False


def _validate_zip(zip_file: zipfile.ZipFile, settings: Settings) -> None:
    infos = zip_file.infolist()
    if len(infos) > settings.max_archive_files:
        raise SourceUploadError("ZIP 내부 파일 수 제한을 초과했습니다.")

    extracted_size = 0
    member_names: set[str] = set()
    for info in infos:
        if _is_unsafe_zip_member(info):
            raise SourceUploadError("안전하지 않은 ZIP 경로 또는 파일 형식입니다.")
        if info.flag_bits & 0x1:
            raise SourceUploadError("암호화된 ZIP 파일은 허용되지 않습니다.")
        if info.filename in member_names:
            raise SourceUploadError("중복된 ZIP 경로는 허용되지 않습니다.")
        member_names.add(info.filename)
        if info.is_dir():
            continue
        if info.file_size > settings.max_single_file_bytes:
            raise SourceUploadError("ZIP 내부 개별 파일 크기 제한을 초과했습니다.")
        extracted_size += info.file_size
        if extracted_size > settings.max_extracted_bytes:
            raise SourceUploadError("압축 해제 후 전체 크기 제한을 초과했습니다.")


def _extract_zip(archive_path: Path, destination: Path, settings: Settings) -> None:
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    destination_root = destination.resolve()
    extracted_size = 0

    try:
        with zipfile.ZipFile(archive_path) as zip_file:
            _validate_zip(zip_file, settings)
            for info in zip_file.infolist():
                target = destination / PurePosixPath(info.filename)
                resolved_target = target.resolve()
                if not resolved_target.is_relative_to(destination_root):
                    raise SourceUploadError("ZIP 경로가 작업 디렉터리를 벗어납니다.")
                if info.is_dir():
                    _ensure_private_directory(resolved_target)
                    continue

                _ensure_private_directory(resolved_target.parent)
                with zip_file.open(info) as source, resolved_target.open("xb") as output:
                    member_size = 0
                    while chunk := source.read(COPY_CHUNK_BYTES):
                        member_size += len(chunk)
                        if member_size > settings.max_single_file_bytes:
                            raise SourceUploadError("ZIP 내부 개별 파일 크기 제한을 초과했습니다.")
                        extracted_size += len(chunk)
                        if extracted_size > settings.max_extracted_bytes:
                            raise SourceUploadError("압축 해제 후 전체 크기 제한을 초과했습니다.")
                        output.write(chunk)
    except (NotImplementedError, RuntimeError, zipfile.BadZipFile) as exc:
        raise SourceUploadError("유효한 ZIP 파일이 아닙니다.") from exc


async def save_project_source(
    source_file: UploadFile, *, project_id: int, settings: Settings
) -> StoredProjectSource:
    """Validate, isolate, and extract a ZIP upload into a new project workspace."""
    filename = source_file.filename or ""
    if not filename.lower().endswith(".zip"):
        raise SourceUploadError("ZIP 파일만 업로드할 수 있습니다.")

    upload_root = settings.upload_dir.resolve()
    incoming_dir = upload_root / ".incoming"
    staging_dir = upload_root / ".staging"
    _ensure_private_directory(upload_root)
    _ensure_private_directory(incoming_dir)
    _ensure_private_directory(staging_dir)

    upload_id = uuid.uuid4().hex
    incoming_archive = incoming_dir / f"{upload_id}.zip"
    staged_workspace = staging_dir / upload_id
    final_workspace = upload_root / "projects" / str(project_id) / "sources" / upload_id
    uploaded_size = 0

    try:
        with incoming_archive.open("xb") as output:
            while chunk := await source_file.read(COPY_CHUNK_BYTES):
                uploaded_size += len(chunk)
                if uploaded_size > settings.max_upload_bytes:
                    raise SourceUploadError("ZIP 파일 크기 제한을 초과했습니다.")
                output.write(chunk)

        if not zipfile.is_zipfile(incoming_archive):
            raise SourceUploadError("유효한 ZIP 파일이 아닙니다.")

        staged_workspace.mkdir(mode=0o700, parents=True, exist_ok=False)
        archive_path = staged_workspace / "source.zip"
        incoming_archive.replace(archive_path)
        extracted_path = staged_workspace / "extracted"
        _extract_zip(archive_path, extracted_path, settings)
        source_summary = _build_source_summary(extracted_path, filename)
        _ensure_private_directory(final_workspace.parent)
        staged_workspace.replace(final_workspace)
        return StoredProjectSource(
            path=final_workspace / "extracted",
            summary=source_summary,
        )
    except SourceUploadError:
        raise
    except (OSError, zipfile.BadZipFile) as exc:
        raise SourceUploadError("소스 ZIP을 저장하지 못했습니다.") from exc
    finally:
        await source_file.close()
        if incoming_archive.exists():
            incoming_archive.unlink()
        if staged_workspace.exists():
            shutil.rmtree(staged_workspace)
