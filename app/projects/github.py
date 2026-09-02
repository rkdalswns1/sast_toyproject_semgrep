"""Bounded public GitHub archive intake using the existing ZIP security boundary."""

from __future__ import annotations

import re
import tempfile
from dataclasses import dataclass
from urllib.parse import quote, urljoin, urlsplit

import httpx
from fastapi import UploadFile

from app.config import Settings
from app.projects.upload import StoredProjectSource, SourceUploadError, save_project_source


GITHUB_API_ROOT = "https://api.github.com"
GITHUB_API_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "sast-mvp-public-source-import",
}
ALLOWED_ARCHIVE_HOSTS = frozenset({"api.github.com", "codeload.github.com"})
OWNER_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\Z")
REPOSITORY_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")
COMMIT_PATTERN = re.compile(r"[0-9a-fA-F]{40}\Z")
REF_PATTERN = re.compile(r"[A-Za-z0-9._/-]{1,255}\Z")
MAX_API_RESPONSE_BYTES = 1024 * 1024
MAX_REDIRECTS = 3


class GitHubSourceError(ValueError):
    """Raised when a public GitHub source cannot be safely collected."""


@dataclass(frozen=True, slots=True)
class GitHubRepository:
    owner: str
    name: str
    url: str


@dataclass(frozen=True, slots=True)
class GitHubProjectSource:
    stored_source: StoredProjectSource
    repository_url: str
    requested_ref: str | None
    commit_sha: str


def parse_github_repository_url(raw_url: str) -> GitHubRepository:
    """Accept only a canonical public github.com owner/repository URL."""
    value = raw_url.strip()
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise GitHubSourceError("올바른 GitHub 저장소 URL을 입력하세요.") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise GitHubSourceError("공개 https://github.com 저장소 URL만 사용할 수 있습니다.")
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 2 or parsed.path.endswith("/"):
        raise GitHubSourceError("GitHub URL은 owner/repository 형식이어야 합니다.")
    owner, repository = parts
    if repository.endswith(".git"):
        repository = repository[:-4]
    if (
        not OWNER_PATTERN.fullmatch(owner)
        or not REPOSITORY_PATTERN.fullmatch(repository)
        or repository in {".", ".."}
    ):
        raise GitHubSourceError("GitHub owner 또는 repository 이름이 올바르지 않습니다.")
    return GitHubRepository(
        owner=owner,
        name=repository,
        url=f"https://github.com/{owner}/{repository}",
    )


def normalize_github_ref(raw_ref: str | None) -> str | None:
    value = raw_ref.strip() if raw_ref else ""
    if not value:
        return None
    if (
        not REF_PATTERN.fullmatch(value)
        or value.startswith(("/", "."))
        or value.endswith(("/", "."))
        or ".." in value
        or "//" in value
        or "@{" in value
        or value.endswith(".lock")
    ):
        raise GitHubSourceError("GitHub ref 형식이 올바르지 않습니다.")
    return value


def _safe_api_json(response: httpx.Response, *, not_found_message: str) -> dict[str, object]:
    if response.status_code == 404:
        raise GitHubSourceError(not_found_message)
    if response.status_code in {403, 429}:
        raise GitHubSourceError("GitHub 요청 제한에 도달했습니다. 잠시 후 다시 시도하세요.")
    if response.status_code != 200:
        raise GitHubSourceError("GitHub 저장소 정보를 가져오지 못했습니다.")
    if len(response.content) > MAX_API_RESPONSE_BYTES:
        raise GitHubSourceError("GitHub API 응답 크기 제한을 초과했습니다.")
    try:
        data = response.json()
    except ValueError as exc:
        raise GitHubSourceError("GitHub API 응답을 확인할 수 없습니다.") from exc
    if not isinstance(data, dict):
        raise GitHubSourceError("GitHub API 응답을 확인할 수 없습니다.")
    return data


async def _resolve_commit(
    client: httpx.AsyncClient, repository: GitHubRepository, requested_ref: str | None
) -> tuple[str | None, str]:
    ref = requested_ref
    repository_api = (
        f"{GITHUB_API_ROOT}/repos/{quote(repository.owner, safe='')}/"
        f"{quote(repository.name, safe='')}"
    )
    if ref is None:
        response = await client.get(repository_api, headers=GITHUB_API_HEADERS)
        data = _safe_api_json(
            response, not_found_message="공개 GitHub 저장소를 찾을 수 없습니다."
        )
        default_branch = data.get("default_branch")
        if not isinstance(default_branch, str):
            raise GitHubSourceError("GitHub 기본 branch를 확인할 수 없습니다.")
        ref = normalize_github_ref(default_branch)
        if ref is None:
            raise GitHubSourceError("GitHub 기본 branch를 확인할 수 없습니다.")

    commit_response = await client.get(
        f"{repository_api}/commits/{quote(ref, safe='')}",
        headers=GITHUB_API_HEADERS,
    )
    commit_data = _safe_api_json(
        commit_response,
        not_found_message="공개 GitHub 저장소의 ref를 찾을 수 없습니다.",
    )
    sha = commit_data.get("sha")
    if not isinstance(sha, str) or not COMMIT_PATTERN.fullmatch(sha):
        raise GitHubSourceError("GitHub commit SHA를 확인할 수 없습니다.")
    return requested_ref, sha.lower()


async def _download_archive(
    client: httpx.AsyncClient,
    *,
    repository: GitHubRepository,
    commit_sha: str,
    max_bytes: int,
) -> tempfile.SpooledTemporaryFile[bytes]:
    url = (
        f"{GITHUB_API_ROOT}/repos/{quote(repository.owner, safe='')}/"
        f"{quote(repository.name, safe='')}/zipball/{commit_sha}"
    )
    response: httpx.Response | None = None
    spool = tempfile.SpooledTemporaryFile(max_size=min(max_bytes, 2 * 1024 * 1024))
    try:
        for redirect_count in range(MAX_REDIRECTS + 1):
            request = client.build_request("GET", url, headers=GITHUB_API_HEADERS)
            response = await client.send(request, stream=True)
            if response.status_code in {301, 302, 303, 307, 308}:
                if redirect_count == MAX_REDIRECTS:
                    raise GitHubSourceError("GitHub archive redirect 제한을 초과했습니다.")
                location = response.headers.get("location")
                await response.aclose()
                response = None
                if not location:
                    raise GitHubSourceError("GitHub archive 위치를 확인할 수 없습니다.")
                next_url = urlsplit(urljoin(url, location))
                if (
                    next_url.scheme != "https"
                    or next_url.hostname not in ALLOWED_ARCHIVE_HOSTS
                    or next_url.username is not None
                    or next_url.password is not None
                    or next_url.port is not None
                ):
                    raise GitHubSourceError("허용되지 않은 GitHub archive 위치입니다.")
                url = next_url.geturl()
                continue
            if response.status_code == 404:
                raise GitHubSourceError("GitHub archive를 찾을 수 없습니다.")
            if response.status_code in {403, 429}:
                raise GitHubSourceError("GitHub 요청 제한에 도달했습니다. 잠시 후 다시 시도하세요.")
            if response.status_code != 200:
                raise GitHubSourceError("GitHub archive를 내려받지 못했습니다.")
            content_length = response.headers.get("content-length")
            if content_length and content_length.isdigit() and int(content_length) > max_bytes:
                raise GitHubSourceError("GitHub archive 크기 제한을 초과했습니다.")
            downloaded = 0
            async for chunk in response.aiter_bytes():
                downloaded += len(chunk)
                if downloaded > max_bytes:
                    raise GitHubSourceError("GitHub archive 크기 제한을 초과했습니다.")
                spool.write(chunk)
            spool.seek(0)
            return spool
        raise GitHubSourceError("GitHub archive를 내려받지 못했습니다.")
    except (httpx.TimeoutException, httpx.NetworkError) as exc:
        spool.close()
        raise GitHubSourceError("GitHub 연결 시간이 초과되었거나 연결할 수 없습니다.") from exc
    except Exception:
        spool.close()
        raise
    finally:
        if response is not None:
            await response.aclose()


async def collect_github_project_source(
    repository_url: str,
    repository_ref: str | None,
    *,
    project_id: int,
    settings: Settings,
    client: httpx.AsyncClient | None = None,
) -> GitHubProjectSource:
    """Resolve a public repository commit, download it, then reuse safe ZIP intake."""
    repository = parse_github_repository_url(repository_url)
    requested_ref = normalize_github_ref(repository_ref)
    owns_client = client is None
    active_client = client or httpx.AsyncClient(
        timeout=httpx.Timeout(settings.github_download_timeout_seconds),
        follow_redirects=False,
    )
    try:
        stored_ref, commit_sha = await _resolve_commit(
            active_client, repository, requested_ref
        )
        spool = await _download_archive(
            active_client,
            repository=repository,
            commit_sha=commit_sha,
            max_bytes=settings.max_upload_bytes,
        )
        upload = UploadFile(
            file=spool,
            filename=f"{repository.name}-{commit_sha[:12]}.zip",
        )
        try:
            stored_source = await save_project_source(
                upload, project_id=project_id, settings=settings
            )
        except SourceUploadError as exc:
            raise GitHubSourceError(str(exc)) from exc
        return GitHubProjectSource(
            stored_source=stored_source,
            repository_url=repository.url,
            requested_ref=stored_ref,
            commit_sha=commit_sha,
        )
    except httpx.HTTPError as exc:
        raise GitHubSourceError(
            "GitHub 연결 시간이 초과되었거나 연결할 수 없습니다."
        ) from exc
    finally:
        if owns_client:
            await active_client.aclose()
