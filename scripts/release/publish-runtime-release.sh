#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail

python3 -B - "$@" <<'PY'
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.parse


API_ORIGIN = "https://api.github.com"
UPLOAD_ORIGIN = "https://uploads.github.com"
ASSET_REDIRECT_HOST = "release-assets.githubusercontent.com"
API_VERSION = "2026-03-10"
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_ASSET_BYTES = 2 * 1024 * 1024 * 1024
RELEASE_PAGE_LIMIT = 100
PER_PAGE = 100
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SEMVER_TAG = re.compile(
    r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
REPOSITORY = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})$"
)
SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}$")


class PublicationError(Exception):
    pass


def reject(reason: str) -> None:
    raise PublicationError(reason)


def duplicate_safe_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            reject("duplicate json key")
        value[key] = item
    return value


def parse_json(raw: bytes):
    if len(raw) > MAX_JSON_BYTES:
        reject("json response too large")
    try:
        return json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=duplicate_safe_object,
            parse_constant=lambda _: reject("nonfinite json number"),
        )
    except PublicationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        reject("invalid json")


def canonical_json(value) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def positive_integer(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def exact_bool(value) -> bool:
    return isinstance(value, bool)


def parse_arguments(argv: list[str]) -> dict[str, str]:
    allowed = {
        "--release-kind",
        "--repository",
        "--tag",
        "--target-commit",
        "--product-tag-object",
        "--tree",
    }
    if not argv or len(argv) % 2:
        reject("arguments")
    result = {}
    for index in range(0, len(argv), 2):
        key = argv[index]
        value = argv[index + 1]
        if key not in allowed or key in result or not value:
            reject("arguments")
        result[key] = value
    required = {
        "--release-kind",
        "--repository",
        "--tag",
        "--target-commit",
        "--tree",
    }
    if not required.issubset(result):
        reject("arguments")
    kind = result["--release-kind"]
    if kind not in {"product", "candidate"}:
        reject("release kind")
    has_product_object = "--product-tag-object" in result
    if has_product_object != (kind == "product"):
        reject("product tag object")
    return result


def require_tokens() -> tuple[str, str]:
    release = os.environ.get("PGHAR_RELEASE_TOKEN")
    settings = os.environ.get("PGHAR_RELEASE_SETTINGS_TOKEN")
    if (
        release is None
        or settings is None
        or not release.strip()
        or not settings.strip()
        or release == settings
    ):
        reject("credentials")
    return release, settings


def validate_relative_path(value) -> pathlib.PurePosixPath:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 512:
        reject("asset path")
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        reject("asset path")
    path = pathlib.PurePosixPath(value)
    if path.is_absolute() or value != path.as_posix():
        reject("asset path")
    if not path.parts or any(
        part in {".", ".."} or SEGMENT.fullmatch(part) is None
        for part in path.parts
    ):
        reject("asset path")
    return path


def validate_basename(value: str) -> None:
    if (
        SEGMENT.fullmatch(value) is None
        or value.endswith(".")
        or value.endswith(" ")
    ):
        reject("asset basename")


def safe_regular_file(root: pathlib.Path, relative: pathlib.PurePosixPath) -> pathlib.Path:
    current = root
    for component in relative.parts:
        current = current / component
        try:
            current_stat = current.lstat()
        except OSError:
            reject("asset missing")
        if stat.S_ISLNK(current_stat.st_mode):
            reject("asset symlink")
    if not stat.S_ISREG(current_stat.st_mode) or current_stat.st_nlink != 1:
        reject("asset type")
    return current


def file_digest(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def load_local_json(path: pathlib.Path):
    try:
        raw = path.read_bytes()
    except OSError:
        reject("local json")
    return parse_json(raw)


def load_assets(root: pathlib.Path) -> dict[str, dict]:
    manifest_path = safe_regular_file(
        root, pathlib.PurePosixPath("provenance-subjects.json")
    )
    manifest = load_local_json(manifest_path)
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"schema_version", "subjects"}
        or manifest["schema_version"] != 1
        or not isinstance(manifest["subjects"], list)
        or not manifest["subjects"]
        or len(manifest["subjects"]) > 256
    ):
        reject("provenance manifest")
    assets = {}
    relative_seen = set()
    folded_seen = set()
    for row in manifest["subjects"]:
        if not isinstance(row, dict) or set(row) != {"path", "sha256", "size"}:
            reject("provenance subject")
        relative = validate_relative_path(row["path"])
        if relative.as_posix() in relative_seen:
            reject("duplicate asset path")
        relative_seen.add(relative.as_posix())
        name = relative.name
        validate_basename(name)
        folded = name.lower()
        if name in assets or folded in folded_seen:
            reject("duplicate asset basename")
        folded_seen.add(folded)
        path = safe_regular_file(root, relative)
        expected_size = row["size"]
        expected_digest = row["sha256"]
        if (
            not positive_integer(expected_size)
            or not isinstance(expected_digest, str)
            or SHA256.fullmatch(expected_digest) is None
            or path.stat().st_size != expected_size
            or file_digest(path) != expected_digest
        ):
            reject("provenance subject bytes")
        assets[name] = {
            "digest": expected_digest,
            "path": path,
            "relative": relative.as_posix(),
            "size": expected_size,
        }
    provenance_name = manifest_path.name
    validate_basename(provenance_name)
    if provenance_name in assets or provenance_name.lower() in folded_seen:
        reject("duplicate asset basename")
    assets[provenance_name] = {
        "digest": file_digest(manifest_path),
        "path": manifest_path,
        "relative": provenance_name,
        "size": manifest_path.stat().st_size,
    }
    return dict(sorted(assets.items(), key=lambda item: item[0].encode("ascii")))


def load_release_identity(
    root: pathlib.Path,
    kind: str,
    tag: str,
    target_commit: str,
) -> tuple[str, str]:
    runtime_path = safe_regular_file(
        root, pathlib.PurePosixPath("runtime-release.json")
    )
    runtime = load_local_json(runtime_path)
    if (
        not isinstance(runtime, dict)
        or runtime.get("release_kind") != kind
        or not isinstance(runtime.get("source"), dict)
        or runtime["source"].get("commit") != target_commit
    ):
        reject("runtime release identity")
    if kind == "product":
        match = SEMVER_TAG.fullmatch(tag)
        if match is None or runtime.get("version") != tag[1:]:
            reject("product release identity")
        return (
            f"portable-ghar {tag[1:]}",
            "Phase 2 runtime release: independently rebuilt, comparator "
            "validated, provenance attested, and immutable.",
        )
    runner = runtime.get("runner_release")
    if not isinstance(runner, dict):
        reject("candidate release identity")
    version = runner.get("version")
    evidence = runner.get("observation_evidence")
    if (
        not isinstance(version, str)
        or SEMVER_TAG.fullmatch(version) is None
        or not isinstance(evidence, str)
        or SHA256.fullmatch(evidence) is None
        or tag != f"runner-candidate-{version}-{evidence}-{target_commit}"
    ):
        reject("candidate release identity")
    return (
        f"portable-ghar runner candidate {version}",
        f"Qualified immutable runner candidate {version} bound to observation "
        f"{evidence}.",
    )


class GitHub:
    def __init__(
        self,
        repository: str,
        release_token: str,
        settings_token: str,
        temporary: pathlib.Path,
    ):
        self.repository = repository
        self.temporary = temporary
        self.curl = shutil.which("curl")
        if self.curl is None:
            reject("curl unavailable")
        self.release_headers = temporary / "release.headers"
        self.settings_headers = temporary / "settings.headers"
        self.release_headers.write_text(
            f"Authorization: Bearer {release_token}\n", encoding="utf-8"
        )
        self.settings_headers.write_text(
            f"Authorization: Bearer {settings_token}\n", encoding="utf-8"
        )
        os.chmod(self.release_headers, 0o600)
        os.chmod(self.settings_headers, 0o600)
        self.counter = 0
        self.child_environment = os.environ.copy()
        for key in (
            "PGHAR_RELEASE_TOKEN",
            "PGHAR_RELEASE_SETTINGS_TOKEN",
            "GITHUB_TOKEN",
            "GH_TOKEN",
        ):
            self.child_environment.pop(key, None)

    def _transfer(
        self,
        *,
        method: str,
        url: str,
        accept: str,
        header_file: pathlib.Path | None,
        data_path: pathlib.Path | None = None,
        content_type: str | None = None,
        maximum: int = MAX_JSON_BYTES,
    ) -> tuple[int, pathlib.Path, str]:
        self.counter += 1
        output = self.temporary / f"response-{self.counter}.body"
        command = [
            self.curl,
            "--disable",
            "--silent",
            "--show-error",
            "--request",
            method,
            "--connect-timeout",
            "10",
            "--max-time",
            "60",
            "--max-redirs",
            "0",
            "--max-filesize",
            str(maximum),
            "--proto",
            "=https",
            "--tlsv1.2",
            "--header",
            f"Accept: {accept}",
            "--header",
            f"X-GitHub-Api-Version: {API_VERSION}",
        ]
        if header_file is not None:
            command.extend(["--header", f"@{header_file}"])
        if content_type is not None:
            command.extend(["--header", f"Content-Type: {content_type}"])
        if data_path is not None:
            command.extend(["--data-binary", f"@{data_path}"])
        command.extend(
            [
                "--output",
                os.fspath(output),
                "--write-out",
                "%{http_code}\n%{redirect_url}",
                url,
            ]
        )
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                env=self.child_environment,
                timeout=65,
            )
        except (OSError, subprocess.TimeoutExpired):
            reject("transport")
        if completed.returncode != 0 or completed.stderr:
            reject("transport")
        try:
            rendered = completed.stdout.decode("utf-8", "strict")
        except UnicodeDecodeError:
            reject("transport status")
        status_text, separator, redirect = rendered.partition("\n")
        if (
            not re.fullmatch(r"[0-9]{3}", status_text)
            or (separator and "\n" in redirect)
        ):
            reject("transport status")
        try:
            output_stat = output.lstat()
        except OSError:
            reject("transport body")
        if (
            not stat.S_ISREG(output_stat.st_mode)
            or stat.S_ISLNK(output_stat.st_mode)
            or output_stat.st_nlink != 1
            or output_stat.st_size > maximum
        ):
            reject("response too large")
        return int(status_text), output, redirect

    def _request(
        self,
        *,
        method: str,
        url: str,
        accept: str,
        header_file: pathlib.Path | None,
        data_path: pathlib.Path | None = None,
        content_type: str | None = None,
        maximum: int = MAX_JSON_BYTES,
    ) -> tuple[int, bytes, str]:
        status, output, redirect = self._transfer(
            method=method,
            url=url,
            accept=accept,
            header_file=header_file,
            data_path=data_path,
            content_type=content_type,
            maximum=maximum,
        )
        try:
            body = output.read_bytes()
        except OSError:
            reject("transport body")
        return status, body, redirect

    def settings(self) -> None:
        url = f"{API_ORIGIN}/repos/{self.repository}/immutable-releases"
        status, body, redirect = self._request(
            method="GET",
            url=url,
            accept="application/vnd.github+json",
            header_file=self.settings_headers,
        )
        if redirect or status != 200:
            reject("immutable settings unavailable")
        value = parse_json(body)
        if (
            not isinstance(value, dict)
            or value.get("enabled") is not True
            or (
                "enforced_by_owner" in value
                and not exact_bool(value["enforced_by_owner"])
            )
        ):
            reject("immutable settings disabled")

    def api(
        self,
        method: str,
        path: str,
        *,
        data: bytes | None = None,
    ) -> tuple[int, bytes]:
        if path == f"/repos/{self.repository}/immutable-releases":
            reject("credential crossover")
        if not path.startswith(f"/repos/{self.repository}/"):
            reject("api path")
        data_path = None
        if data is not None:
            self.counter += 1
            data_path = self.temporary / f"request-{self.counter}.json"
            data_path.write_bytes(data)
            os.chmod(data_path, 0o600)
        status, body, redirect = self._request(
            method=method,
            url=f"{API_ORIGIN}{path}",
            accept="application/vnd.github+json",
            header_file=self.release_headers,
            data_path=data_path,
            content_type="application/json" if data_path is not None else None,
        )
        if redirect:
            reject("api redirect")
        return status, body

    def upload(self, release_id: int, name: str, path: pathlib.Path) -> tuple[int, bytes]:
        encoded = urllib.parse.quote(name, safe="")
        url = (
            f"{UPLOAD_ORIGIN}/repos/{self.repository}/releases/"
            f"{release_id}/assets?name={encoded}"
        )
        status, body, redirect = self._request(
            method="POST",
            url=url,
            accept="application/vnd.github+json",
            header_file=self.release_headers,
            data_path=path,
            content_type="application/octet-stream",
        )
        if redirect:
            reject("upload redirect")
        return status, body

    def download_asset(
        self,
        asset_id: int,
        *,
        expected_size: int,
        expected_digest: str,
    ) -> None:
        if (
            not positive_integer(expected_size)
            or expected_size > MAX_ASSET_BYTES
            or SHA256.fullmatch(expected_digest) is None
        ):
            reject("asset expectation")
        url = (
            f"{API_ORIGIN}/repos/{self.repository}/releases/assets/{asset_id}"
        )
        status, download, redirect = self._transfer(
            method="GET",
            url=url,
            accept="application/octet-stream",
            header_file=self.release_headers,
            maximum=expected_size,
        )
        if status == 302 and redirect:
            parsed = urllib.parse.urlsplit(redirect)
            if (
                parsed.scheme != "https"
                or parsed.hostname != ASSET_REDIRECT_HOST
                or parsed.username is not None
                or parsed.password is not None
                or parsed.fragment
                or parsed.netloc != ASSET_REDIRECT_HOST
            ):
                reject("asset redirect")
            try:
                download.unlink()
            except OSError:
                reject("asset redirect")
            second_status, download, second_redirect = self._transfer(
                method="GET",
                url=redirect,
                accept="application/octet-stream",
                header_file=None,
                maximum=expected_size,
            )
            if second_status != 200 or second_redirect:
                reject("asset redirect")
        elif status != 200 or redirect:
            reject("asset download")
        try:
            size = download.stat().st_size
        except OSError:
            reject("asset bytes")
        if (
            size != expected_size
            or file_digest(download) != expected_digest
        ):
            reject("asset bytes")
        try:
            download.unlink()
        except OSError:
            reject("asset bytes")


class Publisher:
    def __init__(
        self,
        github: GitHub,
        *,
        kind: str,
        repository: str,
        tag: str,
        target_commit: str,
        product_tag_object: str | None,
        title: str,
        body: str,
        assets: dict[str, dict],
    ):
        self.github = github
        self.kind = kind
        self.repository = repository
        self.tag = tag
        self.target_commit = target_commit
        self.product_tag_object = product_tag_object
        self.title = title
        self.body = body
        self.assets = assets
        self.bound_release_id = None
        self.create_attempted = False
        self.candidate_ref_create_attempted = False

    @property
    def encoded_tag(self) -> str:
        return urllib.parse.quote(self.tag, safe="")

    def parse_ref(self, value, expected_type: str, expected_sha: str) -> None:
        if (
            not isinstance(value, dict)
            or value.get("ref") != f"refs/tags/{self.tag}"
            or not isinstance(value.get("object"), dict)
            or value["object"].get("type") != expected_type
            or value["object"].get("sha") != expected_sha
        ):
            reject("ref identity")

    def product_ref(self) -> None:
        status, body = self.github.api(
            "GET",
            f"/repos/{self.repository}/git/ref/tags/{self.encoded_tag}",
        )
        if status != 200:
            reject("product ref")
        value = parse_json(body)
        self.parse_ref(value, "tag", self.product_tag_object)
        status, body = self.github.api(
            "GET",
            f"/repos/{self.repository}/git/tags/{self.product_tag_object}",
        )
        if status != 200:
            reject("product tag")
        tag_value = parse_json(body)
        if (
            not isinstance(tag_value, dict)
            or tag_value.get("tag") != self.tag
            or not isinstance(tag_value.get("object"), dict)
            or tag_value["object"].get("type") != "commit"
            or tag_value["object"].get("sha") != self.target_commit
            or not isinstance(tag_value.get("verification"), dict)
            or tag_value["verification"].get("verified") is not True
        ):
            reject("product tag")

    def read_candidate_ref(self) -> bool:
        status, body = self.github.api(
            "GET",
            f"/repos/{self.repository}/git/ref/tags/{self.encoded_tag}",
        )
        if status == 404:
            return False
        if status != 200:
            reject("candidate ref")
        self.parse_ref(parse_json(body), "commit", self.target_commit)
        return True

    def prove_ref(self) -> None:
        if self.kind == "product":
            self.product_ref()
        elif not self.read_candidate_ref():
            reject("candidate ref missing")

    def create_candidate_ref(self) -> None:
        if self.candidate_ref_create_attempted:
            reject("candidate ref create repeated")
        self.github.settings()
        if self.read_candidate_ref():
            return
        self.candidate_ref_create_attempted = True
        request = canonical_json(
            {
                "ref": f"refs/tags/{self.tag}",
                "sha": self.target_commit,
            }
        )
        status, body = self.github.api(
            "POST",
            f"/repos/{self.repository}/git/refs",
            data=request,
        )
        if status == 201:
            self.parse_ref(parse_json(body), "commit", self.target_commit)
        elif status not in {409, 422}:
            reject("candidate ref create")
        if not self.read_candidate_ref():
            reject("candidate ref create unresolved")

    def scan_releases(self):
        seen_ids = set()
        matches = []
        target_folded = self.tag.lower()
        for page in range(1, RELEASE_PAGE_LIMIT + 1):
            status, body = self.github.api(
                "GET",
                f"/repos/{self.repository}/releases"
                f"?per_page={PER_PAGE}&page={page}",
            )
            if status != 200:
                reject("release listing")
            rows = parse_json(body)
            if not isinstance(rows, list) or len(rows) > PER_PAGE:
                reject("release listing")
            for row in rows:
                if (
                    not isinstance(row, dict)
                    or not positive_integer(row.get("id"))
                    or not isinstance(row.get("tag_name"), str)
                ):
                    reject("release listing")
                release_id = row["id"]
                tag_name = row["tag_name"]
                if release_id in seen_ids:
                    reject("duplicate release id")
                seen_ids.add(release_id)
                if tag_name == self.tag:
                    matches.append(row)
                elif tag_name.isascii() and tag_name.lower() == target_folded:
                    reject("release tag collision")
            if len(rows) < PER_PAGE:
                break
            if page == RELEASE_PAGE_LIMIT:
                reject("release listing bound")
        if len(matches) > 1:
            reject("duplicate release tag")
        return matches[0] if matches else None

    def validate_release(self, value, state: str) -> int:
        if not isinstance(value, dict):
            reject("release identity")
        release_id = value.get("id")
        if not positive_integer(release_id):
            reject("release identity")
        if (
            value.get("tag_name") != self.tag
            or not isinstance(value.get("target_commitish"), str)
            or value.get("name") != self.title
            or value.get("body") != self.body
            or value.get("prerelease") is not False
            or not exact_bool(value.get("draft"))
            or not exact_bool(value.get("immutable"))
        ):
            reject("release identity")
        if state == "draft":
            if value["draft"] is not True or value["immutable"] is not False:
                reject("release state")
        elif state == "published":
            if value["draft"] is not False or value["immutable"] is not True:
                reject("release state")
        else:
            reject("release state")
        return release_id

    def validate_either_release(self, value) -> tuple[int, str]:
        if not isinstance(value, dict) or not exact_bool(value.get("draft")):
            reject("release state")
        state = "draft" if value["draft"] else "published"
        return self.validate_release(value, state), state

    def prove_bound_release(self, state: str):
        self.prove_ref()
        value = self.scan_releases()
        if value is None:
            reject("bound release missing")
        release_id = self.validate_release(value, state)
        if self.bound_release_id is None or release_id != self.bound_release_id:
            reject("release id drift")
        return value

    def create_release(self):
        if self.create_attempted:
            reject("release create repeated")
        self.create_attempted = True
        self.prove_ref()
        if self.scan_releases() is not None:
            reject("release appeared before create")
        self.github.settings()
        self.prove_ref()
        if self.scan_releases() is not None:
            reject("release appeared before create")
        self.prove_ref()
        request = canonical_json(
            {
                "body": self.body,
                "draft": True,
                "make_latest": "false",
                "name": self.title,
                "prerelease": False,
                "tag_name": self.tag,
                "target_commitish": self.target_commit,
            }
        )
        status, body = self.github.api(
            "POST",
            f"/repos/{self.repository}/releases",
            data=request,
        )
        response_id = None
        if status == 201:
            response_id = self.validate_release(parse_json(body), "draft")
        elif status not in {409, 422}:
            reject("release create")
        self.prove_ref()
        value = self.scan_releases()
        if value is None:
            reject("release create unresolved")
        release_id, state = self.validate_either_release(value)
        if response_id is not None and response_id != release_id:
            reject("release create id")
        self.bound_release_id = release_id
        return value, state

    def list_assets(self) -> list[dict]:
        rows = []
        seen_ids = set()
        seen_names = set()
        seen_folded = set()
        page = 1
        while True:
            status, body = self.github.api(
                "GET",
                f"/repos/{self.repository}/releases/"
                f"{self.bound_release_id}/assets"
                f"?per_page={PER_PAGE}&page={page}",
            )
            if status != 200:
                reject("asset listing")
            page_rows = parse_json(body)
            if not isinstance(page_rows, list) or len(page_rows) > PER_PAGE:
                reject("asset listing")
            for row in page_rows:
                if (
                    not isinstance(row, dict)
                    or not positive_integer(row.get("id"))
                    or not isinstance(row.get("name"), str)
                    or not isinstance(row.get("state"), str)
                ):
                    reject("asset listing")
                asset_id = row["id"]
                name = row["name"]
                folded = name.lower()
                if (
                    asset_id in seen_ids
                    or name in seen_names
                    or folded in seen_folded
                ):
                    reject("duplicate asset")
                seen_ids.add(asset_id)
                seen_names.add(name)
                seen_folded.add(folded)
                rows.append(row)
                if len(rows) > len(self.assets):
                    reject("extra asset")
            if len(page_rows) < PER_PAGE:
                break
            page += 1
            if page > len(self.assets) // PER_PAGE + 2:
                reject("asset listing bound")
        return rows

    def verify_asset_bytes(self, row: dict, expected: dict) -> None:
        size = row.get("size")
        digest = row.get("digest")
        if not positive_integer(size) or size != expected["size"]:
            reject("asset size")
        if digest is not None:
            if (
                not isinstance(digest, str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
                or digest != f"sha256:{expected['digest']}"
            ):
                reject("asset digest")
        self.github.download_asset(
            row["id"],
            expected_size=expected["size"],
            expected_digest=expected["digest"],
        )

    def assess_assets(self) -> tuple[list[str], dict | None]:
        rows = self.list_assets()
        uploaded = set()
        starters = []
        for row in rows:
            name = row["name"]
            if name not in self.assets:
                reject("extra asset")
            if row["state"] == "uploaded":
                self.verify_asset_bytes(row, self.assets[name])
                uploaded.add(name)
            elif row["state"] == "starter":
                starters.append(row)
            else:
                reject("asset state")
        if len(starters) > 1:
            reject("starter residue")
        starter = starters[0] if starters else None
        missing = sorted(set(self.assets) - uploaded, key=lambda value: value.encode())
        if starter is not None and starter["name"] not in missing:
            reject("starter residue")
        return missing, starter

    def delete_starter(self, starter: dict) -> None:
        self.prove_bound_release("draft")
        _, current = self.assess_assets()
        if (
            current is None
            or current["id"] != starter["id"]
            or current["name"] != starter["name"]
        ):
            reject("starter drift")
        self.github.settings()
        self.prove_bound_release("draft")
        _, current = self.assess_assets()
        if (
            current is None
            or current["id"] != starter["id"]
            or current["name"] != starter["name"]
        ):
            reject("starter drift")
        self.prove_ref()
        status, _ = self.github.api(
            "DELETE",
            f"/repos/{self.repository}/releases/assets/{starter['id']}",
        )
        if status != 204:
            reject("starter delete")
        self.prove_bound_release("draft")
        _, after = self.assess_assets()
        if after is not None:
            reject("starter delete")

    def upload_missing(self, name: str) -> None:
        self.prove_bound_release("draft")
        missing, starter = self.assess_assets()
        if starter is not None or name not in missing:
            reject("upload precondition")
        self.github.settings()
        self.prove_bound_release("draft")
        missing, starter = self.assess_assets()
        if starter is not None or name not in missing:
            reject("upload precondition")
        self.prove_ref()
        status, body = self.github.upload(
            self.bound_release_id,
            name,
            self.assets[name]["path"],
        )
        if status != 201:
            reject("asset upload")
        response = parse_json(body)
        if (
            not isinstance(response, dict)
            or not positive_integer(response.get("id"))
            or response.get("name") != name
            or response.get("state") != "uploaded"
        ):
            reject("asset upload")
        self.prove_bound_release("draft")
        after_missing, after_starter = self.assess_assets()
        if after_starter is not None or name in after_missing:
            reject("asset upload")

    def verify_published(self) -> None:
        self.github.settings()
        self.prove_bound_release("published")
        missing, starter = self.assess_assets()
        if missing or starter is not None:
            reject("published asset set")

    def publish_draft(self) -> None:
        self.prove_bound_release("draft")
        missing, starter = self.assess_assets()
        if missing or starter is not None:
            reject("draft incomplete")
        self.github.settings()
        self.prove_bound_release("draft")
        missing, starter = self.assess_assets()
        if missing or starter is not None:
            reject("draft incomplete")
        self.prove_ref()
        request = canonical_json({"draft": False, "make_latest": "false"})
        status, body = self.github.api(
            "PATCH",
            f"/repos/{self.repository}/releases/{self.bound_release_id}",
            data=request,
        )
        if status != 200:
            reject("publish transition")
        response_id = self.validate_release(parse_json(body), "published")
        if response_id != self.bound_release_id:
            reject("publish release id")
        self.prove_ref()
        self.verify_published()

    def run(self) -> None:
        if self.kind == "product":
            self.product_ref()
        else:
            candidate_exists = self.read_candidate_ref()
            release_before_ref = self.scan_releases()
            if not candidate_exists:
                if release_before_ref is not None:
                    reject("release without candidate ref")
                self.create_candidate_ref()
        self.prove_ref()
        release = self.scan_releases()
        if release is None:
            release, state = self.create_release()
        else:
            release_id, state = self.validate_either_release(release)
            self.bound_release_id = release_id
        if state == "published":
            self.verify_published()
            return
        self.validate_release(release, "draft")
        missing, starter = self.assess_assets()
        if starter is not None:
            self.delete_starter(starter)
            missing, starter = self.assess_assets()
        if starter is not None:
            reject("starter residue")
        for name in missing:
            self.upload_missing(name)
        self.publish_draft()


def main(argv: list[str]) -> None:
    arguments = parse_arguments(argv)
    release_token, settings_token = require_tokens()
    repository = arguments["--repository"]
    tag = arguments["--tag"]
    target_commit = arguments["--target-commit"]
    if REPOSITORY.fullmatch(repository) is None or SHA40.fullmatch(target_commit) is None:
        reject("identity")
    product_tag_object = arguments.get("--product-tag-object")
    if product_tag_object is not None and SHA40.fullmatch(product_tag_object) is None:
        reject("product tag object")
    tree = pathlib.Path(arguments["--tree"])
    if not tree.is_absolute():
        reject("tree")
    try:
        resolved_tree = tree.resolve(strict=True)
    except OSError:
        reject("tree")
    if resolved_tree != tree or not tree.is_dir() or tree.is_symlink():
        reject("tree")
    assets = load_assets(tree)
    title, body = load_release_identity(
        tree,
        arguments["--release-kind"],
        tag,
        target_commit,
    )
    temporary = pathlib.Path(
        tempfile.mkdtemp(prefix=".portable-ghar-publication.")
    )
    os.chmod(temporary, 0o700)
    caught = None
    try:
        github = GitHub(
            repository,
            release_token,
            settings_token,
            temporary,
        )
        Publisher(
            github,
            kind=arguments["--release-kind"],
            repository=repository,
            tag=tag,
            target_commit=target_commit,
            product_tag_object=product_tag_object,
            title=title,
            body=body,
            assets=assets,
        ).run()
    except BaseException as error:
        caught = error
    cleanup_error = None
    try:
        shutil.rmtree(temporary)
    except OSError as error:
        cleanup_error = error
    if cleanup_error is not None:
        reject("local cleanup")
    if caught is not None:
        raise caught


try:
    main(sys.argv[1:])
except PublicationError as error:
    print(f"publication failed: {error}", file=sys.stderr)
    raise SystemExit(1)
except BaseException:
    print("publication failed: internal", file=sys.stderr)
    raise SystemExit(1)
PY
