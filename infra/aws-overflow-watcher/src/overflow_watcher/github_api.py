# SPDX-License-Identifier: MPL-2.0
"""GitHub App calls used by the poll. Tests inject a fake instead."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from overflow_watcher.config import Config
from overflow_watcher.github_auth import installation_token
from overflow_watcher.inventory import HttpPage, assess_repo
from overflow_watcher.types import CancelUnavailable, Decision, RepoSpec


class LiveGitHub:
    """Installation-token client. Minting failure yields an uncertain decision."""

    def __init__(self, cfg: Config, token: str | None = None) -> None:
        self._cfg = cfg
        self._token = token

    def assess(self, repo: RepoSpec, now: int) -> Decision:
        token = self._token_for(repo.installation, now)
        if not token:
            return Decision(True, "github-token-unavailable", ())
        return assess_repo(_UrllibTransport(token), repo, now)

    def cancel_workflow_run(self, owner: str, repo: str, run_id: str) -> str:
        """Cancel one workflow run. Requires the Actions write permission."""
        token = self._token_for(self._installation(owner, repo), now=0)
        if not token:
            raise CancelUnavailable("github-token-unavailable")
        url = f"https://api.github.com/repos/{owner}/{repo}/actions/runs/{run_id}/cancel"
        request = urllib.request.Request(url, data=b"", method="POST")
        request.add_header("Authorization", f"Bearer {token}")
        request.add_header("Accept", "application/vnd.github+json")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                if response.status not in (202, 201, 204):
                    raise CancelUnavailable(f"http-{response.status}")
        except urllib.error.HTTPError as exc:
            raise CancelUnavailable(f"http-{exc.code}") from exc
        except urllib.error.URLError as exc:
            raise CancelUnavailable("network") from exc
        return "requested"

    def workflow_completed(self, owner: str, repo: str, run_id: str) -> bool | None:
        token = self._token_for(self._installation(owner, repo), now=0)
        if not token:
            return None
        url = f"https://api.github.com/repos/{owner}/{repo}/actions/runs/{run_id}"
        request = urllib.request.Request(url, method="GET")
        request.add_header("Authorization", f"Bearer {token}")
        request.add_header("Accept", "application/vnd.github+json")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                body = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError):
            return None
        status = body.get("status") if isinstance(body, dict) else None
        if status == "completed":
            return True
        if isinstance(status, str):
            return False
        return None

    def _installation(self, owner: str, repo: str) -> str:
        for spec in self._cfg.repos:
            if spec.owner == owner and spec.name == repo:
                return spec.installation
        return ""

    def _token_for(self, installation: str, now: int) -> str | None:
        if self._token:
            return self._token
        if not installation:
            return None
        stamp = now if now else int(time.time())
        return installation_token(self._cfg, installation, stamp)


class _UrllibTransport:
    def __init__(self, token: str) -> None:
        self._token = token

    def get(self, url: str) -> HttpPage:
        request = urllib.request.Request(url, method="GET")
        request.add_header("Authorization", f"Bearer {self._token}")
        request.add_header("Accept", "application/vnd.github+json")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                raw = response.read().decode("utf-8")
                headers = {key: value for key, value in response.headers.items()}
                try:
                    body = json.loads(raw)
                except json.JSONDecodeError:
                    body = None
                return HttpPage(response.status, headers, body, url)
        except urllib.error.HTTPError as exc:
            return HttpPage(exc.code, dict(exc.headers.items()), None, url)
        except urllib.error.URLError:
            return HttpPage(599, {}, None, url)
