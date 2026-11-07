# SPDX-License-Identifier: MPL-2.0
"""GitHub App JWT signing via openssl. Failure returns no token."""

from __future__ import annotations

import base64
import json
import subprocess
import tempfile
import urllib.error
import urllib.request

from overflow_watcher.config import Config


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def sign_app_jwt(app_identifier: str, pem: str, now: int) -> str | None:
    header = _b64url(b'{"alg":"RS256","typ":"JWT"}')
    body = _b64url(
        json.dumps({"iat": now - 60, "exp": now + 540, "iss": app_identifier}, separators=(",", ":")).encode(
            "utf-8"
        )
    )
    signing_input = f"{header}.{body}".encode("ascii")
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            handle.write(pem)
            handle.flush()
            result = subprocess.run(
                ["openssl", "dgst", "-sha256", "-sign", handle.name],
                input=signing_input,
                capture_output=True,
                check=False,
            )
    except OSError:
        return None
    if result.returncode != 0 or not result.stdout:
        return None
    return signing_input.decode("ascii") + "." + _b64url(result.stdout)


def installation_token(cfg: Config, installation: str, now: int) -> str | None:
    """Exchange an App JWT for an installation token. None fails closed."""
    jwt = sign_app_jwt(cfg.app_identifier, cfg.app_pem, now)
    if jwt is None:
        return None
    url = f"https://api.github.com/app/installations/{installation}/access_tokens"
    request = urllib.request.Request(url, data=b"{}", method="POST")
    request.add_header("Authorization", f"Bearer {jwt}")
    request.add_header("Accept", "application/vnd.github+json")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError, OSError):
        return None
    token = payload.get("token") if isinstance(payload, dict) else None
    if not isinstance(token, str) or not token:
        return None
    return token
