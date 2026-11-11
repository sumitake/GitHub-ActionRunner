# SPDX-License-Identifier: MPL-2.0
"""SSM SecureString handoff for one ephemeral JIT config."""

from __future__ import annotations

import re
from typing import Any

from botocore.exceptions import ClientError

_NAME = re.compile(r"/overflow-watcher/jit/[0-9a-f]{64}\Z")


def parameter_name(token: str) -> str:
    """Return the SSM name for a 64-hex ClientToken."""
    name = f"/overflow-watcher/jit/{token}"
    if _NAME.fullmatch(name) is None:
        raise ValueError("jit parameter name")
    return name


def valid_parameter_name(name: str) -> bool:
    return _NAME.fullmatch(name) is not None


class JitParams:
    """Put and delete one reservation's secret. The value is not logged."""

    def __init__(self, client: Any) -> None:
        self._client = client

    def put(self, name: str, value: str) -> str:
        """Store the secret. `exists` means the first put won and the bytes stay."""
        if not valid_parameter_name(name):
            raise ValueError("jit parameter name")
        if not isinstance(value, str) or value == "":
            raise ValueError("jit secret")
        try:
            self._client.put_parameter(
                Name=name,
                Value=value,
                Type="SecureString",
                Overwrite=False,
                Tier="Advanced",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ParameterAlreadyExists":
                return "exists"
            raise
        return "ready"

    def delete(self, name: str) -> None:
        """Remove the secret. A missing parameter is success."""
        try:
            self._client.delete_parameter(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ParameterNotFound":
                return
            raise
