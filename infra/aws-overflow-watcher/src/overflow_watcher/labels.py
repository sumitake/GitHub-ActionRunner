# SPDX-License-Identifier: MPL-2.0
"""F1 label admission. Exact case. Empty runs-on is denied."""

from __future__ import annotations

ALLOW = frozenset({"self-hosted", "Linux", "X64", "homelab-linux"})
EXACT_DENY = frozenset({"rhonas", "macOS", "intel-labmac"})


def is_dispatch_label(label: str) -> bool:
    """A CCG dispatch label contains the substring 'dispatch'."""
    return "dispatch" in label


def labels_admitted(labels: list[str] | tuple[str, ...]) -> bool:
    """Admit only a non-empty subset of the homelab allowlist."""
    if not labels:
        return False
    for label in labels:
        if label in EXACT_DENY:
            return False
        if label.startswith("ubuntu-") or label.startswith("macos-"):
            return False
        if is_dispatch_label(label):
            return False
        if label not in ALLOW:
            return False
    return True
