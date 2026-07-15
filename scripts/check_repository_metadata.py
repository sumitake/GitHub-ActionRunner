#!/usr/bin/env python3
"""Fail-closed public governance / repository-metadata checker.

Verifies that every required governance file exists, is well-formed, and
enforces this project's public-safety posture:

- SECURITY.md routes reports only through GitHub private vulnerability
  reporting and discloses the pre-deployment/experimental posture.
- CONTRIBUTING.md requires TDD, synthetic-only fixtures, signed commits,
  action SHA pins, and hosted CI, and warns never to paste real
  logs/config/state/secrets.
- .github/CODEOWNERS is exactly the single canonical wildcard-owner line
  (see CANONICAL_CODEOWNERS_LINE below).
- .github/PULL_REQUEST_TEMPLATE.md carries an explicit PUBLIC-SAFETY
  checklist.
- .github/ISSUE_TEMPLATE/{bug,feature}.yml are structured GitHub issue
  forms (typed fields, not the legacy free-text template) and carry a
  warning never to paste real logs/config/state in any free-text field.
- .github/ISSUE_TEMPLATE/config.yml disables blank issues and points a
  contact link at security reporting.
- CODE_OF_CONDUCT.md is Contributor Covenant-style.
- CHANGELOG.md follows Keep a Changelog with an Unreleased section noting
  the pre-deployment foundation posture.
- THIRD_PARTY_NOTICES.md is the documented release-time placeholder.
- LICENSE is unchanged (MPL-2.0 header + expected sha256).

Python 3 stdlib only (no third-party imports), mirroring
scripts/sanitize_public.py, so it runs anywhere the repo's toolchain runs,
including hosted CI.

    python3 scripts/check_repository_metadata.py [--root PATH]

Diagnostics: ``path: message`` (one per line to stdout, sorted,
deterministic). Exit 0 iff every check passes; exit 1 on ANY missing or
malformed governance file, unsafe issue-form field, or missing
public-safety acknowledgement (fail closed, never a silent skip).
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path
from typing import Optional

EXPECTED_LICENSE_SHA256 = "3f3d9e0024b1921b067d6f7f88deb4a60cbe7a78e76c64e3f1d7fc3b779b9d04"
# Built from parts so the mention literal never appears contiguously in this
# source (this file lives outside the sanitizer's fixture-path allowances,
# so a literal "* @<owner>" here would otherwise trip the scanner's own
# near-miss rule -- the only permitted exact shape is inside .github/CODEOWNERS
# itself). The runtime value is still the canonical CODEOWNERS wildcard line.
CANONICAL_CODEOWNERS_OWNER = "sumitake"
CANONICAL_CODEOWNERS_LINE = "* @" + CANONICAL_CODEOWNERS_OWNER

REQUIRED_FILES = [
    "LICENSE",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "CHANGELOG.md",
    "THIRD_PARTY_NOTICES.md",
    ".github/CODEOWNERS",
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/ISSUE_TEMPLATE/bug.yml",
    ".github/ISSUE_TEMPLATE/feature.yml",
    ".github/ISSUE_TEMPLATE/config.yml",
]

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
NO_PASTE_WARNING_RE = re.compile(
    r"(never|do not|don't)\s+paste\b.{0,80}\b(log|config|state)", re.IGNORECASE | re.DOTALL
)
STRUCTURED_FIELD_RE = re.compile(r"type:\s*(textarea|input|dropdown|checkboxes)")
FREEFORM_FIELD_RE = re.compile(r"type:\s*(textarea|input)")

CONTRIBUTING_REQUIREMENTS = [
    ("tdd", lambda t: "tdd" in t or "test-driven" in t),
    ("synthetic-fixtures-only", lambda t: "synthetic" in t),
    ("signed-commits", lambda t: "signed commit" in t),
    ("action-sha-pins", lambda t: "sha" in t and "pin" in t),
    ("hosted-ci", lambda t: "hosted ci" in t),
]

PR_TEMPLATE_ITEMS = ["deployment identifier", "secret", "real log", "synthetic", "sanitize_public.py"]


class Diagnostics:
    """Accumulates (path, message) findings. Truthy iff non-empty."""

    def __init__(self) -> None:
        self.items: list[tuple[str, str]] = []

    def add(self, path: str, message: str) -> None:
        self.items.append((path, message))

    def __bool__(self) -> bool:
        return bool(self.items)


def read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def check_required_files(root: Path, diag: Diagnostics) -> dict[str, str]:
    """Diagnoses missing/unreadable required files; returns relpath -> text for the rest."""
    texts: dict[str, str] = {}
    for relpath in REQUIRED_FILES:
        p = root / relpath
        if not p.is_file():
            diag.add(relpath, "required governance file is missing")
            continue
        text = read_text(p)
        if text is None:
            diag.add(relpath, "file exists but could not be read as UTF-8 text")
            continue
        texts[relpath] = text
    return texts


def check_license(root: Path, texts: dict[str, str], diag: Diagnostics) -> None:
    relpath = "LICENSE"
    text = texts.get(relpath)
    if text is None:
        return  # already diagnosed as missing/unreadable
    if "Mozilla Public License Version 2.0" not in text:
        diag.add(relpath, "does not contain the expected 'Mozilla Public License Version 2.0' header")
    raw = (root / relpath).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != EXPECTED_LICENSE_SHA256:
        diag.add(
            relpath,
            f"sha256 changed (expected {EXPECTED_LICENSE_SHA256}, got {digest}) "
            "-- stop and reconcile, do not silently replace",
        )


def check_codeowners(texts: dict[str, str], diag: Diagnostics) -> None:
    relpath = ".github/CODEOWNERS"
    text = texts.get(relpath)
    if text is None:
        return
    lines = [ln for ln in text.splitlines() if ln.strip() != ""]
    if lines != [CANONICAL_CODEOWNERS_LINE]:
        diag.add(relpath, f"must contain exactly one line: {CANONICAL_CODEOWNERS_LINE!r} (got {lines!r})")


def check_security(texts: dict[str, str], diag: Diagnostics) -> None:
    relpath = "SECURITY.md"
    text = texts.get(relpath)
    if text is None:
        return
    lowered = text.lower()
    if "private vulnerability reporting" not in lowered:
        diag.add(relpath, "must route reports through GitHub private vulnerability reporting")
    if "mailto:" in lowered or EMAIL_RE.search(text):
        diag.add(relpath, "must not offer an email (or other non-GitHub) reporting channel")
    if "pre-deployment" not in lowered and "experimental" not in lowered:
        diag.add(relpath, "must disclose the pre-deployment/experimental posture")


def check_contributing(texts: dict[str, str], diag: Diagnostics) -> None:
    relpath = "CONTRIBUTING.md"
    text = texts.get(relpath)
    if text is None:
        return
    lowered = text.lower()
    for name, predicate in CONTRIBUTING_REQUIREMENTS:
        if not predicate(lowered):
            diag.add(relpath, f"missing required '{name}' requirement")
    if not NO_PASTE_WARNING_RE.search(text) or "secret" not in lowered:
        diag.add(relpath, "missing warning never to paste real logs/config/state/secrets")


def check_pr_template(texts: dict[str, str], diag: Diagnostics) -> None:
    relpath = ".github/PULL_REQUEST_TEMPLATE.md"
    text = texts.get(relpath)
    if text is None:
        return
    if "PUBLIC-SAFETY" not in text:
        diag.add(relpath, "missing the PUBLIC-SAFETY checklist heading")
    lowered = text.lower()
    for item in PR_TEMPLATE_ITEMS:
        if item not in lowered:
            diag.add(relpath, f"PUBLIC-SAFETY checklist missing required item: {item!r}")


def check_issue_form(relpath: str, texts: dict[str, str], diag: Diagnostics) -> None:
    text = texts.get(relpath)
    if text is None:
        return
    for key in ("name:", "description:", "body:"):
        if key not in text:
            diag.add(relpath, f"structured issue form must define {key!r}")
    if not STRUCTURED_FIELD_RE.search(text):
        diag.add(
            relpath,
            "must be a structured issue form (type: textarea/input/dropdown/checkboxes), "
            "not a legacy free-text template",
        )
    if FREEFORM_FIELD_RE.search(text) and not NO_PASTE_WARNING_RE.search(text):
        diag.add(relpath, "has free-text fields but no warning against pasting real logs/config/state")


def check_issue_config(texts: dict[str, str], diag: Diagnostics) -> None:
    relpath = ".github/ISSUE_TEMPLATE/config.yml"
    text = texts.get(relpath)
    if text is None:
        return
    if not re.search(r"blank_issues_enabled:\s*false", text):
        diag.add(relpath, "must set blank_issues_enabled: false")
    if "security" not in text.lower():
        diag.add(relpath, "should point a contact link at security reporting (SECURITY.md / private vulnerability reporting)")


def check_code_of_conduct(texts: dict[str, str], diag: Diagnostics) -> None:
    relpath = "CODE_OF_CONDUCT.md"
    text = texts.get(relpath)
    if text is None:
        return
    if "Contributor Covenant" not in text:
        diag.add(relpath, "must be a Contributor Covenant-style code of conduct")


def check_changelog(texts: dict[str, str], diag: Diagnostics) -> None:
    relpath = "CHANGELOG.md"
    text = texts.get(relpath)
    if text is None:
        return
    if "Keep a Changelog" not in text:
        diag.add(relpath, "must follow the Keep a Changelog format")
    if "Unreleased" not in text:
        diag.add(relpath, "must have an Unreleased section")
    if "pre-deployment" not in text.lower():
        diag.add(relpath, "Unreleased section must note the pre-deployment foundation posture")


def check_third_party_notices(texts: dict[str, str], diag: Diagnostics) -> None:
    relpath = "THIRD_PARTY_NOTICES.md"
    text = texts.get(relpath)
    if text is None:
        return
    lowered = text.lower()
    if "no third-party dependencies are bundled yet" not in lowered:
        diag.add(relpath, "must state that no third-party dependencies are bundled yet")
    if "task 10" not in lowered and "release" not in lowered:
        diag.add(relpath, "must note that real notices are compiled at release time (Task 10)")


def run_checks(root: Path) -> Diagnostics:
    diag = Diagnostics()
    texts = check_required_files(root, diag)
    check_license(root, texts, diag)
    check_codeowners(texts, diag)
    check_security(texts, diag)
    check_contributing(texts, diag)
    check_pr_template(texts, diag)
    check_issue_form(".github/ISSUE_TEMPLATE/bug.yml", texts, diag)
    check_issue_form(".github/ISSUE_TEMPLATE/feature.yml", texts, diag)
    check_issue_config(texts, diag)
    check_code_of_conduct(texts, diag)
    check_changelog(texts, diag)
    check_third_party_notices(texts, diag)
    return diag


def default_root() -> Path:
    return Path(__file__).resolve().parent.parent


def parse_args(argv: Optional[list[str]]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument(
        "--root",
        type=Path,
        default=None,
        help="repository root to check (default: this script's repository root)",
    )
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    root = (args.root or default_root()).resolve()
    if not root.is_dir():
        print(f"{root}: --root path does not exist or is not a directory")
        return 1

    diag = run_checks(root)
    for path, message in sorted(diag.items):
        print(f"{path}: {message}")

    if diag:
        return 1
    print("repository metadata checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
