# SPDX-License-Identifier: MPL-2.0
"""Environment configuration. Invalid spend inputs fail closed."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from overflow_watcher.labels import ALLOW
from overflow_watcher.money import PriceError, allowance_cents, parse_price
from overflow_watcher.types import RepoSpec

DEFAULT_BUDGET_STOP_EXCLUSIONS = (
    '[{"kind":"workflow","pattern":"deploy-*"},'
    '{"kind":"workflow","pattern":"*migration*"},'
    '{"kind":"job","pattern":"deploy-*"},'
    '{"kind":"job","pattern":"migrate*"}]'
)

ALLOWED_REPO_NAMES = frozenset(
    {
        "Contextual-Conversation-Gateway",
        "agent-collab-workspace",
        "keicrew",
    }
)

_PLACEHOLDERS = {"", "REQUIRED_INPUT", "<REQUIRED_INPUT>", "CHANGEME"}


def is_placeholder(value: str | None) -> bool:
    if value is None:
        return True
    text = value.strip()
    if text in _PLACEHOLDERS:
        return True
    return text.startswith("<") and text.endswith(">")


@dataclass(frozen=True)
class Exclusion:
    kind: str
    pattern: str


@dataclass(frozen=True)
class Config:
    ok: bool
    reason: str
    price_numer: int
    price_denom: int
    allowance: int
    soft_cap: int
    grace_cents: int
    continue_until: int
    cancel_wait: int
    exclusions: tuple[Exclusion, ...]
    repos: tuple[RepoSpec, ...]
    ami_id: str
    subnet_id: str
    security_group_id: str
    instance_type: str
    instance_profile_name: str
    launch_template_id: str
    app_identifier: str
    app_pem: str
    table_name: str

    @property
    def launch_allowed(self) -> bool:
        return self.ok


def _positive_int(env: dict[str, str], name: str, errors: list[str]) -> int:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        errors.append(f"{name} unset")
        return 0
    try:
        value = int(raw, 10)
    except ValueError:
        errors.append(f"{name} invalid")
        return 0
    if value <= 0:
        errors.append(f"{name} invalid")
        return 0
    return value


def _non_negative_int(env: dict[str, str], name: str, errors: list[str]) -> int:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        errors.append(f"{name} unset")
        return 0
    try:
        value = int(raw, 10)
    except ValueError:
        errors.append(f"{name} invalid")
        return 0
    if value < 0:
        errors.append(f"{name} invalid")
        return 0
    return value


def _required_text(env: dict[str, str], name: str, errors: list[str]) -> str:
    raw = env.get(name)
    if is_placeholder(raw):
        errors.append(f"{name} unset")
        return ""
    return raw.strip() if raw else ""


def _parse_exclusions(raw: str, errors: list[str]) -> tuple[Exclusion, ...]:
    if raw.strip() == "":
        errors.append("BUDGET_STOP_EXCLUSIONS empty")
        return ()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        errors.append("BUDGET_STOP_EXCLUSIONS invalid")
        return ()
    if not isinstance(parsed, list) or not parsed:
        errors.append("BUDGET_STOP_EXCLUSIONS empty")
        return ()
    rules: list[Exclusion] = []
    for entry in parsed:
        if not isinstance(entry, dict):
            errors.append("BUDGET_STOP_EXCLUSIONS invalid")
            return ()
        kind = entry.get("kind")
        pattern = entry.get("pattern")
        if kind not in {"workflow", "job", "label"} or not isinstance(pattern, str) or not pattern:
            errors.append("BUDGET_STOP_EXCLUSIONS invalid")
            return ()
        rules.append(Exclusion(kind=kind, pattern=pattern))
    return tuple(rules)


def _parse_repos(raw: str | None, errors: list[str]) -> tuple[RepoSpec, ...]:
    if is_placeholder(raw):
        errors.append("WATCHED_REPOS unset")
        return ()
    try:
        parsed = json.loads(raw or "")
    except json.JSONDecodeError:
        errors.append("WATCHED_REPOS invalid")
        return ()
    if not isinstance(parsed, list) or not parsed:
        errors.append("WATCHED_REPOS invalid")
        return ()
    repos: list[RepoSpec] = []
    seen: set[str] = set()
    for entry in parsed:
        if not isinstance(entry, dict):
            errors.append("WATCHED_REPOS invalid")
            return ()
        name = entry.get("name")
        repo_id = str(entry.get("id", ""))
        owner = str(entry.get("owner", ""))
        installation = str(entry.get("installation", ""))
        if name not in ALLOWED_REPO_NAMES:
            errors.append("WATCHED_REPOS invalid")
            return ()
        if (
            name in seen
            or is_placeholder(repo_id)
            or is_placeholder(owner)
            or is_placeholder(installation)
            or re.fullmatch(r"[0-9]+", repo_id) is None
        ):
            errors.append("WATCHED_REPOS invalid")
            return ()
        if "runnerGroupId" in entry:
            group = entry.get("runnerGroupId")
            if type(group) is not int or group <= 0:
                errors.append("WATCHED_REPOS invalid")
                return ()
        else:
            group = 1
        seen.add(str(name))
        repos.append(
            RepoSpec(
                repo_id=repo_id,
                owner=owner,
                name=str(name),
                installation=installation,
                runner_group_id=group,
            )
        )
    return tuple(repos)


def load_config(env: dict[str, str]) -> Config:
    errors: list[str] = []
    price_text = env.get("ALL_IN_HOURLY_PRICE")
    numer, denom = 0, 1
    allowance = 0
    if is_placeholder(price_text):
        errors.append("ALL_IN_HOURLY_PRICE unset")
    else:
        try:
            numer, denom = parse_price(price_text or "")
            allowance = allowance_cents(numer, denom)
        except PriceError:
            errors.append("ALL_IN_HOURLY_PRICE invalid")
    soft_cap = _positive_int(env, "MONTHLY_SOFT_CAP_CENTS", errors)
    continue_until = _positive_int(env, "CONTINUE_ACTIVE_UNTIL_CENTS", errors)
    grace_pct_raw = env.get("GRACE_PCT")
    grace_cents_raw = env.get("GRACE_CENTS")
    grace_cents = 0
    if (grace_pct_raw is None or grace_pct_raw.strip() == "") and (
        grace_cents_raw is None or grace_cents_raw.strip() == ""
    ):
        errors.append("grace knob unset")
    else:
        derived: int | None = None
        if grace_pct_raw is not None and grace_pct_raw.strip() != "":
            try:
                pct = int(grace_pct_raw, 10)
            except ValueError:
                errors.append("GRACE_PCT invalid")
                pct = -1
            if pct < 0:
                errors.append("GRACE_PCT invalid")
            elif soft_cap:
                derived = soft_cap * pct // 100
        if grace_cents_raw is not None and grace_cents_raw.strip() != "":
            try:
                explicit = int(grace_cents_raw, 10)
            except ValueError:
                errors.append("GRACE_CENTS invalid")
                explicit = -1
            if explicit < 0:
                errors.append("GRACE_CENTS invalid")
            elif derived is not None and explicit != derived:
                errors.append("grace knobs disagree")
            else:
                derived = explicit
        if derived is not None:
            grace_cents = derived
    if soft_cap and continue_until and continue_until != soft_cap + grace_cents:
        errors.append("CONTINUE_ACTIVE_UNTIL_CENTS invalid")
    if soft_cap and continue_until and continue_until <= soft_cap:
        errors.append("CONTINUE_ACTIVE_UNTIL_CENTS invalid")
    cancel_wait = _non_negative_int(env, "BUDGET_CANCEL_WAIT_SECONDS", errors)
    if "BUDGET_STOP_EXCLUSIONS" not in env:
        errors.append("BUDGET_STOP_EXCLUSIONS unset")
        exclusions: tuple[Exclusion, ...] = ()
    else:
        exclusions = _parse_exclusions(env.get("BUDGET_STOP_EXCLUSIONS", ""), errors)
    repos = _parse_repos(env.get("WATCHED_REPOS"), errors)
    ami = _required_text(env, "AMI_ID", errors)
    subnet = _required_text(env, "SUBNET_ID", errors)
    security_group = _required_text(env, "SECURITY_GROUP_ID", errors)
    instance_type = _required_text(env, "INSTANCE_TYPE", errors)
    profile = _required_text(env, "INSTANCE_PROFILE_NAME", errors)
    launch_template_id = _required_text(env, "LAUNCH_TEMPLATE_ID", errors)
    app_identifier = _required_text(env, "GITHUB_APP_IDENTIFIER", errors)
    app_pem = _required_text(env, "GITHUB_APP_PEM", errors)
    table_name = _required_text(env, "TABLE_NAME", errors)
    # Touch the allowlist so a future edit that drops it is visible to readers.
    _ = ALLOW
    reason = "; ".join(errors)
    return Config(
        ok=not errors,
        reason=reason,
        price_numer=numer,
        price_denom=denom,
        allowance=allowance,
        soft_cap=soft_cap,
        grace_cents=grace_cents,
        continue_until=continue_until,
        cancel_wait=cancel_wait,
        exclusions=exclusions,
        repos=repos,
        ami_id=ami,
        subnet_id=subnet,
        security_group_id=security_group,
        instance_type=instance_type,
        instance_profile_name=profile,
        launch_template_id=launch_template_id,
        app_identifier=app_identifier,
        app_pem=app_pem,
        table_name=table_name,
    )
