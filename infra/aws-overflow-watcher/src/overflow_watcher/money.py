# SPDX-License-Identifier: MPL-2.0
"""Integer-cent cost, Los Angeles month keys, and accrual deltas."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from overflow_watcher.types import ALLOWANCE_SECONDS, StopCandidate

LA = ZoneInfo("America/Los_Angeles")


class PriceError(ValueError):
    """The all-in hourly price is missing or not a positive decimal."""


def parse_price(text: str) -> tuple[int, int]:
    """Return (numerator, denominator) dollars per hour. No binary float."""
    raw = text.strip()
    if not raw or raw[0] == "-" or raw[0] == "+":
        raise PriceError("price must be a positive decimal")
    whole, dot, frac = raw.partition(".")
    if dot and (not frac or not frac.isdigit() or not whole.isdigit()):
        raise PriceError("price must be a positive decimal")
    if not dot and not whole.isdigit():
        raise PriceError("price must be a positive decimal")
    if not whole:
        whole = "0"
    if frac:
        denom = 10 ** len(frac)
        numer = int(whole) * denom + int(frac)
    else:
        numer, denom = int(whole), 1
    if numer <= 0 or denom <= 0:
        raise PriceError("price must be positive")
    return numer, denom


def cost_cents(seconds: int, numer: int, denom: int) -> int:
    """Ceil of dollars/hour * seconds/3600, in integer cents."""
    if seconds <= 0:
        return 0
    numerator = numer * seconds * 100
    denominator = denom * 3600
    return (numerator + denominator - 1) // denominator


def allowance_cents(numer: int, denom: int) -> int:
    return cost_cents(ALLOWANCE_SECONDS, numer, denom)


def owed_cents(elapsed_seconds: int, numer: int, denom: int) -> int:
    """Admission allowance is a floor. Shorter runs are not refunded."""
    return max(allowance_cents(numer, denom), cost_cents(elapsed_seconds, numer, denom))


def month_key(epoch: int) -> str:
    """America/Los_Angeles calendar month for an integer UTC epoch."""
    when = datetime.fromtimestamp(epoch, tz=timezone.utc).astimezone(LA)
    return f"{when.year:04d}-{when.month:02d}"


def _next_month_start(epoch: int) -> int:
    when = datetime.fromtimestamp(epoch, tz=timezone.utc).astimezone(LA)
    year = when.year + (1 if when.month == 12 else 0)
    month = 1 if when.month == 12 else when.month + 1
    start = datetime(year, month, 1, 0, 0, 0, tzinfo=LA)
    return int(start.timestamp())


def month_slices(start: int, end: int) -> list[tuple[str, int, int]]:
    """Split the half-open epoch interval [start, end) on LA month boundaries."""
    if end <= start:
        return []
    slices: list[tuple[str, int, int]] = []
    cursor = start
    while cursor < end:
        boundary = _next_month_start(cursor)
        stop = end if boundary > end else boundary
        if stop <= cursor:
            raise RuntimeError("month boundary did not advance")
        slices.append((month_key(cursor), cursor, stop))
        cursor = stop
    return slices


def accrual_delta(already: int, owed_now: int, watermark: int, now: int) -> int:
    """R2: add only the positive delta past the watermark.

    A duplicate invocation (now <= watermark) or a stale one adds zero.
    A recomputed total that does not exceed the cumulative debit adds zero.
    """
    if now <= watermark:
        return 0
    if owed_now <= already:
        return 0
    return owed_now - already


@dataclass(frozen=True)
class AccrualPlan:
    expected_watermark: int
    new_watermark: int
    new_cumulative: int
    delta: int
    month_deltas: dict[str, int]
    debit_by_month: dict[str, int]
    crossed_allowance: bool


def plan_accrual(
    *,
    launch_epoch: int,
    watermark: int,
    cumulative: int,
    debit_by_month: dict[str, int],
    now: int,
    numer: int,
    denom: int,
) -> AccrualPlan | None:
    """Plan one accrual step. None means the invocation adds zero cents."""
    owed_now = owed_cents(max(0, now - launch_epoch), numer, denom)
    delta = accrual_delta(cumulative, owed_now, watermark, now)
    if delta == 0 and now <= watermark:
        return None
    month_deltas: dict[str, int] = {}
    if delta > 0:
        previous = owed_cents(max(0, watermark - launch_epoch), numer, denom)
        cursor_owed = previous
        for month, _slice_start, slice_end in month_slices(watermark, now):
            at_end = owed_cents(max(0, slice_end - launch_epoch), numer, denom)
            add = at_end - cursor_owed
            if add > 0:
                month_deltas[month] = month_deltas.get(month, 0) + add
            cursor_owed = at_end
        distributed = sum(month_deltas.values())
        if distributed != delta:
            # Keep the ledger and the per-instance debit in agreement.
            raise RuntimeError("accrual slices did not match the positive delta")
    updated = dict(debit_by_month)
    for month, add in month_deltas.items():
        updated[month] = updated.get(month, 0) + add
    allowance = allowance_cents(numer, denom)
    return AccrualPlan(
        expected_watermark=watermark,
        new_watermark=now,
        new_cumulative=cumulative + delta,
        delta=delta,
        month_deltas=month_deltas,
        debit_by_month=updated,
        crossed_allowance=cumulative <= allowance < cumulative + delta,
    )


def select_minimum(
    candidates: list[StopCandidate], accrued: int, grace: int
) -> list[StopCandidate]:
    """Fewest instances whose open-month debits bring the projection under grace.

    Order is deterministic: highest open-month debit, then newest launch,
    then instance id. The projection subtracts those debits from the estimate
    for selection only. The ledger itself is not reduced.
    """
    if accrued < grace:
        return []
    need = accrued - (grace - 1)
    ordered = sorted(
        candidates,
        key=lambda item: (-item.month_debit, -item.launch_epoch, item.instance_id),
    )
    chosen: list[StopCandidate] = []
    covered = 0
    for candidate in ordered:
        if covered >= need:
            break
        if candidate.month_debit <= 0:
            continue
        chosen.append(candidate)
        covered += candidate.month_debit
    if covered < need:
        return []
    return chosen
