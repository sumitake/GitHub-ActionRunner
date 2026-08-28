import { ROUTING_STATES, type RoutingState } from "../protocol/messages";

export type PersistedRouting = RoutingState | "UNINITIALIZED";

const EDGES: ReadonlyArray<readonly [PersistedRouting, RoutingState]> = [
  ["UNINITIALIZED", "HOSTED"],
  ["HOSTED", "PORTABLE_CANARY"],
  ["PORTABLE_CANARY", "PORTABLE"],
  ["PORTABLE_CANARY", "DRAINING_TO_HOSTED"],
  ["HOSTED", "LEGACY_CANARY"],
  ["LEGACY_CANARY", "LEGACY"],
  ["LEGACY_CANARY", "DRAINING_TO_HOSTED"],
  ["PORTABLE", "DRAINING_TO_HOSTED"],
  ["LEGACY", "DRAINING_TO_HOSTED"],
  ["DRAINING_TO_HOSTED", "HOSTED"],
];

export function isRoutingState(value: string): value is RoutingState {
  return (ROUTING_STATES as readonly string[]).includes(value);
}

export function canTransition(
  from: PersistedRouting,
  to: RoutingState,
): boolean {
  return EDGES.some(([left, right]) => left === from && right === to);
}

export function assertTransition(
  from: PersistedRouting,
  to: RoutingState,
): void {
  if (!canTransition(from, to)) {
    throw new Error(`routing transition ${from} -> ${to} is not allowed`);
  }
}

export function isLocalAuthorityState(state: PersistedRouting): boolean {
  return (
    state === "PORTABLE" ||
    state === "PORTABLE_CANARY" ||
    state === "LEGACY" ||
    state === "LEGACY_CANARY"
  );
}
