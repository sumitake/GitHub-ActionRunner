import { expect, test } from "vitest";

import { canTransition, isRoutingState } from "../../src/routing/machine";

test("routing machine has exactly six persisted authority states", () => {
  const states = [
    "HOSTED",
    "DRAINING_TO_HOSTED",
    "PORTABLE_CANARY",
    "PORTABLE",
    "LEGACY_CANARY",
    "LEGACY",
  ];
  expect(states.every(isRoutingState)).toBe(true);
  expect(isRoutingState("UNINITIALIZED")).toBe(false);
  expect(isRoutingState("CANARY_WAITING")).toBe(false);
});

test("allowed transitions stay hosted-safe and reject portable-to-legacy", () => {
  expect(canTransition("UNINITIALIZED", "HOSTED")).toBe(true);
  expect(canTransition("HOSTED", "PORTABLE_CANARY")).toBe(true);
  expect(canTransition("PORTABLE_CANARY", "PORTABLE")).toBe(true);
  expect(canTransition("PORTABLE_CANARY", "DRAINING_TO_HOSTED")).toBe(true);
  expect(canTransition("LEGACY_CANARY", "DRAINING_TO_HOSTED")).toBe(true);
  expect(canTransition("PORTABLE", "LEGACY")).toBe(false);
  expect(canTransition("HOSTED", "PORTABLE")).toBe(false);
  expect(canTransition("UNINITIALIZED", "PORTABLE")).toBe(false);
});
