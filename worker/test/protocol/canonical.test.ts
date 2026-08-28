import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { expect, test } from "vitest";

import {
  canonicalize,
  parseCanonical,
  ProtocolCodecError,
} from "../../src/protocol/canonical";

const fixtureRoot = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../tests/fixtures/protocol/v1",
);

test("session request encodes to the frozen canonical bytes", () => {
  const document = JSON.parse(
    readFileSync(join(fixtureRoot, "session-request.json"), "utf8"),
  ) as unknown;
  const want = readFileSync(
    join(fixtureRoot, "session-request.canonical.txt"),
    "utf8",
  ).trimEnd();
  expect(canonicalize(document)).toBe(want);
  expect(parseCanonical(want)).toEqual(document);
});

test("canonical encoding sorts object keys and rejects whitespace", () => {
  expect(canonicalize({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  expect(() => parseCanonical('{"b":1,"a":2}')).toThrow(ProtocolCodecError);
  expect(() => parseCanonical('{ "a": 1 }')).toThrow(ProtocolCodecError);
});

test("canonical encoding rejects non-finite numbers and oversized bodies", () => {
  expect(() => canonicalize({ n: Number.NaN })).toThrow(ProtocolCodecError);
  expect(() => canonicalize({ n: Number.POSITIVE_INFINITY })).toThrow(
    ProtocolCodecError,
  );
  expect(() => canonicalize("x".repeat(65537))).toThrow(ProtocolCodecError);
});
