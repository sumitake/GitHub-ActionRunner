// Schema/example conformance tests for the portable-ghar public config surface.
//
// Positive cases: each config/examples/*.example.json validates against its
// paired config/schema/*.schema.json.
//
// Negative cases: hand-authored fixtures that each violate exactly one design
// contract (extra field, inline secret, non-synthetic repo identity, missing
// egress class, missing per-repository field, non-deny IPv6 posture, raw log
// field, free-text notification field) must each fail validation.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { validateFile } from "../../scripts/validate-config.mjs";

const SCHEMA = {
  fleet: "config/schema/fleet.schema.json",
  hostProfile: "config/schema/host-profile.schema.json",
  publicLogEvent: "config/schema/public-log-event.schema.json",
  notificationEvent: "config/schema/notification-event.schema.json",
};

const EXAMPLE = {
  fleet: "config/examples/fleet.example.json",
  hostProfile: "config/examples/host-profile.example.json",
  publicLogEvent: "config/examples/public-log-event.example.json",
  notificationEvent: "config/examples/notification-event.example.json",
};

// --- fixture plumbing -------------------------------------------------

const fixtureDir = mkdtempSync(join(tmpdir(), "portable-ghar-schema-test-"));
let fixtureCounter = 0;

function writeFixture(data) {
  fixtureCounter += 1;
  const path = join(fixtureDir, `fixture-${fixtureCounter}.json`);
  writeFileSync(path, JSON.stringify(data, null, 2), "utf8");
  return path;
}

function loadExample(exampleRelPath) {
  // Re-read the example fresh for each test so mutations for one negative
  // fixture never leak into another test.
  return JSON.parse(readFileSync(exampleRelPath, "utf8"));
}

process.on("exit", () => {
  rmSync(fixtureDir, { recursive: true, force: true });
});

// --- positive: every example validates against its schema --------------

test("fleet.example.json validates against fleet.schema.json", () => {
  const result = validateFile(SCHEMA.fleet, EXAMPLE.fleet);
  assert.equal(result.valid, true, JSON.stringify(result.errors));
});

test("host-profile.example.json validates against host-profile.schema.json", () => {
  const result = validateFile(SCHEMA.hostProfile, EXAMPLE.hostProfile);
  assert.equal(result.valid, true, JSON.stringify(result.errors));
});

test("public-log-event.example.json validates against public-log-event.schema.json", () => {
  const result = validateFile(SCHEMA.publicLogEvent, EXAMPLE.publicLogEvent);
  assert.equal(result.valid, true, JSON.stringify(result.errors));
});

test("notification-event.example.json validates against notification-event.schema.json", () => {
  const result = validateFile(SCHEMA.notificationEvent, EXAMPLE.notificationEvent);
  assert.equal(result.valid, true, JSON.stringify(result.errors));
});

// --- negative cases -------------------------------------------------

test("fleet: unknown/extra top-level field is rejected", () => {
  const data = loadExample(EXAMPLE.fleet);
  data.unexpectedExtraField = "not-allowed";
  const path = writeFixture(data);
  const result = validateFile(SCHEMA.fleet, path);
  assert.equal(result.valid, false);
});

test("fleet: inline secret value for heartbeatKeyRef is rejected", () => {
  const data = loadExample(EXAMPLE.fleet);
  data.heartbeatKeyRef = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
  const path = writeFixture(data);
  const result = validateFile(SCHEMA.fleet, path);
  assert.equal(result.valid, false);
});

test("fleet: non-synthetic (real-looking) repository owner/repository is rejected", () => {
  const data = loadExample(EXAMPLE.fleet);
  data.repositories[0].owner = "torvalds";
  data.repositories[0].repository = "linux";
  const path = writeFixture(data);
  const result = validateFile(SCHEMA.fleet, path);
  assert.equal(result.valid, false);
});

test("fleet: missing a blocked-egress class is rejected", () => {
  const data = loadExample(EXAMPLE.fleet);
  delete data.networkPolicy.blockedEgressClasses.multicastBroadcast;
  const path = writeFixture(data);
  const result = validateFile(SCHEMA.fleet, path);
  assert.equal(result.valid, false);
});

test("fleet: repository missing maxConcurrency is rejected", () => {
  const data = loadExample(EXAMPLE.fleet);
  delete data.repositories[0].maxConcurrency;
  const path = writeFixture(data);
  const result = validateFile(SCHEMA.fleet, path);
  assert.equal(result.valid, false);
});

test("fleet: repository missing archiveEligibility is rejected", () => {
  const data = loadExample(EXAMPLE.fleet);
  delete data.repositories[0].archiveEligibility;
  const path = writeFixture(data);
  const result = validateFile(SCHEMA.fleet, path);
  assert.equal(result.valid, false);
});

test("fleet: IPv6 network-policy entry set to a non-deny posture is rejected", () => {
  const data = loadExample(EXAMPLE.fleet);
  data.networkPolicy.blockedEgressClasses.privateUniqueLocal.posture = "allow";
  const path = writeFixture(data);
  const result = validateFile(SCHEMA.fleet, path);
  assert.equal(result.valid, false);
});

test("host-profile: free-form host path / identity / schedule field is rejected", () => {
  const data = loadExample(EXAMPLE.hostProfile);
  data.installPath = "/opt/ghar-agent";
  data.hostAddress = "203.0.113.7";
  data.cronSchedule = "*/5 * * * *";
  const path = writeFixture(data);
  const result = validateFile(SCHEMA.hostProfile, path);
  assert.equal(result.valid, false);
});

test("public-log-event: raw/free-form message field is rejected", () => {
  const data = loadExample(EXAMPLE.publicLogEvent);
  data.message = "Free-form human text that leaks details";
  const path = writeFixture(data);
  const result = validateFile(SCHEMA.publicLogEvent, path);
  assert.equal(result.valid, false);
});

test("notification-event: free text in operatorAction is rejected", () => {
  const data = loadExample(EXAMPLE.notificationEvent);
  data.operatorAction = "Please go check the dashboard and let me know";
  const path = writeFixture(data);
  const result = validateFile(SCHEMA.notificationEvent, path);
  assert.equal(result.valid, false);
});

test("notification-event: free-form notes field is rejected", () => {
  const data = loadExample(EXAMPLE.notificationEvent);
  data.notes = "Unstructured free text should not be allowed";
  const path = writeFixture(data);
  const result = validateFile(SCHEMA.notificationEvent, path);
  assert.equal(result.valid, false);
});

test("health-snapshot.example.json validates against health-snapshot.schema.json", () => {
  const result = validateFile(
    "config/schema/health-snapshot.schema.json",
    "config/examples/health-snapshot.example.json",
  );
  assert.equal(result.valid, true, JSON.stringify(result.errors));
});
