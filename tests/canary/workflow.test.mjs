// SPDX-License-Identifier: MPL-2.0
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { parse } from "yaml";

test("canary template is manual, single-label, SHA-pinned and checks every current real tool", async () => {
  const workflow = parse(
    await readFile(
      new URL("../../examples/live-acquisition/workflow.yml", import.meta.url),
      "utf8",
    ),
  );
  assert.deepEqual(Object.keys(workflow.on), ["workflow_dispatch"]);
  assert.deepEqual(Object.keys(workflow.jobs), ["canary"]);
  const job = workflow.jobs.canary;
  assert.equal(job["runs-on"], "example-canary");
  assert.equal(job["timeout-minutes"], 45);
  const steps = job.steps;
  for (const step of steps.filter((s) => s.uses))
    assert.match(step.uses, /@[0-9a-f]{40}$/);
  for (const action of [
    "actions/checkout",
    "actions/setup-go",
    "actions/setup-node",
    "actions/upload-artifact",
    "actions/attest",
    "anchore/sbom-action",
    "aquasecurity/trivy-action",
    "github/codeql-action/init",
    "github/codeql-action/analyze",
    "actions/dependency-review-action",
    "gitleaks/gitleaks-action",
  ])
    assert.ok(
      steps.some((s) => s.uses?.startsWith(`${action}@`)),
      action,
    );
  assert.equal(steps.at(-1).run, "node canary/probe.mjs");
  const outcomes = steps.at(-1).env.CANARY_TOOL_OUTCOMES;
  for (const id of [
    "checkout",
    "go_setup",
    "go_run",
    "node_setup",
    "node_run",
    "artifact",
    "attest",
    "sbom",
    "trivy",
    "codeql_init",
    "codeql_analyze",
    "dependencies",
    "gitleaks",
  ])
    assert.ok(outcomes.includes(`steps.${id}.outcome`), id);
  assert.equal(
    steps.find((s) => s.id === "checkout").with["persist-credentials"],
    false,
  );
  assert.equal(steps.find((s) => s.id === "trivy").with.cache, false);
  assert.equal(
    steps.find((s) => s.id === "artifact").with.path,
    "fixture/index.js",
  );
  assert.ok(!steps.some((s) => s["continue-on-error"]));
});
