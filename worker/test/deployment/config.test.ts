import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

import { afterEach, expect, test } from "vitest";

const repositoryRoot = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../..",
);
const renderer = join(repositoryRoot, "scripts/render-worker-deployment.mjs");
const base = join(repositoryRoot, "worker/wrangler.jsonc");
const inventoryDigest =
  "786c8d5ae1c3ebeea30656a1a48f87c0124132c26f090d2d099425bd9c5b1dd3";
const syntheticAccountId = "0123456789abcdef".repeat(2);
const temporaryRoots: string[] = [];

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

function privateFile(root: string, name: string, value: unknown): string {
  const path = join(root, name);
  writeFileSync(path, `${JSON.stringify(value)}\n`, { mode: 0o600 });
  chmodSync(path, 0o600);
  return path;
}

function validDescriptor(): Record<string, unknown> {
  return {
    accountId: syntheticAccountId,
    fleetIds: ["alpha", "beta", "gamma"],
    timestampWindowMs: 5_000,
    nonceTtlMs: 60_000,
    maxFleets: 3,
    perFleetDeadlineMs: 10_000,
    cronBudgetOverheadMs: 5_000,
    cronTickBudgetMs: 35_000,
    inventoryRevision: "1",
    inventoryDigest,
  };
}

function validSecrets(): Record<string, string> {
  return {
    HMAC_KEY: "0b".repeat(32),
    CRON_HMAC_KEY: "0c".repeat(32),
  };
}

function runRenderer(
  root: string,
  descriptorValue: unknown,
  secretsValue: unknown = validSecrets(),
  basePath = base,
) {
  const descriptor = privateFile(root, "deployment.json", descriptorValue);
  const secrets = privateFile(root, "secrets.json", secretsValue);
  const output = join(root, "wrangler.json");
  const result = spawnSync(
    process.execPath,
    [
      renderer,
      "--base",
      basePath,
      "--descriptor",
      descriptor,
      "--secrets",
      secrets,
      "--output",
      output,
    ],
    { encoding: "utf8" },
  );
  return { descriptor, secrets, output, result };
}

test("renderer emits the exact address-only Wrangler configuration", () => {
  const root = mkdtempSync(join(tmpdir(), "pghar-worker-config-"));
  temporaryRoots.push(root);
  const { output, result } = runRenderer(root, validDescriptor());

  expect(result.status, result.stderr).toBe(0);
  expect(result.stdout).toBe("");
  expect(result.stderr).toBe("");
  expect(statSync(output).mode & 0o777).toBe(0o600);
  const entrypoint = join(repositoryRoot, "worker/src/index.ts");
  expect(readFileSync(output, "utf8")).toBe(`{
  "name": "github-actionrunner",
  "main": "${entrypoint}",
  "compatibility_date": "2026-07-08",
  "account_id": "${syntheticAccountId}",
  "workers_dev": true,
  "observability": {
    "enabled": true,
    "head_sampling_rate": 1,
    "logs": {
      "invocation_logs": false,
      "persist": true
    }
  },
  "durable_objects": {
    "bindings": [
      {
        "name": "FLEET",
        "class_name": "FleetDurableObject"
      }
    ]
  },
  "migrations": [
    {
      "tag": "v1",
      "new_sqlite_classes": [
        "FleetDurableObject"
      ]
    }
  ],
  "triggers": {
    "crons": [
      "* * * * *"
    ]
  },
  "vars": {
    "FLEET_IDS": "alpha,beta,gamma",
    "TIMESTAMP_WINDOW_MS": "5000",
    "NONCE_TTL_MS": "60000",
    "MAX_FLEETS": "3",
    "PER_FLEET_DEADLINE_MS": "10000",
    "CRON_BUDGET_OVERHEAD_MS": "5000",
    "CRON_TICK_BUDGET_MS": "35000",
    "FLEET_INVENTORY_REVISION": "1",
    "FLEET_INVENTORY_DIGEST": "${inventoryDigest}"
  }
}
`);
  const rendered = readFileSync(output, "utf8");
  expect(rendered).not.toContain("HMAC_KEY");
  expect(rendered).not.toContain("0b".repeat(32));
  expect(rendered).not.toContain("0c".repeat(32));
  expect(rendered).not.toContain("LEASE_DURATION_MS");
  expect(rendered).not.toContain("ARCHIVE_EVIDENCE_MAX_AGE_MS");
  expect(rendered).not.toContain("SELECTOR_EVIDENCE_MAX_AGE_MS");
  expect(rendered).not.toContain("HOSTED_TRANSITION_SAFETY_MARGIN_MS");
});

test("renderer rejects unsafe private inputs without partial output", () => {
  const cases: Array<[string, unknown, unknown?]> = [
    ["unknown descriptor field", { ...validDescriptor(), extra: true }],
    ["inline secret", { ...validDescriptor(), HMAC_KEY: "0b".repeat(32) }],
    [
      "unknown secret field",
      validDescriptor(),
      { ...validSecrets(), LEASE_HMAC_KEY: "0d".repeat(32) },
    ],
    [
      "equal keys",
      validDescriptor(),
      { HMAC_KEY: "0b".repeat(32), CRON_HMAC_KEY: "0b".repeat(32) },
    ],
    [
      "short key",
      validDescriptor(),
      { HMAC_KEY: "0b".repeat(31), CRON_HMAC_KEY: "0c".repeat(32) },
    ],
    [
      "nonhex key",
      validDescriptor(),
      { HMAC_KEY: "zz".repeat(32), CRON_HMAC_KEY: "0c".repeat(32) },
    ],
  ];

  for (const [name, descriptorValue, secretsValue] of cases) {
    const root = mkdtempSync(join(tmpdir(), "pghar-worker-config-invalid-"));
    temporaryRoots.push(root);
    const { output, result } = runRenderer(root, descriptorValue, secretsValue);
    expect(result.status, name).toBe(1);
    expect(result.stdout, name).toBe("");
    expect(result.stderr, name).toBe("render-worker-deployment: rejected\n");
    expect(() => statSync(output), name).toThrow();
    expect(result.stderr, name).not.toContain("0b".repeat(31));
    expect(result.stderr, name).not.toContain("0c".repeat(32));
  }
});

test("renderer rejects invalid inventory and budget terms", () => {
  const cases: Array<[string, Record<string, unknown>]> = [
    ["account", { ...validDescriptor(), accountId: "ABC" }],
    [
      "unsorted fleet",
      { ...validDescriptor(), fleetIds: ["beta", "alpha", "gamma"] },
    ],
    [
      "duplicate fleet",
      { ...validDescriptor(), fleetIds: ["alpha", "alpha", "gamma"] },
    ],
    ["fleet count", { ...validDescriptor(), maxFleets: 2 }],
    [
      "inventory digest",
      { ...validDescriptor(), inventoryDigest: "a".repeat(64) },
    ],
    ["inventory revision", { ...validDescriptor(), inventoryRevision: "01" }],
    ["zero term", { ...validDescriptor(), timestampWindowMs: 0 }],
    ["fractional term", { ...validDescriptor(), nonceTtlMs: 1.5 }],
    ["budget", { ...validDescriptor(), cronTickBudgetMs: 34_999 }],
    ["platform maximum", { ...validDescriptor(), cronTickBudgetMs: 900_001 }],
  ];

  for (const [name, descriptorValue] of cases) {
    const root = mkdtempSync(join(tmpdir(), "pghar-worker-config-terms-"));
    temporaryRoots.push(root);
    const { output, result } = runRenderer(root, descriptorValue);
    expect(result.status, name).toBe(1);
    expect(result.stderr, name).toBe("render-worker-deployment: rejected\n");
    expect(() => statSync(output), name).toThrow();
  }
});

test("renderer requires private regular files and an exact public base", () => {
  const descriptorRoot = mkdtempSync(
    join(tmpdir(), "pghar-worker-config-mode-"),
  );
  temporaryRoots.push(descriptorRoot);
  const unsafeDescriptor = privateFile(
    descriptorRoot,
    "deployment.json",
    validDescriptor(),
  );
  chmodSync(unsafeDescriptor, 0o644);
  const secrets = privateFile(descriptorRoot, "secrets.json", validSecrets());
  const output = join(descriptorRoot, "wrangler.json");
  const modeResult = spawnSync(
    process.execPath,
    [
      renderer,
      "--base",
      base,
      "--descriptor",
      unsafeDescriptor,
      "--secrets",
      secrets,
      "--output",
      output,
    ],
    { encoding: "utf8" },
  );
  expect(modeResult.status).toBe(1);
  expect(() => statSync(output)).toThrow();

  const symlinkRoot = mkdtempSync(join(tmpdir(), "pghar-worker-config-link-"));
  temporaryRoots.push(symlinkRoot);
  const realSecrets = privateFile(
    symlinkRoot,
    "real-secrets.json",
    validSecrets(),
  );
  const linkedSecrets = join(symlinkRoot, "secrets.json");
  symlinkSync(realSecrets, linkedSecrets);
  const linkedDescriptor = privateFile(
    symlinkRoot,
    "deployment.json",
    validDescriptor(),
  );
  const linkOutput = join(symlinkRoot, "wrangler.json");
  const linkResult = spawnSync(
    process.execPath,
    [
      renderer,
      "--base",
      base,
      "--descriptor",
      linkedDescriptor,
      "--secrets",
      linkedSecrets,
      "--output",
      linkOutput,
    ],
    { encoding: "utf8" },
  );
  expect(linkResult.status).toBe(1);
  expect(() => statSync(linkOutput)).toThrow();

  const baseRoot = mkdtempSync(join(tmpdir(), "pghar-worker-config-base-"));
  temporaryRoots.push(baseRoot);
  const mutatedBase = join(baseRoot, "wrangler.jsonc");
  writeFileSync(
    mutatedBase,
    readFileSync(base, "utf8").replace(
      '"name": "portable-ghar-worker"',
      '"name": "foreign-worker"',
    ),
  );
  const { output: baseOutput, result: baseResult } = runRenderer(
    baseRoot,
    validDescriptor(),
    validSecrets(),
    mutatedBase,
  );
  expect(baseResult.status).toBe(1);
  expect(() => statSync(baseOutput)).toThrow();
});
