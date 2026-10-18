// SPDX-License-Identifier: MPL-2.0
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, symlink, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import {
  credentialObservation,
  publishWorkflow,
  workflowObservation,
} from "../../examples/live-acquisition/probe.mjs";

async function fixture(t) {
  const root = await mkdtemp(path.join(tmpdir(), "canary-probe-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, "diag"));
  await writeFile(
    path.join(root, "proc"),
    "HOME=/runner\0ACTIONS_RUNNER_INPUT_JITCONFIG=synthetic-jit-value\0",
  );
  for (const name of [".runner", ".credentials", ".credentials_rsaparams"]) {
    await writeFile(
      path.join(root, name),
      JSON.stringify({ D: "synthetic-private-component" }),
    );
  }
  return {
    environment: {},
    proc: path.join(root, "proc"),
    runner: root,
    diagnostics: path.join(root, "diag"),
  };
}

test("own-job exposure is bounded metadata and credential bytes never enter the result", async (t) => {
  const options = await fixture(t);
  const result = await credentialObservation(options);
  assert.deepEqual(result, {
    inherited_jit_absent: true,
    listener_proc_readable: true,
    decoded_credentials_readable: true,
    credential_probe_completed: true,
  });
  assert.doesNotMatch(JSON.stringify(result), /synthetic/);
});

test("inherited JIT and credential material in diagnostics fail closed", async (t) => {
  const options = await fixture(t);
  await assert.rejects(
    credentialObservation({
      ...options,
      environment: { ACTIONS_RUNNER_INPUT_JITCONFIG: "" },
    }),
  );
  for (const value of ["synthetic-jit-value", "synthetic-private-component"]) {
    await writeFile(
      path.join(options.diagnostics, "runner.log"),
      `ordinary log ${value}`,
    );
    await assert.rejects(credentialObservation(options));
  }
});

test("absent own credentials are acceptable, unbounded or indirect diagnostics are not", async (t) => {
  const options = await fixture(t);
  await rm(options.proc);
  for (const name of [".runner", ".credentials", ".credentials_rsaparams"])
    await rm(path.join(options.runner, name));
  assert.equal(
    (await credentialObservation(options)).decoded_credentials_readable,
    false,
  );
  await writeFile(
    path.join(options.diagnostics, "large.log"),
    Buffer.alloc(8 * 1024 * 1024 + 1),
  );
  await assert.rejects(credentialObservation(options));
  await rm(path.join(options.diagnostics, "large.log"));
  await symlink(options.proc, path.join(options.diagnostics, "link"));
  await assert.rejects(credentialObservation(options));
});

test("workflow requires successful real tool steps and exact report/run/revision binding", () => {
  const input = {
    report: "a".repeat(64),
    run: "42",
    revision: "b".repeat(40),
    outcomes: Array(10).fill("success"),
    checkoutHTTPS: true,
    sandboxVerified: true,
    credentials: {
      inherited_jit_absent: true,
      listener_proc_readable: true,
      decoded_credentials_readable: true,
      credential_probe_completed: true,
    },
  };
  const result = workflowObservation(input);
  assert.equal(result.workflow_run_id, 42);
  assert.equal(result.tools.length, 10);
  for (const change of [
    { report: "bad" },
    { run: "0" },
    { run: "9007199254740992" },
    { revision: "bad" },
    { checkoutHTTPS: false },
    { sandboxVerified: false },
    { outcomes: Array(9).fill("success") },
    { outcomes: ["failure", ...Array(9).fill("success")] },
    { credentials: {} },
    ...[
      "inherited_jit_absent",
      "credential_probe_completed",
      "listener_proc_readable",
      "decoded_credentials_readable",
    ].map((name) => ({
      credentials: { ...input.credentials, [name]: undefined },
    })),
  ])
    assert.throws(() => workflowObservation({ ...input, ...change }));
});

test("private socket transfers only the closed observation and waits for a reader", async (t) => {
  const options = await fixture(t);
  const directory = path.join(options.runner, "gate");
  await mkdir(directory, { mode: 0o700 });
  const { connect } = await import("node:net");
  const { stat } = await import("node:fs/promises");
  const socket = path.join(directory, "canary-report.sock");
  const frame = workflowObservation({
    report: "a".repeat(64),
    run: "42",
    revision: "b".repeat(40),
    outcomes: Array(10).fill("success"),
    checkoutHTTPS: true,
    sandboxVerified: true,
    credentials: await credentialObservation(options),
  });
  const ready = Promise.withResolvers();
  const published = publishWorkflow(frame, {
    directory,
    timeout: 1000,
    ready: ready.resolve,
  });
  await ready.promise;
  assert.equal((await stat(socket)).mode & 0o777, 0o600);
  const received = await new Promise((resolve, reject) => {
    const client = connect(socket);
    const chunks = [];
    client.on("data", (chunk) => chunks.push(chunk));
    client.on("end", () => resolve(Buffer.concat(chunks).toString()));
    client.on("error", reject);
  });
  assert.equal(received, JSON.stringify(frame));
  await published;
});

test("a missing controller reader times out and existing endpoints are never reused", async (t) => {
  const options = await fixture(t);
  const directory = path.join(options.runner, "gate");
  await mkdir(directory, { mode: 0o700 });
  const frame = workflowObservation({
    report: "a".repeat(64),
    run: "42",
    revision: "b".repeat(40),
    outcomes: Array(10).fill("success"),
    checkoutHTTPS: true,
    sandboxVerified: true,
    credentials: await credentialObservation(options),
  });
  await assert.rejects(publishWorkflow(frame, { directory, timeout: 20 }));
  await writeFile(path.join(directory, "canary-report.sock"), "do not replace");
  await assert.rejects(publishWorkflow(frame, { directory, timeout: 20 }));
});

test("configuration metadata alone does not claim decoded credential readability", async (t) => {
  const options = await fixture(t);
  for (const name of [".credentials", ".credentials_rsaparams"])
    await rm(path.join(options.runner, name));
  assert.equal(
    (await credentialObservation(options)).decoded_credentials_readable,
    false,
  );
});

test("a public reporting directory is rejected even when it is otherwise usable", async (t) => {
  const options = await fixture(t);
  const directory = path.join(options.runner, "gate");
  await mkdir(directory, { mode: 0o755 });
  const { chmod } = await import("node:fs/promises");
  await chmod(directory, 0o755);
  const frame = workflowObservation({
    report: "a".repeat(64),
    run: "42",
    revision: "b".repeat(40),
    outcomes: Array(10).fill("success"),
    checkoutHTTPS: true,
    sandboxVerified: true,
    credentials: await credentialObservation(options),
  });
  let ready = false;
  await assert.rejects(
    publishWorkflow(frame, {
      directory,
      timeout: 20,
      ready: () => {
        ready = true;
      },
    }),
  );
  assert.equal(ready, false);
});

test("diagnostic traversal has independent file-count and total-byte limits", async (t) => {
  for (const kind of ["count", "bytes"]) {
    const options = await fixture(t);
    const amount = kind === "count" ? 1025 : 9;
    const content = Buffer.alloc(kind === "count" ? 0 : 8 * 1024 * 1024);
    for (let index = 0; index < amount; index++)
      await writeFile(path.join(options.diagnostics, `${index}.log`), content);
    await assert.rejects(credentialObservation(options));
  }
});

test("unbounded frames and invalid reader windows fail before publishing", async (t) => {
  const options = await fixture(t);
  const directory = path.join(options.runner, "gate");
  await mkdir(directory, { mode: 0o700 });
  const frame = workflowObservation({
    report: "a".repeat(64),
    run: "42",
    revision: "b".repeat(40),
    outcomes: Array(10).fill("success"),
    checkoutHTTPS: true,
    sandboxVerified: true,
    credentials: await credentialObservation(options),
  });
  for (const change of [
    { frame: { ...frame, extra: "x".repeat(4096) }, timeout: 20 },
    { frame, timeout: 0 },
  ]) {
    let ready = false;
    await assert.rejects(
      publishWorkflow(change.frame, {
        directory,
        timeout: change.timeout,
        ready: () => {
          ready = true;
        },
      }),
    );
    assert.equal(ready, false);
  }
});

test("diagnostics never expose nested access tokens or client secrets", async (t) => {
  for (const key of ["oauthAccessToken", "clientSecret", "password"]) {
    const options = await fixture(t);
    await writeFile(
      path.join(options.runner, ".credentials"),
      JSON.stringify({ data: { [key]: "synthetic-sensitive-component" } }),
    );
    await writeFile(
      path.join(options.diagnostics, "runner.log"),
      "synthetic-sensitive-component",
    );
    await assert.rejects(credentialObservation(options));
  }
});
