// SPDX-License-Identifier: MPL-2.0
// Installed with the reviewed workflow in the dedicated canary repository.
// Never print raw probe errors, environment, configuration, or diagnostics.
import { constants } from "node:fs";
import { open, readdir, lstat } from "node:fs/promises";
import path from "node:path";
import { createServer } from "node:net";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

const tools = [
  "actions-checkout",
  "actions-setup-go",
  "actions-setup-node",
  "actions-upload-artifact",
  "actions-attest",
  "anchore-sbom",
  "aquasecurity-trivy",
  "github-codeql",
  "actions-dependency-review",
  "gitleaks",
];
const failure = () => new Error("canary observation incomplete");

async function boundedFile(
  filename,
  limit,
  optional = false,
  nofollow = false,
) {
  let file;
  const buffer = Buffer.alloc(limit + 1);
  try {
    file = await open(
      filename,
      constants.O_RDONLY | (nofollow ? constants.O_NOFOLLOW : 0),
    );
    let length = 0;
    while (length < buffer.length) {
      const result = await file.read(
        buffer,
        length,
        buffer.length - length,
        null,
      );
      if (!result.bytesRead) break;
      length += result.bytesRead;
    }
    if (length > limit) throw failure();
    return buffer.subarray(0, length);
  } catch (error) {
    buffer.fill(0);
    if (optional && ["ENOENT", "EACCES", "EPERM"].includes(error.code))
      return null;
    throw failure();
  } finally {
    await file?.close();
  }
}

export async function credentialObservation({
  environment = process.env,
  proc = "/proc/1/environ",
  runner = "/runner",
  diagnostics = "/runner/_diag",
} = {}) {
  if (Object.hasOwn(environment, "ACTIONS_RUNNER_INPUT_JITCONFIG"))
    throw failure();
  const buffers = [];
  const needles = [];
  let decoded = false;
  try {
    const listener = await boundedFile(proc, 1024 * 1024, true);
    if (listener) {
      buffers.push(listener);
      const prefix = Buffer.from("ACTIONS_RUNNER_INPUT_JITCONFIG=");
      let start = 0;
      while (start < listener.length) {
        const end = listener.indexOf(0, start);
        const entry = listener.subarray(start, end < 0 ? listener.length : end);
        if (
          entry.subarray(0, prefix.length).equals(prefix) &&
          entry.length > prefix.length
        )
          needles.push(entry.subarray(prefix.length));
        start = end < 0 ? listener.length : end + 1;
      }
    }
    for (const name of [".runner", ".credentials", ".credentials_rsaparams"]) {
      const document = await boundedFile(
        path.join(runner, name),
        1024 * 1024,
        true,
      );
      if (!document) continue;
      buffers.push(document);
      if (name !== ".runner") decoded = true;
      const collect = (value) => {
        if (!value || typeof value !== "object") return;
        for (const [key, item] of Object.entries(value)) {
          if (
            typeof item === "string" &&
            /^(d|dp|dq|inverseq|p|q)$|(?:token|password|secret|privatekey)$/i.test(
              key,
            ) &&
            item.length
          ) {
            const needle = Buffer.from(item);
            buffers.push(needle);
            needles.push(needle);
          } else collect(item);
        }
      };
      collect(JSON.parse(document.toString("utf8")));
    }
    let total = 0;
    let count = 0;
    const scan = async (directory) => {
      for (const entry of await readdir(directory, { withFileTypes: true })) {
        if (++count > 1024) throw failure();
        const filename = path.join(directory, entry.name);
        if (entry.isDirectory()) {
          await scan(filename);
          continue;
        }
        if (!entry.isFile()) throw failure();
        const log = await boundedFile(filename, 8 * 1024 * 1024, false, true);
        try {
          total += log.length;
          if (
            total > 64 * 1024 * 1024 ||
            needles.some((needle) => log.includes(needle))
          )
            throw failure();
        } finally {
          log.fill(0);
        }
      }
    };
    await scan(diagnostics);
    return {
      inherited_jit_absent: true,
      listener_proc_readable: listener !== null,
      decoded_credentials_readable: decoded,
      credential_probe_completed: true,
    };
  } catch {
    throw failure();
  } finally {
    for (const buffer of buffers) buffer.fill(0);
  }
}

export function workflowObservation({
  report,
  run,
  revision,
  outcomes,
  checkoutHTTPS,
  sandboxVerified,
  credentials,
}) {
  if (
    !/^[0-9a-f]{64}$/.test(report) ||
    !/^[1-9][0-9]*$/.test(run) ||
    !Number.isSafeInteger(Number(run)) ||
    !/^[0-9a-f]{40}$/.test(revision) ||
    outcomes.length !== tools.length ||
    outcomes.some((outcome) => outcome !== "success") ||
    checkoutHTTPS !== true ||
    sandboxVerified !== true ||
    credentials.inherited_jit_absent !== true ||
    credentials.credential_probe_completed !== true ||
    typeof credentials.listener_proc_readable !== "boolean" ||
    typeof credentials.decoded_credentials_readable !== "boolean"
  )
    throw failure();
  return {
    version: 1,
    report_digest: report,
    workflow_run_id: Number(run),
    revision,
    checkout_https: true,
    sandbox_verified: true,
    inherited_jit_absent: true,
    listener_proc_readable: credentials.listener_proc_readable,
    decoded_credentials_readable: credentials.decoded_credentials_readable,
    credential_probe_completed: true,
    tools: [...tools],
  };
}

export async function publishWorkflow(
  frame,
  {
    directory = "/runner/.portable-ghar",
    timeout = 120000,
    ready = () => {},
  } = {},
) {
  const stat = await lstat(directory);
  if (
    !stat.isDirectory() ||
    (stat.mode & 0o777) !== 0o700 ||
    stat.uid !== process.geteuid()
  )
    throw failure();
  const document = JSON.stringify(frame);
  if (Buffer.byteLength(document) > 4096 || timeout <= 0) throw failure();
  await new Promise((resolve, reject) => {
    let client;
    let settled = false;
    const previousMask = process.umask(0o177);
    const server = createServer((connection) => {
      if (client) {
        connection.destroy();
        return;
      }
      client = connection;
      connection.on("error", () => finish(failure()));
      connection.on("close", () => finish());
      connection.end(document);
    });
    const timer = setTimeout(() => finish(failure()), timeout);
    function finish(error) {
      if (settled) return;
      settled = true;
      process.umask(previousMask);
      clearTimeout(timer);
      client?.destroy();
      server.close(() => (error ? reject(failure()) : resolve()));
    }
    server.on("error", () => finish(failure()));
    server.listen(path.join(directory, "canary-report.sock"), () => {
      process.umask(previousMask);
      ready();
    });
  });
}

async function main() {
  const credentials = await credentialObservation();
  const origin = spawnSync("git", ["remote", "get-url", "origin"], {
    encoding: "utf8",
    maxBuffer: 4096,
    timeout: 10000,
  });
  const checkoutHTTPS =
    origin.status === 0 &&
    origin.stdout.trim() ===
      `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}`;
  // This helper's environment contract is deliberately closed. The actual job
  // environment's JIT absence was checked independently above.
  const proxyHost = [127, 0, 0, 1].join(".");
  const proxy = `http://${proxyHost}:18080`;
  const noProxy = `${proxyHost},${["", "", "1"].join(":")}`;
  const observed = spawnSync(
    "/usr/local/bin/portable-ghar-runner-gate",
    ["conformance-observe"],
    {
      env: {
        HOME: "/runner",
        LANG: "C.UTF-8",
        PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        HTTPS_PROXY: proxy,
        https_proxy: proxy,
        NO_PROXY: noProxy,
        no_proxy: noProxy,
      },
      maxBuffer: 65536,
      timeout: 10000,
    },
  );
  const frame = workflowObservation({
    report: process.env.CANARY_REPORT_DIGEST,
    run: process.env.GITHUB_RUN_ID,
    revision: process.env.GITHUB_SHA,
    outcomes: process.env.CANARY_TOOL_OUTCOMES.split(","),
    checkoutHTTPS,
    sandboxVerified: observed.status === 0 && !observed.error,
    credentials,
  });
  await publishWorkflow(frame);
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  main().catch(() => {
    process.stderr.write("canary observation incomplete\n");
    process.exitCode = 1;
  });
}
