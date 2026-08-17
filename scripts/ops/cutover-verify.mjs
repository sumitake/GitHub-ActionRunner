#!/usr/bin/env node
// Read-only cutover verifier over synthetic receipts. Grafana is never evidence.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const receiptsPath = process.argv[2];
if (!receiptsPath) {
  process.stderr.write("arguments\n");
  process.exit(2);
}

const receipts = JSON.parse(readFileSync(resolve(receiptsPath), "utf8"));
const required = [
  "githubRoute",
  "controllerAdapter",
  "signedHeartbeat",
  "scope",
  "configuration",
];
for (const key of required) {
  if (receipts[key] !== "pass") {
    process.stderr.write("cutover-incomplete\n");
    process.exit(1);
  }
}
if (receipts.grafana === "authority") {
  process.stderr.write("grafana-is-not-authority\n");
  process.exit(1);
}
process.stdout.write("cutover receipts: PASS\n");
