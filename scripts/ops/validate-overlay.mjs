#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import Ajv from "ajv/dist/2020.js";

const overlayPath = process.argv[2];
if (!overlayPath) {
  process.stderr.write("arguments\n");
  process.exit(2);
}

const schema = JSON.parse(
  readFileSync(resolve("config/schema/private-overlay.schema.json"), "utf8"),
);
const document = JSON.parse(readFileSync(resolve(overlayPath), "utf8"));
const ajv = new Ajv({ strict: true, allErrors: true });
const validate = ajv.compile(schema);
if (!validate(document)) {
  process.stderr.write("overlay-invalid\n");
  process.exit(1);
}
process.stdout.write("failover configuration: PASS\n");
