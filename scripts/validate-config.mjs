#!/usr/bin/env node
// Validates the portable-ghar public config schemas and their synthetic
// examples with Ajv (JSON Schema draft 2020-12, strict mode, allErrors).
//
// Library usage:
//   import { validateFile } from "./scripts/validate-config.mjs";
//   const { valid, errors } = validateFile(schemaPath, dataPath);
//
// CLI usage:
//   node scripts/validate-config.mjs
// Validates all four schema/example pairs below. On success, prints exactly
// "validated 4 synthetic examples" and exits 0. On any failure, prints the
// Ajv errors for each failing pair and exits 1.

import { readFileSync } from "node:fs";
import { resolve, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

function resolvePath(path) {
  return isAbsolute(path) ? path : resolve(process.cwd(), path);
}

function loadJson(path) {
  const raw = readFileSync(resolvePath(path), "utf8");
  return JSON.parse(raw);
}

function createAjv() {
  const ajv = new Ajv({ strict: true, allErrors: true });
  addFormats(ajv);
  return ajv;
}

/**
 * Validate the JSON document at dataPath against the JSON Schema at
 * schemaPath. Never throws for a schema-validation failure; it returns
 * { valid: false, errors } instead. Throws only for genuine I/O or JSON
 * parse errors (missing file, malformed JSON, invalid schema).
 *
 * @param {string} schemaPath
 * @param {string} dataPath
 * @returns {{ valid: boolean, errors: import("ajv").ErrorObject[] | null }}
 */
export function validateFile(schemaPath, dataPath) {
  const schema = loadJson(schemaPath);
  const data = loadJson(dataPath);
  const ajv = createAjv();
  const validate = ajv.compile(schema);
  const valid = validate(data);
  return { valid, errors: valid ? null : validate.errors };
}

const PAIRS = [
  ["config/schema/fleet.schema.json", "config/examples/fleet.example.json"],
  ["config/schema/host-profile.schema.json", "config/examples/host-profile.example.json"],
  ["config/schema/public-log-event.schema.json", "config/examples/public-log-event.example.json"],
  [
    "config/schema/notification-event.schema.json",
    "config/examples/notification-event.example.json",
  ],
];

function main() {
  const failures = [];
  for (const [schemaPath, dataPath] of PAIRS) {
    const { valid, errors } = validateFile(schemaPath, dataPath);
    if (!valid) {
      failures.push({ schemaPath, dataPath, errors });
    }
  }

  if (failures.length > 0) {
    for (const failure of failures) {
      console.error(`FAIL ${failure.dataPath} against ${failure.schemaPath}`);
      console.error(JSON.stringify(failure.errors, null, 2));
    }
    process.exit(1);
  }

  console.log(`validated ${PAIRS.length} synthetic examples`);
  process.exit(0);
}

const invokedDirectly =
  process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (invokedDirectly) {
  main();
}
