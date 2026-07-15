#!/usr/bin/env node
// scripts/docs/check-command-examples.mjs
//
// Deterministically verifies every fenced ```operator-command``` block in
// the scanned docs contains only commands that map to either:
//   (a) an existing repo-relative script/executable path, or
//   (b) a documented PLANNED_EXECUTABLE -- a binary named in the Phase 1
//       repository layout that does not exist yet (Phase 1 ships no
//       runtime code). See docs/superpowers/specs/2026-07-10-portable-ghar-
//       platform-design.md section 14 (cmd/portable-ghar-controller/) and
//       docs/superpowers/plans/2026-07-11-controller-runtime.md
//       (cmd/portable-ghar-watchdog/).
//
// This is a purely lexical check: it never spawns, evaluates, or otherwise
// executes any command it reads. Only fenced blocks whose info string is
// exactly "operator-command" are inspected; every other fence (```sh,
// ```yaml, ```text, ```mermaid, ...) is left untouched, so illustrative
// non-operator snippets (job YAML, plain shell examples) are never treated
// as an operator-command contract.
//
// Usage:
//   node scripts/docs/check-command-examples.mjs [PATH...]
//
// With no arguments, scans README.md and docs/ (recursively) relative to
// the current working directory.
//
// Diagnostics: "path:line: message" (one per line, sorted, deterministic).
// Exit 0 iff no findings.

import { readFileSync, existsSync, statSync, readdirSync } from "node:fs";
import { join, resolve, extname } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(fileURLToPath(new URL("../../", import.meta.url)));
const DEFAULT_PATHS = ["README.md", "docs"];
const SKIP_DIR_NAMES = new Set(["node_modules", ".git"]);
const FENCE_LANG = "operator-command";

// Bare planned binary names an operator-command line may invoke directly.
// Neither exists on disk yet in Phase 1; both are named in the Phase 2+
// repository layout cited above.
const PLANNED_EXECUTABLES = new Set([
  "portable-ghar",
  "portable-ghar-watchdog",
]);

// Known interpreters that may prefix a repo-relative script path in an
// illustrative command line (e.g. "python3 scripts/sanitize_public.py").
// The interpreter itself is not validated; the token that follows is.
const KNOWN_INTERPRETERS = new Set(["python3", "node", "bash", "sh"]);

function collectMarkdownFiles(startPaths) {
  const files = [];
  for (const p of startPaths) {
    const abs = resolve(p);
    if (!existsSync(abs)) {
      throw new Error(`path does not exist: ${p}`);
    }
    const stat = statSync(abs);
    if (stat.isDirectory()) {
      walk(abs, files);
    } else {
      files.push(abs);
    }
  }
  return [...new Set(files)];
}

function walk(dir, files) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIR_NAMES.has(entry.name)) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full, files);
    } else if (entry.isFile() && extname(entry.name) === ".md") {
      files.push(full);
    }
  }
}

function extractOperatorCommandBlocks(text) {
  const lines = text.split("\n");
  const blocks = [];
  let inBlock = false;
  let marker = "";
  let startLine = 0;
  let buf = [];
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (!inBlock && (trimmed.startsWith("```") || trimmed.startsWith("~~~"))) {
      const fence = trimmed.slice(0, 3);
      const lang = trimmed.slice(3).trim();
      if (lang === FENCE_LANG) {
        inBlock = true;
        marker = fence;
        startLine = i + 2; // 1-based line number of the first content line
        buf = [];
      }
      continue;
    }
    if (inBlock && trimmed.startsWith(marker)) {
      blocks.push({ startLine, lines: buf });
      inBlock = false;
      buf = [];
      continue;
    }
    if (inBlock) buf.push(raw);
  }
  // An unterminated block at EOF is not itself validated further here;
  // its lines were never pushed, so nothing spurious is checked.
  return blocks;
}

function resolveCommandToken(line) {
  const tokens = line.trim().split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return null;
  if (KNOWN_INTERPRETERS.has(tokens[0])) {
    return tokens.length > 1 ? tokens[1] : null;
  }
  return tokens[0];
}

function isKnownCommand(token) {
  if (token.includes("/")) {
    const candidate = resolve(REPO_ROOT, token);
    return existsSync(candidate) && statSync(candidate).isFile();
  }
  return PLANNED_EXECUTABLES.has(token);
}

function relDisplay(absPath) {
  return absPath.startsWith(REPO_ROOT)
    ? absPath.slice(REPO_ROOT.length + 1)
    : absPath;
}

function checkFile(absPath, findings) {
  const text = readFileSync(absPath, "utf8");
  for (const block of extractOperatorCommandBlocks(text)) {
    block.lines.forEach((raw, idx) => {
      const trimmed = raw.trim();
      if (trimmed === "" || trimmed.startsWith("#")) return;
      const lineNo = block.startLine + idx;
      const token = resolveCommandToken(trimmed);
      if (token === null) {
        findings.push(
          `${relDisplay(absPath)}:${lineNo}: operator-command line has no command token: ${JSON.stringify(trimmed)}`,
        );
        return;
      }
      if (!isKnownCommand(token)) {
        findings.push(
          `${relDisplay(absPath)}:${lineNo}: unknown operator command ${JSON.stringify(token)} (not an existing repo-relative script path and not a documented planned executable)`,
        );
      }
    });
  }
}

function main(argv) {
  const paths = argv.length === 0 ? DEFAULT_PATHS : argv;
  let files;
  try {
    files = collectMarkdownFiles(paths);
  } catch (err) {
    process.stderr.write(`check-command-examples: ${err.message}\n`);
    return 1;
  }

  const findings = [];
  for (const file of files) {
    checkFile(file, findings);
  }
  findings.sort();
  for (const f of findings) process.stdout.write(f + "\n");

  if (findings.length > 0) return 1;
  process.stdout.write("check-command-examples: passed\n");
  return 0;
}

process.exit(main(process.argv.slice(2)));
