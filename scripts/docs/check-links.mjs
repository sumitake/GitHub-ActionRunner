#!/usr/bin/env node
// scripts/docs/check-links.mjs
//
// Deterministically verifies every LOCAL markdown link and same-file/
// cross-file anchor in the scanned files resolves on disk. External links
// (any scheme other than a bare local path -- http(s), mailto, etc.) are
// syntax-checked only via the WHATWG URL parser: this tool never performs a
// network request, DNS lookup, or shell evaluation of any kind.
//
// Usage:
//   node scripts/docs/check-links.mjs [PATH...]
//
// With no arguments, scans README.md and docs/ (recursively) relative to
// the current working directory. Each PATH may be a single .md file or a
// directory (scanned recursively for *.md, excluding node_modules/.git).
//
// Diagnostics: "path:line: message" (one per line, sorted, deterministic).
// Exit 0 iff no findings; prints "check-links: passed" on a clean default
// (argument-free) run only, mirroring scripts/sanitize_public.py's contract.

import { readFileSync, existsSync, statSync, readdirSync } from "node:fs";
import { join, resolve, dirname, extname } from "node:path";

const DEFAULT_PATHS = ["README.md", "docs"];
const SKIP_DIR_NAMES = new Set(["node_modules", ".git"]);

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

// ---------------------------------------------------------------------------
// Heading extraction + GitHub-style anchor slugs (fenced code blocks are
// excluded so a heading-shaped line inside an example is never treated as a
// real anchor target).
// ---------------------------------------------------------------------------

function slugify(heading) {
  const slug = heading
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9 _-]+/g, "")
    .trim()
    .replace(/\s+/g, "-");
  return slug === "" ? "-" : slug;
}

function extractHeadings(text) {
  const headings = [];
  let inFence = false;
  let marker = "";
  for (const raw of text.split("\n")) {
    const trimmed = raw.trim();
    if (trimmed.startsWith("```") || trimmed.startsWith("~~~")) {
      const fence = trimmed.slice(0, 3);
      if (!inFence) {
        inFence = true;
        marker = fence;
      } else if (trimmed.startsWith(marker)) {
        inFence = false;
      }
      continue;
    }
    if (inFence) continue;
    const m = /^#{1,6}\s+(.+?)\s*$/.exec(raw);
    if (m) headings.push(m[1]);
  }
  return headings;
}

function anchorSetFor(text) {
  const counts = new Map();
  const anchors = new Set();
  for (const heading of extractHeadings(text)) {
    const base = slugify(heading);
    const n = counts.get(base) ?? 0;
    counts.set(base, n + 1);
    anchors.add(n === 0 ? base : `${base}-${n}`);
  }
  return anchors;
}

const anchorCache = new Map();

function anchorsForFile(absPath) {
  if (anchorCache.has(absPath)) return anchorCache.get(absPath);
  let anchors;
  if (extname(absPath) === ".md" && existsSync(absPath) && statSync(absPath).isFile()) {
    anchors = anchorSetFor(readFileSync(absPath, "utf8"));
  } else {
    anchors = new Set();
  }
  anchorCache.set(absPath, anchors);
  return anchors;
}

// ---------------------------------------------------------------------------
// Link extraction (fenced code blocks excluded).
// ---------------------------------------------------------------------------

const LINK_RE = /!?\[[^\]]*\]\(([^)]+)\)/g;
// A leading scheme like "https:", "mailto:", "ftp:" marks an external
// target. Relative/absolute local paths never match (no leading letters
// immediately followed by ":").
const EXTERNAL_SCHEME_RE = /^[a-zA-Z][a-zA-Z0-9+.-]*:/;

function extractLinks(text) {
  const out = [];
  let inFence = false;
  let marker = "";
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (trimmed.startsWith("```") || trimmed.startsWith("~~~")) {
      const fence = trimmed.slice(0, 3);
      if (!inFence) {
        inFence = true;
        marker = fence;
      } else if (trimmed.startsWith(marker)) {
        inFence = false;
      }
      continue;
    }
    if (inFence) continue;
    LINK_RE.lastIndex = 0;
    let match;
    while ((match = LINK_RE.exec(raw)) !== null) {
      let target = match[1].trim();
      // Strip an optional "title" suffix: (url "title") or (url 'title').
      const titleIdx = target.search(/\s+["']/);
      if (titleIdx !== -1) target = target.slice(0, titleIdx).trim();
      if (target.startsWith("<") && target.endsWith(">")) {
        target = target.slice(1, -1);
      }
      out.push({ line: i + 1, target });
    }
  }
  return out;
}

function isSyntacticallyValidExternal(target) {
  try {
    // WHATWG URL parsing only: no network, no DNS, no fetch.
    // eslint-disable-next-line no-new
    new URL(target);
    return true;
  } catch {
    return false;
  }
}

function checkFile(absPath, findings) {
  const text = readFileSync(absPath, "utf8");
  for (const { line, target } of extractLinks(text)) {
    if (target === "") {
      findings.push(`${absPath}:${line}: empty link target`);
      continue;
    }
    if (EXTERNAL_SCHEME_RE.test(target)) {
      if (!isSyntacticallyValidExternal(target)) {
        findings.push(`${absPath}:${line}: external link is not a syntactically valid URI: ${target}`);
      }
      continue; // external: syntax-checked only, never fetched
    }

    const hashIdx = target.indexOf("#");
    const pathPart = hashIdx === -1 ? target : target.slice(0, hashIdx);
    const anchorPart = hashIdx === -1 ? "" : target.slice(hashIdx + 1);

    let targetFile = absPath;
    if (pathPart !== "") {
      targetFile = resolve(dirname(absPath), pathPart);
      if (!existsSync(targetFile) || !statSync(targetFile).isFile()) {
        findings.push(`${absPath}:${line}: local link target does not exist: ${pathPart}`);
        continue;
      }
    }
    if (anchorPart !== "") {
      const anchors = anchorsForFile(targetFile);
      if (!anchors.has(anchorPart)) {
        findings.push(
          `${absPath}:${line}: anchor #${anchorPart} not found in ${pathPart || "(same file)"}`
        );
      }
    }
  }
}

function main(argv) {
  const paths = argv.length === 0 ? DEFAULT_PATHS : argv;
  let files;
  try {
    files = collectMarkdownFiles(paths);
  } catch (err) {
    process.stderr.write(`check-links: ${err.message}\n`);
    return 1;
  }

  const findings = [];
  for (const file of files) {
    checkFile(file, findings);
  }
  findings.sort();
  for (const f of findings) process.stdout.write(f + "\n");

  if (findings.length > 0) return 1;
  process.stdout.write("check-links: passed\n");
  return 0;
}

process.exit(main(process.argv.slice(2)));
