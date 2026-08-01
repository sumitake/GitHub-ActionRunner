# Portable-GHAR Task 11 Closed Synthetic Seed Catalog Amendment

## Scope

The reviewed Task 11 lifecycle contract requires one immutable synthetic seed
with this exact identity:

```text
id      portable-ghar-task11-seed-v1
path    task11/portable-ghar-task11-seed-v1.bin
target  tools/portable-ghar-task11-seed-v1/payload.bin
mode    0644
bytes   portable-ghar-task11-immutable-seed-v1\n
sha256  ef368121857519d3895e11481813b99d2e1d76d0555074a79d6af3ce9039e636
```

The current `internal/archive.Manifest` accepts only first-party action and
released-tool seeds. Both require external source/revision/license evidence,
and tool targets must contain a release revision. Reusing either kind would
misstate provenance or change the already-reviewed fixed target. A second
catalog, sidecar loader, runtime-created source, or direct copy path would
violate the single production hydration path.

This amendment closes only that representation gap. It does not change the
Task 11 protocol, add a general caller-defined seed class, alter production
action/tool validation, select a host or numeric value, or authorize Docker or
host execution.

## Closed schema extension

Add `archive.KindSynthetic` with wire value `synthetic`. It is not a generic
synthetic namespace. `validateManifest` accepts it only when all of these
predicates are simultaneously true:

1. the entire manifest contains exactly one seed;
2. `id` equals `portable-ghar-task11-seed-v1`;
3. `kind` equals `synthetic`;
4. `source` and `revision` are exact empty strings;
5. every `license` member is its exact zero value;
6. `files` has exactly one entry;
7. that entry has the exact path, target, digest, byte length, and mode listed
   above; and
8. all existing canonical JSON, duplicate-field, path, case-fold collision,
   tree verification, descriptor identity, publication, tree-lock, readiness,
   and hydration checks still run.

No individual predicate is defaulted. Because the fixed Go struct emits the
empty source/revision and zero license object, the canonical document remains
one declaration-ordered object and alternate omission is impossible.

The implementation imports the protocol-only
`internal/task11synthetic` constants into `internal/archive`; it does not
duplicate the seed bytes, path, target, digest, or ID. The dependency remains
acyclic because `task11synthetic` imports only the standard library.

`0644` becomes valid only inside the exact synthetic predicate. Existing
action/tool entries remain restricted to `0444` or `0555`. The installed seed
tree remains root-owned and its listener runs as numeric UID/GID `65532`, so
the source is readable but not writable; Task 11 independently performs the
required denied-write probe and post-run source digest check.

## Deterministic publication

Extend the existing build-time runtime-lock utility with a closed
`stage-synthetic-listener` operation. It accepts exactly:

- one canonical absolute listener path;
- one nonzero canonical evidence generation; and
- one fresh canonical absolute output directory.

It creates a private verified runner tree with only:

```text
bin/
bin/Runner.Listener
externals/
```

`externals/` is empty because the generic runner-tree validator requires the
top-level directory; it contains no GitHub runner external payload. The
listener is the only regular file. Existing `archive.VerifyRunnerDirectory`,
runner manifest, tree lock, `runtimelock.NewRunnerLock`, readback, readiness,
fsync, and cleanup-on-failure paths generate the same production gate inputs.
The runtime lock retains the pinned upstream-runner ABI/build fields, while
the image smoke test requires:

```text
gate verify-image == pinned upstream version without leading v
direct listener --version == portable-ghar-task11-synthetic-v1
the two values are unequal
```

The Task 11 preparation transaction:

1. builds the static Linux listener and runner gate from the current source;
2. stages the closed listener tree with the runtime-lock utility;
3. creates the exact private one-file source root and canonical synthetic
   manifest;
4. publishes that source through the existing `stage-seeds` operation;
5. stages one ignored, deny-all Docker context atomically; and
6. never invokes Docker, downloads an archive, contacts a provider, or writes
   outside the ignored context and private temporary directory.

CI and release preparation invoke this transaction before the existing
manifest-driven reproducibility build. The source task itself runs only
source tests and cross-compilation; it does not build the image locally.

## Adversarial requirements

Tests must reject:

- every single-field substitution of synthetic ID, kind, source, revision,
  license, path, target, digest, size, and mode;
- a second file, second seed, action/tool mixed with the synthetic seed, or
  an empty manifest passed as the synthetic asset;
- omission, duplicate JSON members, reordered members, alternate whitespace,
  extra fields, and trailing data through the existing canonical parser;
- `0644` on any action/tool seed and `0444`/`0555` on the synthetic seed;
- wrong listener path, mode, size, identity, generation, existing output,
  extra runner object, missing empty `externals`, changed staged listener, or
  failure before readiness;
- any Dockerfile context object outside the exact allowlist;
- equality between the gate ABI version and synthetic protocol version; and
- preparation lock collision, preexisting build output, indirect input, or
  partial publication.

Positive tests must re-load and re-verify the canonical manifest, source
directory, published seed tree, runner manifest, tree lock, runtime lock, and
readiness documents. The final image definition must retain the numeric
runner UID/GID, production gate, immutable seed cache, fixed work/tmp/scratch
directories, and no second listener payload.

## Stop conditions

Stop before schema implementation if the distinct-family architecture review
finds a material way this extension could authorize a caller-defined seed,
weaken existing action/tool provenance, admit a second payload, bypass
canonical publication, or create a second hydration path. Any material plan
change requires one changed-artifact confirmation before implementation.

No RhoNAS, QTS, Docker, service, selector, runner, or host configuration
change is authorized by this amendment.
