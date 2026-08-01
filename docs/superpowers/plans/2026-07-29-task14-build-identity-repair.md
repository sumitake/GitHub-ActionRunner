# Portable-GHAR Task 14 Build-Identity Repair Plan

## Scope and stop conditions

Repair only the Task 14 contract that every registered production Linux/amd64
binary is attributable to the exact release version and source commit used by
the immutable release workflow. Do not deploy, publish, tag, activate, mutate
a host, or broaden the command-line surface. Preserve deterministic stripped
static binaries and the empty Go build ID.

Stop if the design cannot prove all 11 manifest-registered binaries carry one
coherent identity, or if the repair would require a mutable/generated source
overlay that is absent from the exact source tree.

## Reproduced defect

The release rehearsal passed:

- `-X github.com/sumitake/portable-ghar/internal/buildinfo.version=...`
- `-X github.com/sumitake/portable-ghar/internal/buildinfo.commit=...`

but `buildinfo.Info()` was unused and two command packages did not link
`internal/buildinfo` at all. All 11 independently built binaries lacked both
requested values. The existing test only grepped the rehearsal source for the
flags, so it proved command text rather than produced bytes.

## Threat and failure model

The repair must close:

1. linker dead-code elimination of all stamped variables;
2. a command package that never links the identity package;
3. version-only, commit-only, default-value, or cross-paired identities;
4. independent substring checks satisfied by unrelated source bytes;
5. delimiter ambiguity or injection through a release version;
6. a test that verifies build commands without inspecting all produced
   binaries;
7. nondeterministic metadata, build IDs, paths, or wall-clock values;
8. candidate overlay behavior accidentally rewriting this release identity
   contract;
9. tests passing for the wrong filesystem-mode reason under `umask 077`.

## Closed identity format

Add a third linker-set package variable `stamp` beside `version` and `commit`.
Its exact ASCII value is:

`portable-ghar-build-identity-v1|VERSION|COMMIT`

`VERSION` is already constrained by the rehearsal's closed safe-version
grammar, which excludes `|`. `COMMIT` is the exact lowercase 40-hex detached
source commit. Defaults remain coherent for developer builds:

`version=dev`, `commit=unknown`,
`stamp=portable-ghar-build-identity-v1|dev|unknown`.

One pure Go helper in `internal/buildinfo` is the sole framing and validation
authority. It accepts either the exact developer default pair `dev/unknown`,
or a release pair where:

- `VERSION` matches the rehearsal's exact safe-version grammar, including the
  ban on `..`; and
- `COMMIT` is exactly 40 lowercase hexadecimal bytes.

At package initialization, invoke that helper over live `version` and `commit`
variables and panic unless the live `stamp` variable is byte-equal to the
helper's result. This makes partial or mismatched `-X` assignments fail closed
at process start and creates observable reads of all three linker-set symbols.

Every production command must directly import `internal/buildinfo`; transitive
linkage is not accepted. Retain existing direct imports and add explicit blank
imports to every remaining manifest command. Do not add a new `--version`
command or change accepted command arguments.

## Rehearsal enforcement

For every manifest-registered binary:

1. invoke a fixed build-time Go helper that calls the pure Go framing
   authority; use its single-line output as the only source of the `stamp`
   linker value;
2. build with the existing deterministic flags plus exact `-X` assignments
   for `version`, `commit`, and that computed `stamp`;
3. run a fixed host-native test harness under the identical three `-X` values;
   it must start successfully, read live `version` and `commit` through
   `Info()`, and prove live `stamp` equals the helper-computed frame;
4. retain the existing ELF64/x86-64, mode, and no-checkout-path checks;
5. require one single contiguous framed-stamp needle in the final binary;
   independent prefix, version, or commit needles are never sufficient;
6. reject the default framed stamp and any missing exact frame;
7. keep `-buildid=` empty and `-buildvcs=false`.

The release manifest remains the sole closed binary inventory; no hard-coded
second list is introduced.

Candidate substitution overlays may not modify the framing helper, build-info
initializer, direct-import wiring, build-time framing command, rehearsal
three-value linker surface, or manifest-loop binary assertion. Add a policy
test proving all such paths are absent from `replace: true` substitutions;
retain the existing candidate token/inventory closure gate as a separate
identity-data check.

## RED-to-GREEN tests

1. Replace the static source-grep Bats assertion with an executable build of
   every binary row from `release/manifest.json`, using a fixture version and
   generated 40-hex commit that do not add a literal candidate-identity token
   to tracked source.
2. Before implementation, prove the test fails because the exact contiguous
   frame is absent.
3. Prove every manifest package directly imports `internal/buildinfo`.
4. Run a deliberately partial or mismatched host-native link and require
   package initialization to panic before tests run. Then run the same fixed
   harness under the coherent three-value linker tuple and require live
   `Info()` plus live `stamp` equality to pass.
5. After implementation, require the one exact contiguous framed needle in all
   11 Linux output binaries. Separate substring checks do not count.
6. Add focused `internal/buildinfo` unit coverage for the sole framing helper,
   exact safe-version grammar, exact lowercase 40-hex commit, default-pair
   exception, empty/mismatch rejection, and field order.
7. Add the candidate-overlay non-interference policy check described above,
   then preserve and rerun the real candidate token/inventory closure test.
8. Run the full source gate under its real `umask 077`, including all Bats,
   Python, workflow-policy, sanitizer, metadata, race, and integrity stages.
9. Build all 11 binaries twice from the final signed commit using disjoint
   private `GOCACHE`, `GOMODCACHE`, and `GOPATH`; require byte equality, exact
   ELF platform, the one exact framed identity, and no checkout path.
10. Run the opt-in full gate and record the expected typed macOS stop only at
   `linux-docker-preflight`; do not count it as Linux/Docker evidence.

## Review and checkpoint

Seal the exact changed-artifact diff and obtain direct distinct-family
xAI/Grok review. Any material change requires a matching-digest confirmation.
Amend only the reviewed Task 14 paths into the signed checkpoint. Push and
open the governed Phase 2 source-completion PR only after all source gates
pass. The PR must say “Phase 2 source complete,” never “Phase 2 fully
verified,” and must preserve every deferred Linux/Docker, forced-bump,
observability, sizing, activation, and host-change gate.
