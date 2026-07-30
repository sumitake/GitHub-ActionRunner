# Hosted CI Portability Repair Plan

## Scope and boundary

Repair only the failures revealed by the first hosted run of Portable-GHAR pull
request 15. Keep the Phase 2 source checkpoint distinct from deferred Linux/Docker
operational evidence. Do not deploy, activate, mutate a host, or begin Phase 3.

## Observed failures

1. Linux has `/tmp`, not Darwin's `/private/tmp`; seven test helpers therefore
   fail before exercising their contracts.
2. Linux connected Unix-stream `recvmsg` metadata differs from Darwin while
   the current fixed-frame reader treats any returned source address as a
   protocol failure.
3. Device plus inode is not a durable replacement identity after unlink:
   Linux may immediately reuse an inode for a newly created socket or lock
   object. Two replacement regressions demonstrated the resulting false
   acceptance.
4. Linux may reset a TCP connection during intentional over-capacity or
   rejected-TLS teardown; two test harnesses incorrectly require Darwin's
   close shape.
5. The container reproducibility gate builds twice without a fixed
   `SOURCE_DATE_EPOCH`, so image config/layer timestamps differ.
6. Hosted ShellCheck and local ShellCheck disagree on version-specific
   informational diagnostics. Actionlint also correctly rejects one
   `A && B || C` workflow expression.
7. CodeQL found two unchecked allocation-size sums and a uint32-to-int
   conversion without an explicit architecture bound.
8. Gitleaks scans the complete PR commit range and found one synthetic,
   deterministic digest fixture in an intermediate commit.
9. The second hosted Linux run exposed two more immediate-inode-reuse
   boundaries: the controller's local admin server could remove a replacement
   socket during shutdown, and the network adapter could accept a replacement
   broker socket whose device/inode pair had been recycled.
10. The second hosted Docker run proved that passing
    `SOURCE_DATE_EPOCH` as an undeclared build argument to plain
    `docker build` did not normalize every exported layer/config timestamp:
    the first two independent network-adapter images had different IDs.
11. The push-only full-history sanitizer scanned the intended complete
    reachable history, but its diagnostic `path@blob` label defeated the
    current exact-path allowlist and canonical CODEOWNERS context. Public,
    immutable Git author/committer identities were also treated as private
    mail findings, so the first complete-history run could never pass.
12. GNU `stat -f` succeeds with filesystem output rather than failing over to
    BSD-compatible mode output, so one Bats assertion used the wrong branch on
    Linux. CodeQL also requires an unconditional, explicit `uint32`-to-`int`
    representability bound before `os.Chown`.

## Threat model and invariants

- Untrusted jobs never receive the host authority directory. The broker sees
  it only through a read-only bind mount, and the production controller is the
  sole host-namespace writer. A hostile same-UID process with direct host
  namespace write access is already outside the qualified-host boundary; the
  controller must detect and quarantine any replacement observed at its
  boundaries, but does not claim conditional-unlink safety against a
  continuously racing trusted-host compromise.
- Within that isolation boundary, immediate allocator reuse must never make a
  replacement Unix socket or journal lock compare equal to the original.
- A framing repair must never accept extra payload bytes, truncated payloads,
  ancillary descriptors, truncation flags, missing half-close, or data from a
  different connection.
- The public authority-proof wire schema must not change.
- Lock serialization must retain independent open file descriptions; a pinned
  descriptor must never become the descriptor used for `flock`.
- An image comparison must use one immutable source-derived epoch for both
  builds and must still use independent no-cache builds.
- A secret-scan exception must bind one historical fingerprint only; it must
  not exempt a path, rule, digest pattern, or future commit.
- Historical policy evaluation must use the original repository path. Any
  suppression of the resulting historical diagnostic must instead bind the
  original path plus the complete 40-character blob OID, exact line, rule, and
  canonical content hash. A current-tree allowance never suppresses a
  historical blob implicitly.
- Commit-metadata exceptions may admit only a closed exact set of already
  public repository identities. They must not admit a domain, suffix, partial
  email, arbitrary GitHub identity, or near-miss owner mention.
- Disabling listener auto-unlink must not turn an ordinary process crash into
  a permanent restart failure. Stale-name recovery requires an independent
  proof that the prior writer is gone plus exclusive authority over the exact
  private parent; pathname metadata by itself is never recovery authority.

## Implementation

### 1. Portable test roots and Linux teardown shapes

- Add package-local test helpers that choose `/private/tmp` on Darwin and
  `/tmp` on Linux, preserving short Unix-socket paths.
- Replace only real `os.MkdirTemp("/private/tmp", ...)` calls. Synthetic
  transcript and fixture-path literals remain unchanged because they exercise
  serialization contracts rather than the local filesystem.
- In the over-capacity relay test, accept an immediate `ECONNRESET` from the
  second dial as the expected rejected-client outcome, while still proving the
  handler count never increases.
- In the CONNECT relay test harness, treat `ECONNRESET` as an expected
  teardown result only after the tested client has already rejected the
  exchange. These are TCP test-harness accommodations only: neither production
  relay code nor either Unix fixed-frame reader treats reset as canonical
  framing success.

### 2. Exact Unix frame portability

- Continue using `ReadMsgUnix` for every read so ancillary descriptors are
  observable and closed.
- Require the exact payload length, zero out-of-band bytes, and no
  `MSG_CTRUNC`/`MSG_TRUNC`.
- This helper is reachable only through `net.Dial(..., "unix", ...)` and
  `net.ListenUnix`, which are connected `AF_UNIX` `SOCK_STREAM` transports.
  Keep its API scoped to an already connected `*net.UnixConn` so a datagram or
  unconnected caller cannot reach it by convention alone.
  Do not use the optional source-address return as an authority signal. Peer
  authority remains the separately verified kernel peer credential. Ignore
  this metadata rather than rejecting Linux's unnamed-peer representation.
  No datagram or unconnected call site is admitted.
- Still require the post-frame read to return zero bytes and EOF.
- Add a direct connected-stream regression plus existing extra-byte,
  short-read, truncation, ancillary-descriptor, non-EOF completion, and
  missing-half-close regressions. Replace the test-only datagram fixture for
  `ReadDialRequestUnix` with a connected stream pair so its tests exercise the
  declared transport rather than an ineligible datagram transport.

### 3. Replacement-resistant object pinning

- Do not treat `UnixListener.File` as a filesystem-vnode pin. A live Darwin
  probe proved that `fstat` on the duplicated listener reports the kernel
  socket object's device/inode/mode/ownership, not the bound pathname's
  filesystem identity. Linux has the same socket-object versus pathname-vnode
  distinction.
- Retain an exact descriptor for the private authority directory for the
  endpoint lifetime. Verify it against the already validated `0700` directory
  identity, and use `openat`, `fstatat(AT_SYMLINK_NOFOLLOW)`, and `unlinkat`
  with the fixed literal `dial-authority.sock`. Re-open the absolute directory
  only to prove that its public name still resolves to the pinned directory;
  never use that traversal as cleanup authority.
- On Linux, immediately after bind/final chmod/chown, open the final socket
  entry relative to that directory descriptor with
  `O_PATH|O_NOFOLLOW|O_CLOEXEC`. Require `fstat(pin)` and
  `fstatat(directoryFD, literal, AT_SYMLINK_NOFOLLOW)` to match the final
  public identity before the endpoint can become active, then retain both
  descriptors. `O_PATH` references the filesystem object without opening the
  socket for I/O, so it pins the original pathname inode against reuse. The
  qualified-host isolation above is what excludes a hostile concurrent swap
  between `bind` and pin establishment; construction still fails if a
  replacement is actually observed. Failure to open or stat either retained
  descriptor aborts activation; the qualified Linux filesystem/kernel must
  support these operations.
- Darwin is a development/test platform, not an approved runner host, and has
  no `O_PATH` equivalent that can open a Unix-socket vnode. Retain a closed
  internal fingerprint containing the public identity plus kernel-controlled
  high-resolution change and birth times, and require exact equality at
  cleanup. This never upgrades Darwin to production evidence; it only avoids
  accepting immediate inode reuse in local tests. Linux remains the required
  positive operational platform.
- Stop ordering is exact: pre-verify directory, pin/fingerprint, and current
  entry before closing the serving listener; close the listener; verify all
  three again; `unlinkat` only on equality; prove the entry absent with
  `fstatat`; close the guard; then deactivate the ledger. Never remove a
  mismatched entry and never deactivate after replacement detection.
- After successful guard establishment, explicitly disable `UnixListener`'s
  automatic unlink behavior. From that point onward, only the retained
  directory's guarded `unlinkat` path owns cleanup. Every construction failure
  before and after that transfer closes each acquired descriptor exactly once,
  removes only a still-matching object, and preserves any observed replacement.
- Removal is a one-shot state machine. After a final equality check, call
  `unlinkat` at most once. Any unlink error, a name that remains or reappears,
  or (on Linux) a pinned socket whose link count does not become zero
  quarantines the guard: retain its pins, perform no second name unlink, do not
  deactivate the ledger or report clean shutdown, reject reuse, and return the
  cleanup error with mismatch precedence. Only `ENOENT` plus the expected
  unlinked pin state marks removal successful.
- A pre-close mismatch returns with the listener state untouched. A
  post-close mismatch is a closed, explicitly quarantined endpoint: keep the
  pin and active ledger, reject future reuse, and return failure. There is no
  force-unlink or best-effort-deactivate path. Recovery may accept only an
  already inactive ledger plus absent entry, or the still-live exact endpoint;
  it never infers identity from a bare pathname after the pin is gone.
- A pin-close error after confirmed path removal does not restore admission:
  continue the safe ledger deactivation, then return the cleanup error. This
  prevents a capacity leak without converting cleanup failure into success.
  Every pin is closed exactly once on success and every construction failure.
- Keep the journal store's bootstrap lock descriptor open as a lifetime pin.
  Each lease continues to open the pathname independently for `flock`, so
  serialization semantics do not collapse across duplicated descriptors.
- During `Acquire`, duplicate both the root descriptor and the pin descriptor
  under the store mutex; `fstat` the pin duplicate; independently
  `openat(O_RDWR|O_NOFOLLOW|O_CLOEXEC)` and `fstat` the prospective lock
  descriptor; require the two already-open descriptors to have the same
  identity; then `flock` only the prospective lock descriptor. Close the
  temporary pin duplicate after `flock` succeeds. Neither the lifetime pin nor
  its duplicate is ever passed to `flock`. Root-duplication failure performs no
  pin duplication; pin-duplication failure closes the root duplicate; every
  later failure closes both temporary duplicates exactly once.
- Model the post-`flock` transition explicitly. Until lease publication, the
  prospective lock FD remains cleanup-owned. Any pin-close or subsequent
  verification failure performs `LOCK_UN` and closes that prospective FD
  exactly once, closes each still-open temporary duplicate at most once, and
  returns the integrity error. Successful publication transfers the root and
  prospective lock FDs to the lease and leaves no deferred cleanup owner. No
  branch unlocks or closes the lifetime pin or flocks a duplicate of its open
  file description.
- Extend Linux replacement tests to require a numerically distinct live inode
  while the original descriptor is pinned. On Darwin, require the internal
  fingerprint to reject the replacement even if the public device/inode pair
  happens to repeat. Retain the existing fail-closed ledger/journal
  assertions, and exercise two concurrent lease attempts on Linux and Darwin
  to prove independent-open serialization remains intact.
- Add guard-level Linux regressions for an entry replaced after pinning,
  pre-close and post-close mismatch quarantine, construction cleanup that
  never removes a mismatch, and relative-directory cleanup. The existing
  production-controller target checks (`runtime.GOOS == overlay.Target.OS`
  and the closed overlay target `linux`) remain the hard gate preventing the
  Darwin fingerprint branch from becoming deployment evidence. If the local
  filesystem does not expose the required high-resolution fingerprint, the
  Darwin regression skips with an explicit unsupported reason and production
  remains fail-closed; it never becomes positive operational evidence.
- Recovery admits no bare-path revival: it accepts only an already inactive
  ledger with an absent entry, or a still-live endpoint whose retained guard
  verifies. Once the guard is lost, pathname identity alone is insufficient.
- Restart liveness is supplied by the owning lifecycle rather than by weakening
  this rule. The controller's admin/health recovery runs only after its
  exclusive process-ownership lock is acquired and revalidated; under that
  independent prior-writer-dead proof it opens the exact `0700` parent, accepts
  only the two fixed same-UID `0600` single-link socket entries, removes them
  relative to the retained directory FD, fsyncs the parent, and proves absence
  before constructing either server. Any extra or mismatched entry fails
  closed. Dial-authority directories are per-job: restart reconciliation proves
  the referenced adapter, broker, and runner objects gone and removes the
  complete private per-job directory while retaining the durable permit
  ledger. The adapter control socket lives in a no-restart ephemeral
  container-private runtime directory, so container replacement removes crash
  residue; it is never revived in place from a bare path.

### 4. Deterministic CI contracts

- Derive a positive `SOURCE_DATE_EPOCH` from exact `HEAD`, pass it to both
  no-cache Docker builds both as the standardized environment variable and
  the Dockerfile build argument, and declare that argument in every compared
  Dockerfile. Use a fixed `linux/amd64` platform and
  `docker buildx build --output type=docker,...,rewrite-timestamp=true`, while
  disabling comparison-build provenance and SBOM generation. Pin the hosted
  Buildx setup action. Build failure on an unsupported exporter option remains
  fatal, and after each export inspect the local image config and require its
  creation timestamp to parse to the exact derived epoch. Preserve independent
  no-cache builds and image-ID equality as a true failure; do not replace the
  comparison with a weaker successful-build check.
- Make workflow ShellCheck operate at warning-or-higher severity on the exact
  tracked shell inventory, matching the source gate across ShellCheck
  versions. Keep informational diagnostics advisory.
- Rewrite the workflow gofmt check as an explicit `if`, satisfying actionlint.
- Remove unsafe capacity preallocation hints flagged by CodeQL and explicitly
  reject UID/GID values above the unconditional current-architecture maximum
  `int` before conversion and `os.Chown`.
- Add exactly one `.gitleaksignore` fingerprint for the historical synthetic
  finding; do not add regex/path/rule allowlists.

### 5. One shared lifetime socket guard

- Add one internal Unix-socket path guard with Linux and Darwin
  implementations and use it for dial authority, local admin/health, adapter
  control, and the adapter's read-only broker binding. Expose a read-only guard
  with `Verify`/`Close` and a distinct owned guard that alone adds one-shot
  `Remove`; a read-only broker guard cannot accidentally unlink its source.
  Its public snapshot is the exact directory and socket
  device/inode/UID/GID/mode tuple; the socket name is one validated fixed path
  element, never a traversal. Remove the endpoint-specific authority pin
  implementations after parity tests prove the shared primitive supplies the
  same or stronger contract.
- Linux opens and retains the directory with
  `O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC` and the socket entry with
  `openat(O_PATH|O_NOFOLLOW|O_CLOEXEC)`. Every verification compares the
  absolute directory name, directory descriptor, socket descriptor, and
  `fstatat(AT_SYMLINK_NOFOLLOW)` entry against the same snapshot. Holding the
  socket descriptor prevents allocator reuse of the original inode.
- Darwin retains the directory descriptor and a fingerprint containing the
  public tuple plus high-resolution change and birth times. Darwin remains a
  development platform; this fingerprint is not Linux production evidence.
- Each local admin/health server establishes the guard immediately after final
  mode assignment and before returning from construction. Listener automatic
  unlink remains enabled only until the guard is proven; if guard
  establishment observes a mismatch, disable automatic unlink before closing
  so a replacement is preserved. On successful guard establishment, also
  disable automatic unlink permanently and transfer sole cleanup ownership to
  the guard. Enumerate every post-bind failure: close acquired guard
  descriptors, close the listener, remove only the still-matching original
  through guarded relative unlink, and preserve a mismatch. Shutdown verifies
  before close, closes the listener, re-verifies, unlinks relative to the
  retained directory descriptor only on equality, proves absence, and closes
  the guard. Any mismatch returns `errLocalProtocol` and never removes the
  replacement.
- The adapter control listener uses the same owned-guard cleanup transfer. The
  network adapter establishes a separate read-only guard exactly once after
  receiving the authenticated broker binding and before acknowledging
  readiness or opening relay listeners. The captured snapshot must equal the
  complete binding. Every relay verifies that retained guard before dial and
  after connect; the guard remains open for the complete adapter lifetime and
  closes only after relay serving ends. A standalone path re-stat is not
  represented as replacement proof.

### 6. Full-history sanitizer coherence

- Scan historical blob content using its original repository path as policy
  context. After classification, label returned diagnostics with
  `original/path@<full-40-character-blob-oid>`; a short OID may appear only as
  a human display abbreviation and is never a matching key. This preserves
  fixture qualification and canonical CODEOWNERS policy without letting
  current-tree policy suppress a different immutable blob.
- Historical allowlist lookup accepts only an exact full-OID diagnostic label.
  It never falls back to the original current-tree path. Add explicit
  historical-label records for every legitimate immutable finding: the
  historical instances corresponding to current exact allowances plus the
  nine inspected synthetic findings (seven secret-shaped runtime fixtures,
  one rejected absolute-path fixture, and one synthetic job UUID fixture).
  Every record binds full blob OID, original path, exact line, rule, and
  canonical content hash; no line-insensitive, path-only, wildcard, OID-prefix,
  or rule-wide suppression is introduced.
- During commit/tag/ref metadata scanning only, admit a literal,
  case-sensitive closed set already present in public repository history:
  `GitHub <noreply@github.com>`,
  `John Osumi <931193+sumitake@users.noreply.github.com>`,
  `dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>`,
  `Signed-off-by: dependabot[bot] <support@github.com>`, both exact historical
  capitalization variants of the full
  `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` line, and the exact
  historical metadata line containing the canonical `@sumitake` owner mention.
  No normalization, domain/suffix
  rule, or defaulting is permitted. Unknown mail, mixed known/unknown mail,
  arbitrary GitHub-domain addresses, case changes, and owner-prefix or
  owner-suffix near misses remain findings.
- Keep complete reachable-history scanning on push, schedule, and manual
  dispatch. Do not downgrade it to current-tree-only or silently baseline all
  ancestors.

### 7. Shell portability

- Query GNU mode first (`stat -c %a`) and fall back to BSD mode
  (`stat -f %Lp`) only when GNU mode is unavailable. Preserve the exact
  expected `400` assertion.

## RED and GREEN verification

1. Add focused tests for:
   - portable test-root selection;
   - Linux connected-stream framing metadata;
   - socket and lock replacement while the original object remains pinned;
   - immediate `ECONNRESET` rejection paths;
   - required deterministic Docker flags and exact source epoch;
   - the exact one-entry Gitleaks fingerprint contract;
   - ShellCheck tracked-inventory/severity and actionlint workflow shape;
   - local-admin and adapter lifetime guards rejecting same-UID replacements
     while the original Linux vnode remains pinned;
   - owner-lock-authorized admin/health crash-residue cleanup, and rejection of
     stale names when the independent ownership proof is absent;
   - one-shot unlink error, post-unlink recreation, and Linux pinned-link-count
     quarantine with no second unlink or ledger deactivation;
   - every journal failure after successful `flock`, proving exactly one
     unlock/close of the prospective lock and no operation on the lifetime pin;
   - historical policy-path restoration, mandatory full-blob-OID allowances
     with no current-path fallback, literal closed public metadata identities,
     and unknown/mixed/near-miss negative cases;
   - GNU-first/BSD-fallback file-mode inspection;
   - Buildx image-export timestamp rewriting without weakening image-ID
     comparison, including exact exported config epoch inspection.
2. Observe the focused tests fail for the intended reason before production
   edits.
3. Implement the minimum changes, run focused tests, `go test ./...`,
   `go test -race ./...`, `go vet ./...`, staticcheck, shellcheck, shfmt,
   Bats, workflow policy, repository metadata, sanitization, and the complete
   source gate.
4. Push a new signed head. Count only hosted Linux/Docker/CodeQL/Gitleaks
   results on that exact head.
5. Seal the changed-head diff and obtain a substantive exact-artifact
   distinct-family Grok review before normal merge.

## Distinct-family cross-check adjudication

Two Grok architecture rounds completed before the revised socket-pin
implementation. The accepted changes are: directory-FD-relative verification
and removal, an absolute-directory identity check to detect parent replacement,
pre-close and immediate pre-unlink verification, fail-closed quarantine after
any post-close mismatch, exact journal FD-to-FD comparison before `flock`, and
an explicit `0700` sole-writer authority boundary.

Two findings do not change the implementation. A duplicated
`UnixListener.File` descriptor cannot equal the bound pathname vnode: a live
Darwin probe showed that `fstat` reports the kernel socket object instead.
Journal release already unlocks and closes the exact retained lease descriptor
without reopening its pathname. Crash recovery remains the pre-existing
controller transaction/restart responsibility; this repair neither broadens
recovery nor accepts a pathname-only identity after a guard is lost.

The first exact-patch Grok review of signed head `145f4d1` correctly found two
cleanup gaps. Construction now keeps listener unlink-on-close enabled until the
socket pin is established, but disables it on an observed pin/path mismatch so
a replacement is never removed. Journal acquisition now duplicates the root
first, attempts the pin only after root success, and closes the root duplicate
if pin duplication fails. Focused failure-injection regressions cover all three
branches before the changed-head confirmation review.

The hosted-failure repair reconsultation first required full 40-character blob
OID allowlist keys with no current-path fallback, explicit listener cleanup
ownership transfer, fixed-platform timestamp-rewriting exports, literal
metadata identities, and positive kernel/filesystem capability failure. Those
changes materially revised this plan and triggered another Grok round. That
round correctly found six remaining design obligations now integrated above:
owner-lock or ephemeral-root crash-residue recovery, one-shot post-unlink
quarantine, explicit post-`flock` cleanup, one shared socket-guard primitive,
strict separation of TCP reset tests from Unix framing, and positive exported
config epoch inspection.

Several tail claims in the same model response are rejected as contradicted by
the artifact and do not change the plan: connected-stream `ReadMsgUnix` already
loops over partial reads and rejects non-EOF completion; a numeric FD reuse
cannot alias two simultaneously open descriptions; post-close mismatch already
keeps the ledger active; and the historical allowlist key includes the immutable
full blob OID, so a future blob cannot reuse it.

The final confirm-only Grok 4.5 review covered the exact 27,023-byte plan
artifact with SHA-256
`630b3ae1b2884de27914027c771ca030e9b158bcc7bff434e38a1f46f2d5b3d1`
(session `019fb397-719e-7512-b967-38d8894ee28b`, request
`fa514a8b-f708-4c51-aaed-d97956da5fe6`). Its schema-constrained result was
`PROCEED` with an empty material-gap list. The implementation therefore starts
only after this converged design checkpoint.

## Stop conditions

- Stop if the framing repair needs to weaken byte/OOB/truncation/EOF checks.
- Stop if object pinning changes the public proof schema or lock serialization.
- Stop if reproducibility requires dropping the image-ID comparison.
- Stop if any secret-scan exception is broader than one exact immutable
  finding tuple.
- After the verified, reviewed Phase 2 source PR merges, report the exact PR
  and merge commit plus deferred operational gates, then pause.

## Adversarial review request

Review this plan as a self-contained, read-only design artifact. Attack
fail-open framing, descriptor lifetime, inode reuse, flock aliasing,
cleanup/error precedence, Linux/Darwin divergence, reproducibility false
evidence, and overbroad secret-scan exemptions. Return `PROCEED` only if no
material design gap remains; otherwise return `REVISE` with concrete required
changes.
