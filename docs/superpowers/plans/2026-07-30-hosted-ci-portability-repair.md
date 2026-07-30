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
  exchange.

### 2. Exact Unix frame portability

- Continue using `ReadMsgUnix` for every read so ancillary descriptors are
  observable and closed.
- Require the exact payload length, zero out-of-band bytes, and no
  `MSG_CTRUNC`/`MSG_TRUNC`.
- This helper is reachable only through `net.Dial(..., "unix", ...)` and
  `net.ListenUnix`, which are connected `AF_UNIX` `SOCK_STREAM` transports.
  Do not use the optional source-address return as an authority signal. Peer
  authority remains the separately verified kernel peer credential. Ignore
  this metadata rather than rejecting Linux's unnamed-peer representation.
  No datagram or unconnected call site is admitted.
- Still require the post-frame read to return zero bytes and EOF.
- Add a direct connected-stream regression plus existing extra-byte,
  truncation, ancillary-descriptor, and missing-half-close regressions.

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
  replacement is actually observed.
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
  its duplicate is ever passed to `flock`.
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
  Darwin fingerprint branch from becoming deployment evidence.

### 4. Deterministic CI contracts

- Derive a positive `SOURCE_DATE_EPOCH` from exact `HEAD`, pass it to both
  no-cache Docker builds, and disable comparison-build provenance. Preserve
  image-ID equality as a true failure.
- Make workflow ShellCheck operate at warning-or-higher severity on the exact
  tracked shell inventory, matching the source gate across ShellCheck
  versions. Keep informational diagnostics advisory.
- Rewrite the workflow gofmt check as an explicit `if`, satisfying actionlint.
- Remove unsafe capacity preallocation hints flagged by CodeQL and explicitly
  reject UID/GID values that cannot fit `int` on the current architecture.
- Add exactly one `.gitleaksignore` fingerprint for the historical synthetic
  finding; do not add regex/path/rule allowlists.

## RED and GREEN verification

1. Add focused tests for:
   - portable test-root selection;
   - Linux connected-stream framing metadata;
   - socket and lock replacement while the original object remains pinned;
   - immediate `ECONNRESET` rejection paths;
   - required deterministic Docker flags and exact source epoch;
   - the exact one-entry Gitleaks fingerprint contract;
   - ShellCheck tracked-inventory/severity and actionlint workflow shape.
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

## Stop conditions

- Stop if the framing repair needs to weaken byte/OOB/truncation/EOF checks.
- Stop if object pinning changes the public proof schema or lock serialization.
- Stop if reproducibility requires dropping the image-ID comparison.
- Stop if the secret-scan exception is broader than one exact fingerprint.
- After the verified, reviewed Phase 2 source PR merges, report the exact PR
  and merge commit plus deferred operational gates, then pause.

## Adversarial review request

Review this plan as a self-contained, read-only design artifact. Attack
fail-open framing, descriptor lifetime, inode reuse, flock aliasing,
cleanup/error precedence, Linux/Darwin divergence, reproducibility false
evidence, and overbroad secret-scan exemptions. Return `PROCEED` only if no
material design gap remains; otherwise return `REVISE` with concrete required
changes.
