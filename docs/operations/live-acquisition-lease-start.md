# Waiting for the first Worker lease

Changing acquisition policy invalidates the cached Worker lease before reopening
the controller's epoch gate. The next authenticated heartbeat installs a lease
for the new policy. A positive-capacity poll can reach the cache between those
two events; that interval is normal and must not end the canary process.

The controller skips only that pre-effect poll when the non-poisoned cache is
empty. It makes no GitHub poll, acquisition, JIT request, or acquisition/receipt write, and
leaves the selected policy unchanged. The existing poll cadence tries again
later, after the existing heartbeat can supply authority. There is no delay
constant, background service, authority table, or fallback permit.

The distinction is deliberately narrow:

- A missing cache/clock, poisoned cache, expired lease, or mismatched authority
  still fails closed.
- An already-issued permit cannot turn a failed revalidation into a wait.
- Failed host/operation guard cleanup remains fatal.
- An authority failure after a GitHub poll, including before an acquire call,
  retains the existing disable/fail-stop behavior. No upstream operation is
  retried or replayed by the wait rule.
- A zero-capacity observer poll follows its existing path, so running-job
  completion and cleanup do not depend on a new acquisition lease.

For the operator, the order stays Worker start, `canary-only`, one dispatch,
then `disabled` after that job. No extra sleep is needed between start and the
local transition. The Worker's signed receipt and existing exact policy, fence,
generation, and permit checks remain prerequisites for any positive poll.

This is source behavior only. Worker deployment and the real canary remain
operator steps, and this document runs neither.
