## Summary

<!-- What does this change do, and why? -->

## Test plan

<!-- How did you verify this? List the exact commands you ran. -->

- [ ] `python3 -m unittest discover -s tests -p 'test_*.py'` passes
- [ ] Relevant new tests were written FIRST and observed to fail (TDD)

## PUBLIC-SAFETY checklist

This repository is public. Please confirm every item below before
requesting review -- a reviewer cannot always tell from a diff alone
whether a value is real or synthetic.

- [ ] This PR contains **no deployment identifiers** (account IDs, zone
      IDs, tunnel IDs, installation/client/app IDs, or any other
      environment-specific identifier).
- [ ] This PR contains **no secrets** (tokens, keys, credentials,
      passwords, or anything secret-shaped), real or expired.
- [ ] This PR contains **no real logs, real configuration, or real
      runtime state** -- only synthetic examples (see CONTRIBUTING.md for
      the placeholder conventions, e.g. `owner/repository`,
      `example-fleet`, `operator@example.invalid`).
- [ ] I ran `python3 scripts/sanitize_public.py --tracked` locally and it
      reported `sanitization passed`.
- [ ] I ran `python3 scripts/check_repository_metadata.py` locally (if
      this PR touches governance/repository metadata) and it exited 0.

## Additional context

<!-- Anything else a reviewer should know. -->
