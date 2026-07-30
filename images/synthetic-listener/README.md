# images/synthetic-listener

Task 11 defines a deterministic runner-role image containing the closed
synthetic listener and exactly one immutable seed. Its `build/` directory is
ignored and must be created only by:

```sh
scripts/prepare-task11-images.sh --generation <nonzero-integer>
```

The preparation transaction cross-compiles the static listener and production
runner gate, publishes the listener through the existing verified runner-tree
authority, and publishes the closed seed through the production seed-cache
path. It performs no network, Docker, or host mutation.

The deny-all context and Dockerfile require one listener payload, an empty
`externals/`, exact runner/seed locks and readiness, the pinned production gate
ABI, the distinct `portable-ghar-task11-synthetic-v1` listener protocol, and
numeric UID/GID `65532`.

This image definition is source evidence only. Linux target execution,
operator-selected sizing, and any RhoNAS change remain separate gates.
