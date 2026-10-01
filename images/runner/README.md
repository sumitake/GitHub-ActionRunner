# images/runner

Task 5 defines the source-controlled, digest-pinned runner image. Its
`build/` directory is intentionally ignored and must be created only by:

```sh
repository="$(pwd -P)"
scripts/prepare-task6-images.sh
scripts/prepare-task5-images.sh \
  --generation <nonzero-integer> \
  --ca-bundle "$repository/images/trust/build/ca-bundle.pem"
```

Task 6 downloads and verifies the locked CA bundle. The Task 5 preparation
transaction requires that exact canonical output, validates it against the
tracked lock before and after staging, downloads and verifies the exact pinned
Actions runner, publishes an explicit verified seed cache (empty by default),
and cross-compiles the static runner gate. The deny-all `.dockerignore`
excludes the archive, transfer metadata, native verifier, source tree, and
temporary staging paths. The Dockerfile audits the effective context and
locked trust inputs, uses the audited bundle only to bootstrap HTTPS package
installation, removes it, re-verifies the installed runner/seed/lock/readiness
tuple, and smoke-tests the exact listener version before switching to numeric
UID/GID `65532`.

Debian packages come from one immutable snapshot date, set once as
`snapshot=` in the Dockerfile and used for `bookworm`, `bookworm-updates`, and
`bookworm-security`. The image installs the runner's direct dependencies by
name and runs `dist-upgrade`, so every installed package, including the base
image's, is at its version in that snapshot. `apt` verifies the
Debian-signed indexes; the release A/B rebuild proves the result is
reproducible; and the image records its full installed inventory in
`dpkg-manifest.tsv`.

Applying Debian security fixes is one change: move the snapshot date forward
and let CI rebuild, scan, and compare. The base image digest is pinned
separately and refreshed by Dependabot. Weekly Vulnerability Watch scans the
built runner image (`trivy image`, OS packages and bundled libraries) and
fails when a HIGH/CRITICAL finding has a published fix, which is the signal to
move the date.

This image definition is source evidence only. Linux target-conformance,
approved resource sizing, and any RhoNAS activation remain separate gates.
