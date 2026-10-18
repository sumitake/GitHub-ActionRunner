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

For a control environment whose TLS proxy is outside that pinned runtime CA
bundle, an optional build-only named context `debian-cache` can supply the same
snapshot's original Debian-signed `InRelease`, package indexes and `.deb` files.
The build checks all three `InRelease` hashes against the tracked
`verify-debian-cache.sh` pins before APT runs. A valid signature from a different
snapshot is insufficient.
Set `DEBIAN_SNAPSHOT_SOURCE=offline`, bind that cache read-only, and run the build
with network mode `none`. APT still authenticates the indexes with the pinned
base image's archive keys and checks the package hashes. Missing, changed or
unsigned inputs fail the build. Do not add proxy certificates, disable TLS or
archive signature checks, or generate a replacement signed repository. Acquire
the official HTTPS files through the already trusted control download route,
verify the signed index chain, and retain their exact hashes with the build.
The cache stays outside the runner context and final image; the final sources
list records the official HTTPS snapshot. Ordinary builds keep the existing
HTTPS route by default. This option does not by itself qualify a release.

The context audit uses a read-only bind mount and retains only its receipt and
verified bootstrap CA. Small files are installed before the runner payload to
avoid repeated copies of that payload in native BuildKit snapshots. Bound and
measure the whole builder and staging footprint; retained A/B native caches may
need cleanup within their exclusive builder between builds.

Applying Debian security fixes requires updating the snapshot timestamp, its
three reviewed `InRelease` hash pins, and release metadata together. Move the timestamp
(`YYYYMMDDTHHMMSSZ`, in the past) forward and let CI rebuild, scan, and
compare. A fix published today needs a time after snapshot.debian.org imported
it; the midnight snapshot may predate it. The base image digest is pinned
separately and refreshed by Dependabot. Weekly Vulnerability Watch scans the
built runner image (`trivy image`, OS packages and bundled libraries) and
fails when a HIGH/CRITICAL finding has a published fix, which is the signal to
move the date.

This image definition is source evidence only. Linux target-conformance,
approved resource sizing, and any RhoNAS activation remain separate gates.
