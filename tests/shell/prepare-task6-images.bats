#!/usr/bin/env bats
# SPDX-License-Identifier: MPL-2.0

setup() {
  REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
  SCRIPT="$REPO_ROOT/scripts/prepare-task6-images.sh"
}

@test "prepare-task6-images.sh exists, is executable, and parses as POSIX shell" {
  [ -x "$SCRIPT" ]
  run sh -n "$SCRIPT"
  [ "$status" -eq 0 ]
}

@test "the CA lock and SBOM bind the reviewed immutable curl revision" {
  lock="$REPO_ROOT/images/trust/ca-bundle.lock.json"
  sbom="$REPO_ROOT/images/trust/ca-bundle.spdx.json"
  run jq -er '
    .schema_version == 1 and
    .source_url == "https://curl.se/ca/cacert-2026-07-16.pem" and
    .source_revision == "2026-07-16" and
    .sha256 == "3ff344e30b9b1ed2971044eabb438a08f2e2245ddb5f8ab1a3ad8b63ab4eaf91" and
    .license_spdx == "MPL-2.0" and
    .copied_path == "/etc/ssl/certs/ca-bundle.crt"
  ' "$lock"
  [ "$status" -eq 0 ]
  run jq -er '
    .spdxVersion == "SPDX-2.3" and
    .packages[0].checksums[0].checksumValue ==
      "3ff344e30b9b1ed2971044eabb438a08f2e2245ddb5f8ab1a3ad8b63ab4eaf91"
  ' "$sbom"
  [ "$status" -eq 0 ]
}

@test "legacy dependency locks contain immutable package archives and licenses" {
  lock="$REPO_ROOT/images/network-helper/legacy/packages.lock.json"
  sbom="$REPO_ROOT/images/network-helper/legacy/packages.spdx.json"
  run jq -er '
    .schema_version == 1 and
    .architecture == "amd64" and
    (.packages | length) == 8 and
    all(.packages[];
      (.name | type) == "string" and
      (.version | type) == "string" and
      (.source_url | startswith("https://snapshot.debian.org/archive/debian/20250101T000000Z/")) and
      (.sha256 | test("^[0-9a-f]{64}$")) and
      (.license_spdx | type) == "string")
  ' "$lock"
  [ "$status" -eq 0 ]
  run jq -er '
    .spdxVersion == "SPDX-2.3" and
    (.packages | length) == 8
  ' "$sbom"
  [ "$status" -eq 0 ]
}

@test "all four Task 6 contexts are deny-all scratch images" {
  for image in \
    network-helper \
    network-verifier \
    network-broker-parser \
    network-broker-dialer
  do
    [ "$(sed -n '1p' "$REPO_ROOT/images/$image/.dockerignore")" = '**' ]
    grep -F 'COPY . /context' "$REPO_ROOT/images/$image/Dockerfile"
    grep -F 'FROM scratch' "$REPO_ROOT/images/$image/Dockerfile"
    grep -F '*) exit 1 ;;' "$REPO_ROOT/images/$image/Dockerfile"
  done
  grep -F '!build/rootfs/**' "$REPO_ROOT/images/network-helper/.dockerignore"
  grep -F '!build/ca-bundle.pem' "$REPO_ROOT/images/network-verifier/.dockerignore"
  grep -F '!build/portable-ghar-network-broker-parser' \
    "$REPO_ROOT/images/network-broker-dialer/.dockerignore"
}

@test "preparation is lock-driven and cross-compiles only the closed binaries" {
  grep -F 'images/trust/ca-bundle.lock.json' "$SCRIPT"
  grep -F 'images/network-helper/legacy/packages.lock.json' "$SCRIPT"
  grep -F 'CGO_ENABLED=0 GOOS=linux GOARCH=amd64' "$SCRIPT"
  for command in \
    portable-ghar-network-helper \
    portable-ghar-network-verifier \
    portable-ghar-network-broker-parser \
    portable-ghar-network-broker-dialer
  do
    grep -F "./cmd/$command" "$SCRIPT"
  done
  grep -F 'data.tar.xz' "$SCRIPT"
  grep -F 'usr/lib/x86_64-linux-gnu/xtables' "$SCRIPT"
  grep -F 'legacy.layout' "$REPO_ROOT/scripts/_prepare_task6_context.py"
  grep -F 'legacy.sha256' "$REPO_ROOT/scripts/_prepare_task6_context.py"
}

@test "the image manifest registers all Task 5 and Task 6 contexts once" {
  run jq -r '.images[].name' "$REPO_ROOT/images/manifest.json"
  [ "$status" -eq 0 ]
  [ "$output" = $'network-adapter\nnetwork-broker-dialer\nnetwork-broker-parser\nnetwork-helper\nnetwork-verifier\nrunner' ]
}

@test "CI and release prepare Task 6 contexts before building the image manifest" {
  for workflow in ci.yml release.yml; do
    task6_line="$(
      grep -nF 'scripts/prepare-task6-images.sh' \
        "$REPO_ROOT/.github/workflows/$workflow" |
        cut -d: -f1
    )"
    image_line="$(
      grep -nF 'scripts/ci/check-images.sh' \
        "$REPO_ROOT/.github/workflows/$workflow" |
        cut -d: -f1
    )"
    [ -n "$task6_line" ]
    [ -n "$image_line" ]
    [ "$task6_line" -lt "$image_line" ]
  done
}
