#!/usr/bin/env bats
# SPDX-License-Identifier: MPL-2.0

setup() {
  REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
  SCRIPT="$REPO_ROOT/scripts/prepare-task11-images.sh"
  WORK="$(mktemp -d)"
}

teardown() {
  rm -rf "$WORK"
}

@test "prepare-task11-images.sh exists, is executable, and parses as POSIX shell" {
  [ -x "$SCRIPT" ]
  run sh -n "$SCRIPT"
  [ "$status" -eq 0 ]
}

@test "invalid generation fails before creating a transaction" {
  run "$SCRIPT" --generation 0
  [ "$status" -ne 0 ]
  [[ "$output" == *"prepare-task11-images: unavailable"* ]]

  run "$SCRIPT" --generation 1 --generation 2
  [ "$status" -ne 0 ]
  [[ "$output" == *"prepare-task11-images: unavailable"* ]]
}

@test "preparation compiles and stages only the closed Task 11 artifacts" {
  grep -F 'CGO_ENABLED=0 GOOS=linux GOARCH=amd64' "$SCRIPT"
  grep -F './cmd/portable-ghar-task11-listener' "$SCRIPT"
  grep -F './cmd/portable-ghar-runner-gate' "$SCRIPT"
  grep -F 'stage-synthetic-listener' "$SCRIPT"
  grep -F 'stage-seeds' "$SCRIPT"
  grep -F 'cp -Rp "$runtime_output/runner" "$stage/runner"' "$SCRIPT"
  grep -F 'cp -Rp "$seed_output/seed-cache" "$stage/seed-cache"' "$SCRIPT"
  grep -F 'portable-ghar-task11-immutable-seed-v1' "$SCRIPT"
  grep -F 'ef368121857519d3895e11481813b99d2e1d76d0555074a79d6af3ce9039e636' "$SCRIPT"
  ! grep -E '(^|[[:space:]])(curl|wget|docker)([[:space:]]|$)' "$SCRIPT"
}

@test "synthetic listener context is deny-all and proves role-specific versions" {
  context="$REPO_ROOT/images/synthetic-listener"
  [ "$(sed -n '1p' "$context/.dockerignore")" = '**' ]
  grep -F 'COPY . /context' "$context/Dockerfile"
  grep -F '*) exit 1 ;;' "$context/Dockerfile"
  grep -F 'portable-ghar-task11-synthetic-v1' "$context/Dockerfile"
  grep -F 'test "$installed_version" != "$expected_version"' "$context/Dockerfile"
  grep -F 'build/runner/**' "$context/.dockerignore"
  grep -F '!build/portable-ghar-runner-gate' "$context/.dockerignore"
}

@test "image manifest and workflows include Task 11 before image builds" {
  run jq -r '.images[].name' "$REPO_ROOT/images/manifest.json"
  [ "$status" -eq 0 ]
  [ "$output" = $'network-adapter\nnetwork-broker-dialer\nnetwork-broker-parser\nnetwork-helper\nnetwork-verifier\nrunner\nsynthetic-listener' ]

  for workflow in ci.yml release.yml; do
    task11_line="$(
      grep -nF 'scripts/prepare-task11-images.sh' \
        "$REPO_ROOT/.github/workflows/$workflow" |
        cut -d: -f1
    )"
    image_line="$(
      grep -nF 'scripts/ci/check-images.sh' \
        "$REPO_ROOT/.github/workflows/$workflow" |
        cut -d: -f1
    )"
    [ -n "$task11_line" ]
    [ -n "$image_line" ]
    [ "$task11_line" -lt "$image_line" ]
  done
}
