#!/usr/bin/env bats
# SPDX-License-Identifier: MPL-2.0

setup() {
  REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd -P)"
  SCRIPT="$REPO_ROOT/scripts/release/publish-runtime-release.sh"
  WORK="$(mktemp -d)"
  WORK="$(cd "$WORK" && pwd -P)"
  BIN="$WORK/bin"
  TREE="$WORK/tree"
  STATE="$WORK/state"
  mkdir -m 700 "$BIN" "$TREE" "$STATE"

  export FAKE_STATE="$STATE"
  export FAKE_TREE="$TREE"
  export FAKE_LOG="$WORK/curl.jsonl"
  export FAKE_SETTINGS=enabled
  export FAKE_REF_MODE=product
  export FAKE_RELEASE_PAGES=normal
  export FAKE_TAG=v1.2.3
  export FAKE_TITLE="portable-ghar 1.2.3"
  export FAKE_BODY="Phase 2 runtime release: independently rebuilt, comparator validated, provenance attested, and immutable."
  export TARGET_COMMIT=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  export TAG_OBJECT=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  export EVIDENCE=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
  export PGHAR_RELEASE_TOKEN=changeme
  export PGHAR_RELEASE_SETTINGS_TOKEN=placeholder

  write_tree product
  write_fake_curl
}

teardown() {
  rm -rf "$WORK"
}

file_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

write_tree() {
  local kind=$1
  rm -rf "$TREE"
  mkdir -m 700 "$TREE" "$TREE/bin"
  printf 'portable-ghar fixture\n' >"$TREE/bin/portable-ghar"
  chmod 555 "$TREE/bin/portable-ghar"
  if [ "$kind" = product ]; then
    jq -cS -n \
      --arg commit "$TARGET_COMMIT" \
      '{
        release_kind: "product",
        version: "1.2.3",
        source: {commit: $commit}
      }' >"$TREE/runtime-release.json"
  else
    jq -cS -n \
      --arg commit "$TARGET_COMMIT" \
      --arg evidence "$EVIDENCE" \
      '{
        release_kind: "candidate",
        version: "2.336.0-runner.fixture",
        source: {commit: $commit},
        runner_release: {
          version: "v2.336.0",
          observation_evidence: $evidence
        }
      }' >"$TREE/runtime-release.json"
  fi
  chmod 444 "$TREE/runtime-release.json"
  jq -cS -n \
    --arg binary_sha "$(file_sha256 "$TREE/bin/portable-ghar")" \
    --argjson binary_size "$(wc -c <"$TREE/bin/portable-ghar")" \
    --arg runtime_sha "$(file_sha256 "$TREE/runtime-release.json")" \
    --argjson runtime_size "$(wc -c <"$TREE/runtime-release.json")" \
    '{
      schema_version: 1,
      subjects: [
        {
          path: "bin/portable-ghar",
          sha256: $binary_sha,
          size: $binary_size
        },
        {
          path: "runtime-release.json",
          sha256: $runtime_sha,
          size: $runtime_size
        }
      ]
    }' >"$TREE/provenance-subjects.json"
  chmod 444 "$TREE/provenance-subjects.json"
}

write_fake_curl() {
  cat >"$BIN/curl" <<'PY'
#!/usr/bin/env python3
import hashlib
import json
import os
import pathlib
import sys
import urllib.parse

state = pathlib.Path(os.environ["FAKE_STATE"])
tree = pathlib.Path(os.environ["FAKE_TREE"])
log_path = pathlib.Path(os.environ["FAKE_LOG"])
args = sys.argv[1:]
if not args or args[0] != "--disable" or "--max-filesize" not in args:
    raise SystemExit(96)
method = "GET"
output = None
write_out = ""
data_path = None
headers = []
url = None
i = 0
while i < len(args):
    arg = args[i]
    if arg in ("--request", "-X"):
        method = args[i + 1]
        i += 2
    elif arg in ("--output", "-o"):
        output = pathlib.Path(args[i + 1])
        i += 2
    elif arg in ("--write-out", "-w"):
        write_out = args[i + 1]
        i += 2
    elif arg in ("--header", "-H"):
        value = args[i + 1]
        if value.startswith("@"):
            headers.extend(
                pathlib.Path(value[1:]).read_text(encoding="utf-8").splitlines()
            )
        else:
            headers.append(value)
        i += 2
    elif arg == "--data-binary":
        value = args[i + 1]
        if value.startswith("@"):
            data_path = pathlib.Path(value[1:])
        i += 2
    elif arg.startswith("https://"):
        url = arg
        i += 1
    elif arg in (
        "--silent",
        "--show-error",
        "--no-progress-meter",
        "--location-trusted",
    ):
        i += 1
    elif arg in (
        "--connect-timeout",
        "--max-time",
        "--max-redirs",
        "--proto",
        "--tlsv1.2",
    ):
        i += 2 if arg != "--tlsv1.2" else 1
    else:
        i += 1

if output is None or url is None:
    raise SystemExit(97)

authorization = ""
accept = ""
for header in headers:
    lower = header.lower()
    if lower.startswith("authorization:"):
        authorization = header.split(":", 1)[1].strip()
    elif lower.startswith("accept:"):
        accept = header.split(":", 1)[1].strip()

data = b""
if data_path is not None:
    data = data_path.read_bytes()

with log_path.open("a", encoding="utf-8") as handle:
    handle.write(
        json.dumps(
            {
                "accept": accept,
                "authorization": authorization,
                "data_sha256": hashlib.sha256(data).hexdigest() if data else "",
                "method": method,
                "url": url,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )


def load_assets():
    path = state / "assets.json"
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def save_assets(rows):
    (state / "assets.json").write_text(
        json.dumps(rows, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def mark_moved(boundary):
    if os.environ.get("FAKE_MOVE_REF_AFTER_MUTATION") == boundary:
        (state / "moved-ref").write_text(boundary + "\n", encoding="utf-8")


def release_object():
    release_state = (state / "release").read_text(encoding="utf-8").strip()
    return {
        "id": 42,
        "tag_name": os.environ["FAKE_TAG"],
        "target_commitish": os.environ.get("FAKE_TARGET_COMMITISH", "main"),
        "name": os.environ["FAKE_TITLE"],
        "body": os.environ["FAKE_BODY"],
        "draft": release_state == "draft",
        "prerelease": False,
        "immutable": release_state == "published"
        and os.environ.get("FAKE_MUTABLE_PUBLISHED", "0") != "1",
    }


def unrelated(page, count=100):
    return [
        {
            "id": page * 1000 + index + 1,
            "tag_name": f"unrelated-{page}-{index}",
        }
        for index in range(count)
    ]


parsed = urllib.parse.urlsplit(url)
path = parsed.path
query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
status = 500
body = b""
redirect = ""

is_settings = path.endswith("/immutable-releases")
is_public_asset = parsed.hostname == "release-assets.githubusercontent.com"
if is_settings:
    if authorization != "Bearer placeholder" or method != "GET":
        status = 403
        body = b'{"message":"forbidden"}'
    elif os.environ["FAKE_SETTINGS"] == "enabled":
        status = 200
        body = b'{"enabled":true,"enforced_by_owner":false}'
    elif os.environ["FAKE_SETTINGS"] == "disabled":
        status = 200
        body = b'{"enabled":false,"enforced_by_owner":false}'
    elif os.environ["FAKE_SETTINGS"] == "malformed":
        status = 200
        body = b'{"enabled":true,"enabled":false}'
    else:
        status = 404
        body = b'{"message":"not found"}'
elif is_public_asset:
    if authorization:
        status = 403
    else:
        asset_id = int(path.rsplit("/", 1)[1])
        row = next(item for item in load_assets() if item["id"] == asset_id)
        body = (state / row["file"]).read_bytes()
        status = 200
elif authorization != "Bearer changeme":
    status = 403
    body = b'{"message":"forbidden"}'
elif "/git/ref/tags/" in path and method == "GET":
    if os.environ["FAKE_REF_MODE"] == "candidate-absent" and not (
        state / "candidate-ref"
    ).exists():
        status = 404
        body = b'{"message":"not found"}'
    else:
        ref_type = "tag" if os.environ["FAKE_REF_MODE"] == "product" else "commit"
        if (state / "moved-ref").exists():
            ref_sha = "dddddddddddddddddddddddddddddddddddddddd"
        else:
            ref_sha = (
                os.environ.get("FAKE_PRODUCT_TAG_OBJECT", os.environ["TAG_OBJECT"])
                if ref_type == "tag"
                else os.environ.get("FAKE_REF_SHA", os.environ["TARGET_COMMIT"])
            )
        body = json.dumps(
            {
                "ref": f"refs/tags/{os.environ['FAKE_TAG']}",
                "object": {"type": ref_type, "sha": ref_sha},
            }
        ).encode()
        status = 200
elif "/git/tags/" in path and method == "GET":
    body = json.dumps(
        {
            "tag": os.environ["FAKE_TAG"],
            "object": {"type": "commit", "sha": os.environ["TARGET_COMMIT"]},
            "verification": {"verified": True},
        }
    ).encode()
    status = 200
elif path.endswith("/git/refs") and method == "POST":
    if os.environ.get("FAKE_REF_CREATE_CONFLICT", "0") == "1":
        status = 422
        body = b'{"message":"exists"}'
    else:
        (state / "candidate-ref").write_text("created\n", encoding="utf-8")
        mark_moved("ref-create")
        body = json.dumps(
            {
                "ref": f"refs/tags/{os.environ['FAKE_TAG']}",
                "object": {
                    "type": "commit",
                    "sha": os.environ["TARGET_COMMIT"],
                },
            }
        ).encode()
        status = 201
elif path.endswith("/releases") and method == "GET":
    page = int(query.get("page", ["1"])[0])
    mode = os.environ["FAKE_RELEASE_PAGES"]
    target = release_object() if (state / "release").exists() else None
    if mode == "full":
        rows = unrelated(page)
    elif mode == "target-page-2":
        rows = unrelated(1) if page == 1 else ([target] if page == 2 and target else [])
    elif mode == "duplicate-target":
        if page == 1:
            rows = ([target] if target else []) + unrelated(1, 99)
        elif page == 2:
            rows = [target] if target else []
        else:
            rows = []
    else:
        rows = [target] if page == 1 and target else []
    body = json.dumps(rows).encode()
    status = 200
elif path.endswith("/releases") and method == "POST":
    if os.environ.get("FAKE_RELEASE_CREATE_CONFLICT", "0") == "1":
        status = 422
        body = b'{"message":"exists"}'
    else:
        request = json.loads(data.decode())
        (state / "release").write_text("draft\n", encoding="utf-8")
        mark_moved("release-create")
        body = json.dumps(
            {
                **request,
                "id": 42,
                "immutable": False,
            }
        ).encode()
        status = 201
elif path.endswith("/releases/42/assets") and method == "GET":
    rows = []
    for row in load_assets():
        item = {
            "id": row["id"],
            "name": row["name"],
            "state": row["state"],
            "size": 0,
            "digest": None,
        }
        if row["state"] == "uploaded":
            raw = (state / row["file"]).read_bytes()
            item["size"] = len(raw)
            item["digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()
        rows.append(item)
    body = json.dumps(rows).encode()
    status = 200
elif "/releases/assets/" in path and method == "GET":
    asset_id = int(path.rsplit("/", 1)[1])
    row = next(item for item in load_assets() if item["id"] == asset_id)
    raw = (state / row["file"]).read_bytes()
    if os.environ.get("FAKE_ASSET_MISMATCH", "0") == "1":
        raw += b"x"
    if os.environ.get("FAKE_ASSET_REDIRECT", "0") == "1":
        status = 302
        host = os.environ.get(
            "FAKE_ASSET_REDIRECT_HOST", "release-assets.githubusercontent.com"
        )
        redirect = f"https://{host}/download/{asset_id}?signature=test"
    else:
        status = 200
        body = raw
elif "/releases/assets/" in path and method == "DELETE":
    asset_id = int(path.rsplit("/", 1)[1])
    rows = [row for row in load_assets() if row["id"] != asset_id]
    save_assets(rows)
    mark_moved("asset-delete")
    status = 204
elif parsed.hostname == "uploads.github.com" and method == "POST":
    name = query["name"][0]
    rows = load_assets()
    asset_id = 100 + len(rows)
    filename = f"asset-{asset_id}.bin"
    (state / filename).write_bytes(data)
    rows.append(
        {
            "id": asset_id,
            "name": name,
            "state": "uploaded",
            "file": filename,
        }
    )
    save_assets(rows)
    mark_moved("asset-upload")
    body = json.dumps(
        {
            "id": asset_id,
            "name": name,
            "state": "uploaded",
            "size": len(data),
            "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
        }
    ).encode()
    status = 201
elif path.endswith("/releases/42") and method == "PATCH":
    (state / "release").write_text("published\n", encoding="utf-8")
    mark_moved("publish")
    body = json.dumps(release_object()).encode()
    status = 200
else:
    status = 404
    body = b'{"message":"unhandled"}'

output.write_bytes(body)
rendered = write_out.replace("%{http_code}", str(status)).replace(
    "%{redirect_url}", redirect
)
sys.stdout.write(rendered)
PY
  chmod 755 "$BIN/curl"
}

seed_release() {
  local state=$1
  printf '%s\n' "$state" >"$STATE/release"
}

seed_uploaded_assets() {
  python3 - "$TREE" "$STATE" <<'PY'
import hashlib
import json
import pathlib
import sys

tree = pathlib.Path(sys.argv[1])
state = pathlib.Path(sys.argv[2])
manifest = json.loads((tree / "provenance-subjects.json").read_text())
paths = [row["path"] for row in manifest["subjects"]] + ["provenance-subjects.json"]
rows = []
for index, relative in enumerate(paths, start=100):
    raw = (tree / relative).read_bytes()
    filename = f"asset-{index}.bin"
    (state / filename).write_bytes(raw)
    rows.append(
        {
            "id": index,
            "name": pathlib.PurePosixPath(relative).name,
            "state": "uploaded",
            "file": filename,
        }
    )
(state / "assets.json").write_text(json.dumps(rows, separators=(",", ":")) + "\n")
PY
}

seed_residue() {
  local residue_state=$1
  local name=${2:-portable-ghar}
  jq -cS -n \
    --arg state "$residue_state" \
    --arg name "$name" \
    '[{id: 100, name: $name, state: $state, file: "unused"}]' \
    >"$STATE/assets.json"
}

run_product() {
  run env PATH="$BIN:$PATH" "$SCRIPT" \
    --release-kind product \
    --repository sumitake/Portable-GHAR \
    --tag "$FAKE_TAG" \
    --target-commit "$TARGET_COMMIT" \
    --product-tag-object "$TAG_OBJECT" \
    --tree "$TREE"
}

run_candidate() {
  export FAKE_REF_MODE=${FAKE_REF_MODE:-candidate-absent}
  export FAKE_TAG="runner-candidate-v2.336.0-$EVIDENCE-$TARGET_COMMIT"
  export FAKE_TITLE="portable-ghar runner candidate v2.336.0"
  export FAKE_BODY="Qualified immutable runner candidate v2.336.0 bound to observation $EVIDENCE."
  write_tree candidate
  run env PATH="$BIN:$PATH" "$SCRIPT" \
    --release-kind candidate \
    --repository sumitake/Portable-GHAR \
    --tag "$FAKE_TAG" \
    --target-commit "$TARGET_COMMIT" \
    --tree "$TREE"
}

mutation_count() {
  jq -s '[.[] | select(.method != "GET")] | length' "$FAKE_LOG"
}

@test "publisher exists and is executable" {
  [ -x "$SCRIPT" ]
}

@test "fresh product creates one resumable draft uploads exact assets and publishes immutable" {
  run_product
  [ "$status" -eq 0 ]
  [ "$output" = "" ]
  [ "$(cat "$STATE/release")" = "published" ]
  [ "$(jq 'length' "$STATE/assets.json")" -eq 3 ]
  [ "$(jq -s '[.[] | select(.method == "POST" and (.url | endswith("/releases")))] | length' "$FAKE_LOG")" -eq 1 ]
  [ "$(jq -s '[.[] | select(.method == "PATCH")] | length' "$FAKE_LOG")" -eq 1 ]
  [ "$(jq -s '[.[] | select(.url | endswith("/immutable-releases")) | .authorization] | unique == ["Bearer placeholder"]' "$FAKE_LOG")" = true ]
  [ "$(jq -s '[.[] | select((.url | endswith("/immutable-releases")) | not) | .authorization] | map(select(length > 0)) | unique == ["Bearer changeme"]' "$FAKE_LOG")" = true ]
}

@test "published immutable release is byte-verified and causes no mutation" {
  seed_release published
  seed_uploaded_assets
  run_product
  [ "$status" -eq 0 ]
  [ "$(mutation_count)" -eq 0 ]
}

@test "release target commitish is advisory while the exact product tag ref is mandatory" {
  export FAKE_TARGET_COMMITISH=main
  run_product
  [ "$status" -eq 0 ]

  rm -f "$STATE"/release "$STATE"/assets.json "$STATE"/asset-*.bin
  : >"$FAKE_LOG"
  export FAKE_PRODUCT_TAG_OBJECT=dddddddddddddddddddddddddddddddddddddddd
  run_product
  [ "$status" -ne 0 ]
  [ "$(mutation_count)" -eq 0 ]
}

@test "exact product tag proofs immediately bracket every remote mutation" {
  run_product
  [ "$status" -eq 0 ]
  python3 - "$FAKE_LOG" <<'PY'
import json
import pathlib
import sys

rows = [
    json.loads(line)
    for line in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
]
mutations = [
    index
    for index, row in enumerate(rows)
    if row["method"] != "GET"
]
assert mutations
for index in mutations:
    assert index >= 2
    assert "/git/ref/tags/" in rows[index - 2]["url"]
    assert "/git/tags/" in rows[index - 1]["url"]
    assert index + 1 < len(rows)
    assert "/git/ref/tags/" in rows[index + 1]["url"]
PY
}

@test "moved product tag after every release mutation is terminal" {
  for boundary in release-create asset-upload publish; do
    rm -f "$STATE"/release "$STATE"/assets.json "$STATE"/asset-*.bin \
      "$STATE"/moved-ref
    : >"$FAKE_LOG"
    export FAKE_MOVE_REF_AFTER_MUTATION=$boundary
    run_product
    [ "$status" -ne 0 ]
    [ -f "$STATE/moved-ref" ]
  done

  rm -f "$STATE"/release "$STATE"/assets.json "$STATE"/asset-*.bin \
    "$STATE"/moved-ref
  : >"$FAKE_LOG"
  seed_release draft
  seed_residue starter portable-ghar
  export FAKE_MOVE_REF_AFTER_MUTATION=asset-delete
  run_product
  [ "$status" -ne 0 ]
  [ -f "$STATE/moved-ref" ]
  [ "$(jq -s '[.[] | select(.method == "DELETE")] | length' "$FAKE_LOG")" -eq 1 ]
  [ "$(jq -s '[.[] | select(.method == "PATCH")] | length' "$FAKE_LOG")" -eq 0 ]
}

@test "existing partial draft resumes without a second create" {
  seed_release draft
  seed_uploaded_assets
  python3 - "$STATE/assets.json" <<'PY'
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
rows = json.loads(path.read_text())
path.write_text(json.dumps(rows[:1], separators=(",", ":")) + "\n")
PY
  run_product
  [ "$status" -eq 0 ]
  [ "$(jq -s '[.[] | select(.method == "POST" and (.url | endswith("/releases")))] | length' "$FAKE_LOG")" -eq 0 ]
  [ "$(jq 'length' "$STATE/assets.json")" -eq 3 ]
}

@test "create conflict followed by zero match is terminal with no second create" {
  export FAKE_RELEASE_CREATE_CONFLICT=1
  run_product
  [ "$status" -ne 0 ]
  [ "$(jq -s '[.[] | select(.method == "POST" and (.url | endswith("/releases")))] | length' "$FAKE_LOG")" -eq 1 ]
  [ "$(jq -s '[.[] | select(.method == "PATCH" or .method == "DELETE")] | length' "$FAKE_LOG")" -eq 0 ]
}

@test "candidate creates one exact lightweight ref and includes the source commit in its tag" {
  export FAKE_REF_MODE=candidate-absent
  run_candidate
  [ "$status" -eq 0 ]
  [ -f "$STATE/candidate-ref" ]
  [ "$(jq -s '[.[] | select(.method == "POST" and (.url | endswith("/git/refs")))] | length' "$FAKE_LOG")" -eq 1 ]
  [[ "$FAKE_TAG" =~ -"$TARGET_COMMIT"$ ]]
}

@test "candidate wrong existing commit and unresolved create conflict are terminal" {
  export FAKE_REF_MODE=candidate-present
  export FAKE_REF_SHA=dddddddddddddddddddddddddddddddddddddddd
  run_candidate
  [ "$status" -ne 0 ]
  [ "$(mutation_count)" -eq 0 ]

  : >"$FAKE_LOG"
  export FAKE_REF_MODE=candidate-absent
  export FAKE_REF_CREATE_CONFLICT=1
  run_candidate
  [ "$status" -ne 0 ]
  [ "$(jq -s '[.[] | select(.method == "POST" and (.url | endswith("/git/refs")))] | length' "$FAKE_LOG")" -eq 1 ]
  [ "$(jq -s '[.[] | select(.method == "POST" and (.url | endswith("/releases")))] | length' "$FAKE_LOG")" -eq 0 ]
}

@test "moved candidate ref after creation or publication mutation is terminal" {
  for boundary in ref-create release-create asset-upload publish; do
    rm -f "$STATE"/release "$STATE"/assets.json "$STATE"/asset-*.bin \
      "$STATE"/candidate-ref "$STATE"/moved-ref
    : >"$FAKE_LOG"
    export FAKE_REF_MODE=candidate-absent
    export FAKE_MOVE_REF_AFTER_MUTATION=$boundary
    run_candidate
    [ "$status" -ne 0 ]
    [ -f "$STATE/moved-ref" ]
  done
}

@test "missing blank or equal credentials fail before any remote call" {
  run env PATH="$BIN:$PATH" PGHAR_RELEASE_TOKEN="" PGHAR_RELEASE_SETTINGS_TOKEN=placeholder \
    "$SCRIPT" --release-kind product --repository sumitake/Portable-GHAR \
    --tag "$FAKE_TAG" --target-commit "$TARGET_COMMIT" \
    --product-tag-object "$TAG_OBJECT" --tree "$TREE"
  [ "$status" -ne 0 ]
  [ ! -e "$FAKE_LOG" ]

  run env PATH="$BIN:$PATH" PGHAR_RELEASE_TOKEN=changeme PGHAR_RELEASE_SETTINGS_TOKEN=changeme \
    "$SCRIPT" --release-kind product --repository sumitake/Portable-GHAR \
    --tag "$FAKE_TAG" --target-commit "$TARGET_COMMIT" \
    --product-tag-object "$TAG_OBJECT" --tree "$TREE"
  [ "$status" -ne 0 ]
  [ ! -e "$FAKE_LOG" ]
}

@test "disabled missing and ambiguous immutable settings fail before mutation" {
  for setting in disabled missing malformed; do
    : >"$FAKE_LOG"
    export FAKE_SETTINGS=$setting
    run_product
    [ "$status" -ne 0 ]
    [ "$(mutation_count)" -eq 0 ]
  done
}

@test "release scan finds a second-page published target and still byte-verifies" {
  seed_release published
  seed_uploaded_assets
  export FAKE_RELEASE_PAGES=target-page-2
  run_product
  [ "$status" -eq 0 ]
  [ "$(jq -s '[.[] | select(.method == "GET" and (.url | contains("/releases?per_page=100&page=2")))] | length > 0' "$FAKE_LOG")" = true ]
  [ "$(mutation_count)" -eq 0 ]
}

@test "release scan continues after first target and rejects a later duplicate" {
  seed_release published
  seed_uploaded_assets
  export FAKE_RELEASE_PAGES=duplicate-target
  run_product
  [ "$status" -ne 0 ]
  [ "$(mutation_count)" -eq 0 ]
}

@test "release scan fails closed at the source-constant full-page ceiling" {
  export FAKE_RELEASE_PAGES=full
  run_product
  [ "$status" -ne 0 ]
  [ "$(jq -s '[.[] | select(.method == "GET" and (.url | contains("/releases?per_page=100&page=")))] | length' "$FAKE_LOG")" -eq 100 ]
  [ "$(mutation_count)" -eq 0 ]
}

@test "one expected starter residue is deleted but open and unknown states are terminal" {
  seed_release draft
  seed_residue starter portable-ghar
  run_product
  [ "$status" -eq 0 ]
  [ "$(jq -s '[.[] | select(.method == "DELETE")] | length' "$FAKE_LOG")" -eq 1 ]

  for state in open mystery; do
    rm -f "$STATE"/release "$STATE"/assets.json "$STATE"/asset-*.bin
    : >"$FAKE_LOG"
    seed_release draft
    seed_residue "$state" portable-ghar
    run_product
    [ "$status" -ne 0 ]
    [ "$(jq -s '[.[] | select(.method == "DELETE")] | length' "$FAKE_LOG")" -eq 0 ]
  done
}

@test "asset bytes are mandatory and only the closed unauthenticated redirect is followed" {
  seed_release published
  seed_uploaded_assets
  export FAKE_ASSET_MISMATCH=1
  run_product
  [ "$status" -ne 0 ]
  [ "$(mutation_count)" -eq 0 ]

  : >"$FAKE_LOG"
  export FAKE_ASSET_MISMATCH=0
  export FAKE_ASSET_REDIRECT=1
  run_product
  [ "$status" -eq 0 ]
  [ "$(jq -s '[.[] | select(.url | startswith("https://release-assets.githubusercontent.com/")) | .authorization] | unique == [""]' "$FAKE_LOG")" = true ]

  : >"$FAKE_LOG"
  export FAKE_ASSET_REDIRECT_HOST=example.invalid
  run_product
  [ "$status" -ne 0 ]
}

@test "asset byte verification streams through a bounded private file" {
  grep -F 'def download_asset(' "$SCRIPT"
  grep -F 'file_digest(download)' "$SCRIPT"
  grep -F 'size != expected_size' "$SCRIPT"
  grep -F 'download.unlink()' "$SCRIPT"
  ! sed -n '/def download_asset(/,/^$/p' "$SCRIPT" | grep -F 'return body'
  ! sed -n '/def verify_asset_bytes(/,/^$/p' "$SCRIPT" | grep -F 'hashlib.sha256(raw)'
}

@test "mutable postpublish response is irreversible terminal and never retried" {
  export FAKE_MUTABLE_PUBLISHED=1
  run_product
  [ "$status" -ne 0 ]
  [ "$(jq -s '[.[] | select(.method == "PATCH")] | length' "$FAKE_LOG")" -eq 1 ]
  [ "$(jq -s '[.[] | select(.method == "DELETE")] | length' "$FAKE_LOG")" -eq 0 ]
}

@test "malformed arguments and unsafe provenance fail before network" {
  run env PATH="$BIN:$PATH" "$SCRIPT" --release-kind product
  [ "$status" -ne 0 ]
  [ ! -e "$FAKE_LOG" ]

  chmod 644 "$TREE/provenance-subjects.json"
  printf '{"schema_version":1,"subjects":[],"subjects":[]}\n' \
    >"$TREE/provenance-subjects.json"
  run_product
  [ "$status" -ne 0 ]
  [ ! -e "$FAKE_LOG" ]
}
