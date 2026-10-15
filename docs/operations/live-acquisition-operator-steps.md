# Live acquisition: operator steps D5, D7, D2

These are the operator steps from the live acquisition plan
(`docs/superpowers/plans/2026-10-10-live-acquisition-plan.md`, section 2), in
the plan's order: D5, then D7, then D2. Nothing here runs automatically. Run
each step only on an explicit go.

Conventions:

- Run every target command in a root shell on the QTS target, opened from the
  operator workstation. The commands assume euid 0 and do not use `sudo`.
- `<...>` marks a value only the operator knows. No real path, host, or
  repository appears in this repository.
- Record each command's full output. The next step depends on it.

## D5. Read the fence (read-only)

Acquisition needs the portable fleet to hold the fence. The live fence state
on the target is not recorded anywhere, so it is read before the handover is
designed. Every command in this step only reads.

1. Find the fence root. It is the overlay's `paths.fence_root`. If no
   overlay is installed on the target, a legacy launcher passes it as the
   second argument to `run-legacy-fenced`.

   ```sh
   grep -E '"(fence_root|legacy_fence_binary)"' <overlay_path>
   grep -rs 'run-legacy-fenced' /etc/config/crontab <launcher_dir>
   ```

2. List the fence files. These names are fixed by the fence store:
   `fleet.lock`, `fleet.json`, and the `holders` directory.

   ```sh
   ls -la <fence_root> <fence_root>/holders
   cat <fence_root>/fleet.json
   ```

   The `.` line of the first listing shows the root's owner and mode; it
   must be owned by root with mode `drwx------`. Do not edit or remove any of
   these files.

3. When all three names exist, read the fence through `inspect`. The fleet
   and generation come only from an `inspect` that exits 0, never from the
   `cat` above, which is a diagnostic. `inspect` takes a shared lock, so it can
   run beside live guards, and it writes nothing. If no
   `portable-ghar-fleet-fence` binary is installed, build one from `main` the
   way D7 builds the controller (`./cmd/portable-ghar-fleet-fence`) and copy it
   to the staging directory; that copy is the only thing this step writes. The
   arguments must be exactly these three, in this order.

   ```sh
   <fence_binary> inspect --state-dir <fence_root> --json; echo "exit=$?"
   ```

   It prints one line,
   `{"generation":N,"active_fleet":"none|portable|legacy","holders":[...]}`.
   Exit 1 with `portable-ghar-fleet-fence: unavailable` also covers a fence
   that was never set up, because `inspect` needs all three files to exist.

4. Holder records are files and are not filtered for liveness. Check each
   holder's `pid`:

   ```sh
   tr '\0' ' ' < /proc/<holder_pid>/cmdline; echo
   ```

   A missing `/proc/<holder_pid>` means that holder's process is gone.

What the result decides. The fleet and generation in the last three rows come
only from an `inspect` that exited 0.

| Fence state                                                                           | Meaning for the canary                                                                                                                                                            |
| ------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Root absent                                                                           | No fence exists. The handover must first create the root as a root-owned mode `0700` directory. Nothing currently guards the target against a second acquirer.                    |
| Root is a root-owned mode `0700` directory, and none of the three names exist         | Never set up. The handover starts from `none` at generation 0.                                                                                                                    |
| One or two of the three names exist, or the root is not a root-owned `0700` directory | Partial or invalid state. The fence store rejects it, and the files present may belong to a live or earlier guard. Stop and report. Do not hand over, create, or remove anything. |
| All three names exist, but `inspect` exits 1                                          | Corrupt or unreadable state, such as a malformed header, a wrong mode or type, or an invalid holder record. Stop and report. Do not hand over, create, or remove anything.        |
| `legacy` at generation N                                                              | Legacy work must be suspended and its guards gone before a `legacy` to `portable` handover at expected generation N.                                                              |
| `portable` at generation N                                                            | Unexpected before any Portable deployment. Stop and report.                                                                                                                       |
| `none` at generation N, N above 0                                                     | A fence that was handed back. Record N; the handover expects it.                                                                                                                  |

The handover itself is not part of D5. It belongs to the canary runbook and
waits for its own go.

## D7. Create the scale set and token

`create-scale-set` creates the repository's runner scale set in the default
runner group, with one label equal to the scale set name and
`DisableUpdate=true`, then re-reads and verifies it. It never updates or
deletes an existing scale set. `external-probe` then opens and closes one
message session per repository. Neither command touches controller state, the
fence, or the Worker. See [GitHub scale set and probe](github-scale-set.md).

Both commands validate the whole overlay against the current schema,
including the target's OS, architecture, and euid, so they must run on the
target itself.

**Prerequisites:**

- A private overlay on the target that validates on the current `main`
  schema. It must include the `github` section and a repository entry with
  `alias`, `config_url`, `scale_set_name`, and a `credential_name` that names
  a `file` secret. The overlay file must be root-owned, mode `0600`, a regular
  file with exactly one link, at most 1 MiB, and not a symlink.
- A controller binary built from `main`. No tagged release includes these
  commands: both releases predate them.

**Build on the workstation, from a clean checkout of `main`.** The overlay
schema accepts only `amd64` targets, and the commands refuse to run unless the
binary's architecture matches the overlay. Check that `uname -m` on the target
reports `x86_64`; if it reports anything else, stop. The binary is pure Go and
needs no C toolchain.

```sh
git -C <checkout> fetch origin main
git -C <checkout> checkout --detach origin/main
cd <checkout>
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -o <workstation_out>/portable-ghar-controller \
  ./cmd/portable-ghar-controller
```

Copy it to a root-owned staging directory on the target, then on the target:

```sh
chown root:root <staging_dir>/portable-ghar-controller
chmod 0755 <staging_dir>/portable-ghar-controller
```

**Token.** Create one token for this repository only, with the shortest
expiry the canary allows. A fine-grained token needs repository
"Administration: read and write"; a classic token needs `repo`. Whether a
fine-grained token can use the scale-set API is not yet verified, so try it
first. `create-scale-set` reads the runner group and the scale set before it
creates anything, so a token without access fails at a named step.

Write the file with terminal echo off, so the token never reaches the screen,
shell history, or a recorded transcript. Paste the token and press Enter;
nothing is shown. `read` and `printf` are shell builtins, so the token never
appears in a process's argument list. Echo is restored on every exit. An
interrupt, end of input, or an empty line ends the step before the file is
created.

The step refuses to write over an existing path, including a symlink. With
`set -C` the shell also refuses to truncate a file that appears in between. To
replace a token, check the old file with `ls -l <token_path>` and remove it
with `rm -- <token_path>` first.

```sh
(
  umask 077
  set -C
  if [ -e <token_path> ] || [ -L <token_path> ]; then
    echo 'token path exists; check and remove the old file first' >&2
    exit 1
  fi
  trap 'stty echo' EXIT
  trap 'exit 1' INT TERM
  stty -echo
  IFS= read -r token || exit 1
  [ -n "$token" ] || exit 1
  printf '%s\n' "$token" > <token_path>
)
echo
ls -l <token_path>
```

The listing must show a regular file owned by root with mode `-rw-------`. The
file must be at most 4096 bytes, and may end with one newline but hold no other
whitespace.

**Create and verify.**

```sh
<staging_dir>/portable-ghar-controller create-scale-set \
  --config=<overlay_path> --alias=<repository_alias>
<staging_dir>/portable-ghar-controller create-scale-set \
  --config=<overlay_path> --alias=<repository_alias>
<staging_dir>/portable-ghar-controller external-probe --config=<overlay_path>
```

- Both runs must name the same scale set with `"single_name_label":true` and
  `"disable_update":true`.
- The first run prints `"created":true` if it made the scale set, or
  `"created":false` if a compatible one already existed and passed the same
  verification. The second run must print `"created":false`, which proves the
  command is idempotent against the real API.
- `external-probe` must list every overlay repository. It fails while a
  controller holds a session, so run it with no controller running.
- Failures print a step name, never GitHub's response text. A failure at
  `resolve runner group` or `create scale set` on the first run usually means
  the token lacks permission. Switching to a classic token widens access, so
  that is an operator decision.

## D2. Conformance cases 1-14 on the target

**Blocked until plan phase 6 merges.** The harness preflight requires a
`vcs.revision` stamp that matches the run's `source_commit`, and test binaries
carry none. Building with `-buildvcs=true` was tried and does not stamp them
either. The harness also never writes its report out. Phase 6 adds a source
commit check that works for test binaries, and a report writer. The exact D2
commands ship with phase 6.

Facts that hold either way, for planning:

- The run consumes its input file: the harness deletes it. Keep a private
  copy, mode `0400`, owned by the euid the run expects.
- The input names the runtime manifest, overlay, policy, CA, and seccomp files
  by path and digest, and a nonzero fleet generation. Every named file must be
  a regular file owned by that euid, with no group or other write access.
- The test locates the Task 11 plan through its own source path. It must
  therefore run from a checkout owned by that euid, built without
  `-trimpath`.
