# Serviced app-local runner runtime

The pinned upstream runner has a separately authenticated Linux x64 rebuild
with .NET SDK 8.0.426 and app-local runtime 8.0.32. Its C# application code
comes from the upstream commit in
[`runner_rebuild.json`](../internal/buildinfo/runner_rebuild.json).
The exact source patch is [`runner-rebuild.patch`](runner-rebuild.patch):
two SDK selectors change, and the Pkcs and Asn1 package references move to
10.0.13. Their Microsoft.Bcl.Cryptography dependency also resolves to 10.0.13.

The descriptor retains the official release identity and digest separately
from the rebuilt archive name, size and digest. It also binds the Microsoft
SDK archive SHA512 and source patch SHA256. The archive includes the upstream
MIT license, runtime notices and package attribution. GitHub supports its
own distributed runner packages for production; this private rebuild retains
that support limitation and must pass the complete qualification gates.

Use `portable-ghar-runtime-lock runner-payload-spec` to inspect the selected
payload. `pins` continues to describe the official upstream release.
`runner-download-spec` fails closed while the rebuild is selected. Supply the
archive explicitly to `scripts/prepare-task5-images.sh --runner-archive`, or
append `--runner-archive "$REBUILT_ARCHIVE"` to the release rehearsal command.
The archive must have the descriptor's exact basename, size and SHA256; aliases
and changed bytes are refused. Rehearsal compares its selection with the
compiled Go consumer before extraction.

A clean Linux x64 checkout can reproduce the archive using Docker, Go, Git,
Python 3.11 or later, and curl:

```sh
mkdir -m 700 "$RUNNER_TEMP/rebuilt-runner"
python3 scripts/release/rebuild-runner.py --output-directory "$RUNNER_TEMP/rebuilt-runner"
```

The recipe pins the Microsoft SDK container by digest, fetches the exact
upstream commit, authenticates the official archive before reusing only its
prepared externals, and carries forward the complete notices. It caps the SDK
build at four CPUs, 5.75 GiB memory, no swap and 1,024 PIDs. It mounts a fresh
build directory and optionally the existing transport CA file; it does not
mount a Docker socket or user credentials. A different output digest fails
closed and leaves the destination unpublished. CI and both product release
builds invoke this recipe when the rebuild is selected.

The archive uses the existing extractor's canonical USTAR format: one `./`
root entry, `./` relative path prefixes and no PAX metadata. Header corrections
must preserve and recheck every payload file against both independent build
manifests; the extractor's acceptance rules remain unchanged.

Both independent builds must produce identical archives. Their qualification
records must cover all three entrypoints, the actual runtime/package bytes,
upstream tests, fresh SBOMs, complete notices, and the existing vulnerability,
secret and public-sanitization gates. No finding suppression is introduced.
A successful payload check alone does not qualify the complete release images
or authorize a target handover. Runner configuration still requires
`DisableUpdate=true`.

When a patched official asset becomes available, observe its real metadata and
run the existing official candidate path and complete gates. A different
upstream asset digest automatically selects the official archive; the old
rebuild descriptor and source patch remain read-only evidence. Promoting the
replacement must refresh its license evidence and provenance, or disable the
rebuild descriptor with the minimal canonical disabled document. Disabling it
alone selects the currently pinned official asset and does not prove that
asset contains a patched runtime. Keep automatic runner updates disabled;
change live targets only through the separate approved handover procedure.
