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
SDK archive SHA512, public SDK container digest and source patch SHA256. The archive includes the upstream
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

The original A/B build authenticates the Microsoft SDK archive. The public
recipe consumes the descriptor's separate immutable Microsoft SDK container
input and checks its SDK version before compilation. It fetches the exact
upstream commit, authenticates the official archive before reusing only its
prepared externals, and carries forward the complete notices. It caps the SDK
build at four CPUs, 5.75 GiB memory, no swap and 1,024 PIDs. It mounts a fresh
build directory and optionally the existing transport CA file; it does not
mount a Docker socket or user credentials. A different output digest fails
closed and leaves the destination unpublished. CI, the vulnerability watch and both product release builds invoke this
recipe when the rebuild is selected. Before accepting an archive it runs
Listener, Worker and PluginHost with benign arguments and verifies their
expected exit behavior and actual app-local CoreCLR traces.

The runtime servicing release also requires a valid user-owned runtime
directory for named synchronization objects. The build recipe creates a
private mode-0700 directory and sets `XDG_RUNTIME_DIR`. The runner's closed
environment points it at the existing mode-0700 `/tmp` tmpfs owned by the
runner UID. This uses the current mount and memory budget. See the
[runtime maintainer's compatibility discussion](https://github.com/dotnet/runtime/issues/135726).

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

Generated SBOM checks retain complete public attribution and legal terms.
[`public-dependency-metadata.json`](public-dependency-metadata.json) records
the exact Debian package identities and Maintainer fields authenticated from
the pinned signed snapshot, plus Go legal documents authenticated against
the module ZIP checksums in `go.sum`. Rehearsal fills missing Go legal text
and replaces its placeholder local citation with the public producer URL.
The sanitizer recognizes only the registered package, version and exact field
value, or a complete hash-verified legal document, in memory. It checks the
original producer evidence under exact source-line bindings; unknown or changed
values remain scanned. Original SBOM attribution, package relationships and
private-denylist checks remain intact. This evidence is independent of the
runner asset; a replacement runner still needs its own runner license evidence.

When a patched official asset becomes available, observe its real metadata and
run the existing official candidate path and complete gates. A different
upstream asset digest automatically selects the official archive; the old
rebuild descriptor and source patch remain read-only evidence. Promoting the
replacement must refresh its license evidence and provenance, or disable the
rebuild descriptor with the minimal canonical disabled document. Disabling it
alone selects the currently pinned official asset and does not prove that
asset contains a patched runtime. Keep automatic runner updates disabled;
change live targets only through the separate approved handover procedure.
