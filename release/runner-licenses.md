# Runner licensing metadata

`runner-licenses.json` records producer declarations missing from the pinned
cataloger's runner-image SBOM. It is bound to the exact authenticated runner
asset digest. It is metadata evidence, not a vulnerability ignore list, a
license waiver, or a legal conclusion. `license_exceptions` stays unchanged.

The current records cover 135 exact package/version/purl identities:

- 47 NuGet manifests explicitly declare MIT. The runtimepack entry is the
  dependency-manifest name of the exact published runtime package identified
  by its evidence URL; its version and purl are preserved.
- Seven runner-owned project assemblies use the MIT license from the immutable
  upstream source revision. They are not assumed to be public NuGet packages.
- Minimatch's exact manifest names the MIT license URL. YamlDotNet.Signed's
  manifest and versioned upstream license text identify MIT.
- 75 older Microsoft package archives contain .NET Library terms and bundled
  notices; they are not reclassified as MIT. Apache.Arrow and
  Microsoft.AspNet.WebApi.Client also publish license files in their archives.
  Those five distinct files are retained verbatim under `runner-license-texts`.
- The two Node versions use the complete upstream LICENSE files already in the
  authenticated prepared runner. Their hashes also match the versioned Node
  source LICENSE files, including bundled third-party notices.

Every package entry cites the exact NuGet manifest, package archive or immutable
upstream source license URL and its SHA-256. Package archive licensing-file
hashes are also recorded. The six SPDX LicenseRef bundles preserve the complete
upstream text and notices in `hasExtractedLicensingInfos` and the generated
notices text. They do not invent a permissive SPDX license for unfamiliar terms.

The release path performs no new license-network resolution: it reads the
reviewed registry, the five checked-in documents and the two already authenticated
Node documents. It checks source paths, text hashes, runner digest, complete
identity coverage and conflicting declarations before writing metadata. Unknown
packages, stale inventories and conflicting or missing evidence still block.
Only `licenseDeclared` is supplemented; `licenseConcluded`, package identities
and vulnerability inputs are preserved.

When updating the runner pin, refresh these records from exact-version upstream
NuGet manifests/package archives, the runner source LICENSE and the Node LICENSE
files. Preserve the source URLs and byte hashes, inspect all non-expression
license documents, and review the resulting data diff. Do not reuse this registry
for a different asset or infer licenses from a package namespace. Use synthetic
offline fixtures for source tests. An independent replay may use retained SBOMs
and authenticated license documents without rebuilding runtime artifacts; such a
replay is not release or target admission.

The generated-output sanitizer recognizes complete upstream document bodies
only with `--verified-runner-licenses`. The registry must match its committed
Git blob, and every source document must be a regular canonical file with the
recorded byte hash. Both plain and JSON-escaped copies are projected to digest
markers for scanning the remaining metadata. Every recognized original document
is independently scanned under its exact source path, with all rules enabled.
The existing allowlist contains only exact source-path, line, rule and content
hash entries for inspected public Node licensing identifiers. Unknown or altered
text, extra metadata, secrets, unsafe files and private-denylist matches remain
blocking. Original size and archive checks precede projection. The released SBOM
and notices retain their complete original text; the scan does not rewrite them.

The registry is registered as read-only evidence in the existing protected
candidate inventory. A candidate overlay cannot rewrite its upstream attribution;
a new asset requires a reviewed registry refresh. Source and generated-output
sanitization and all vulnerability/admission gates still apply independently.
