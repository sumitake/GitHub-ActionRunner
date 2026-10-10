package hostruntime

import "errors"

// ErrOverlayManifestConflict reports a private overlay template whose
// release-derived fields disagree with the runtime manifest it is bound to.
var ErrOverlayManifestConflict = errors.New(
	"hostruntime: private overlay conflicts with runtime manifest",
)

// BindRuntimeManifest copies every release-derived identity from a validated
// runtime manifest into a private overlay template: the manifest path and
// digest, the policy manifest digest, and the five image references. An
// image reference is the image's config digest ("sha256:<hex>"), the same
// value the manifest records, because that ID is what survives docker load.
//
// A template field that is already set must equal the derived value, so
// re-binding is idempotent and a hand-typed release identity can never
// silently differ from the release. The broker network must already equal
// the manifest's egress mode. The result is validated as a complete overlay.
func BindRuntimeManifest(
	template PrivateOverlay,
	manifest RuntimeManifest,
	manifestPath string,
) (PrivateOverlay, error) {
	if err := validateRuntimeManifest(manifest); err != nil {
		return PrivateOverlay{}, err
	}
	canonical, manifestDigest, err := MarshalRuntimeManifest(manifest)
	if err != nil || len(canonical) == 0 {
		return PrivateOverlay{}, ErrInvalidRuntimeManifest
	}
	if template.Docker.BrokerNetworkID != manifest.EgressMode {
		return PrivateOverlay{}, ErrOverlayManifestConflict
	}
	bound := template
	fields := []struct {
		target *string
		value  string
	}{
		{&bound.Manifest.Path, manifestPath},
		{&bound.Manifest.Digest, manifestDigest},
		{&bound.Policy.ManifestDigest, manifest.PolicyManifestDigest},
		{&bound.Docker.RunnerImage, manifest.RunnerImageDigest},
		{&bound.Docker.AdapterImage, manifest.AdapterImageDigest},
		{&bound.Docker.BrokerImage, manifest.BrokerImageDigest},
		{&bound.Docker.HelperImage, manifest.HelperImageDigest},
		{&bound.Docker.VerifierImage, manifest.VerifierImageDigest},
	}
	for _, field := range fields {
		if *field.target != "" && *field.target != field.value {
			return PrivateOverlay{}, ErrOverlayManifestConflict
		}
		*field.target = field.value
	}
	if err := validatePrivateOverlay(bound); err != nil {
		return PrivateOverlay{}, err
	}
	return bound, nil
}
