package cli

import "github.com/sumitake/portable-ghar/internal/hostruntime"

const privateOverlayValidationSchemaVersion = uint32(1)

type PrivateOverlayValidationReceipt struct {
	SchemaVersion               uint32 `json:"schema_version"`
	PrivateOverlaySchemaVersion uint32 `json:"private_overlay_schema_version"`
	PrivateOverlayRevision      string `json:"private_overlay_revision"`
	Mode                        string `json:"mode"`
	TargetOS                    string `json:"target_os"`
	TargetArchitecture          string `json:"target_architecture"`
	ProfileID                   string `json:"profile_id"`
}

func RunPrivateOverlayValidation(
	args []string,
	load func(string) (hostruntime.PrivateOverlay, string, error),
) (PrivateOverlayValidationReceipt, error) {
	if len(args) != 3 ||
		args[0] != "validate-private-overlay" ||
		args[1] != "--private" ||
		!canonicalHostPath(args[2]) {
		return PrivateOverlayValidationReceipt{}, ErrHostUsage
	}
	if load == nil {
		return PrivateOverlayValidationReceipt{}, ErrHostCommandFailed
	}
	overlay, revision, err := load(args[2])
	if err != nil ||
		overlay.SchemaVersion != 1 ||
		overlay.Target.OS != "linux" ||
		overlay.Target.Architecture != "amd64" ||
		overlay.Target.ExpectedEUID != 0 ||
		!validLowerDigest(overlay.Target.HostIdentityDigest) ||
		!validLowerDigest(overlay.Target.ControlHostIdentityDigest) ||
		overlay.Target.HostIdentityDigest ==
			overlay.Target.ControlHostIdentityDigest ||
		!validValidationProfile(overlay.Target.ProfileID) ||
		overlay.Policy.AcquisitionDefault != "disabled" ||
		!validLowerDigest(revision) {
		return PrivateOverlayValidationReceipt{}, ErrHostCommandFailed
	}
	return PrivateOverlayValidationReceipt{
		SchemaVersion:               privateOverlayValidationSchemaVersion,
		PrivateOverlaySchemaVersion: overlay.SchemaVersion,
		PrivateOverlayRevision:      revision,
		Mode:                        "disabled-observer",
		TargetOS:                    overlay.Target.OS,
		TargetArchitecture:          overlay.Target.Architecture,
		ProfileID:                   overlay.Target.ProfileID,
	}, nil
}

func validValidationProfile(profile string) bool {
	return profile == "strict-linux" || profile == "qts-capless-root"
}
