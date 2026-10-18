package controller

// CanaryPolicy previews exactly the policy used by SetAcquisition. It is a
// pure value transformation, not a transition or acquisition authority.
func CanaryPolicy(template AcquisitionPolicy, scaleSet string) (AcquisitionPolicy, error) {
	if !validAcquisitionScalar(scaleSet, maxAcquisitionScaleSetBytes) {
		return AcquisitionPolicy{}, ErrAdminConflict
	}
	next := cloneAcquisitionPolicy(template)
	next.Mode = AcquisitionCanaryOnly
	next.MaxCapacity = 1
	next.EligibleScaleSets = []string{scaleSet}
	return CanonicalizeAcquisitionPolicy(next)
}
