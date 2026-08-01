//go:build !darwin && !linux

package fleetfence

import "context"

type systemIdentitySource struct{}

func NewSystemIdentitySource() IdentitySource {
	return systemIdentitySource{}
}

func (systemIdentitySource) Current(
	context.Context,
	int,
) (ProcessIdentity, error) {
	return ProcessIdentity{}, ErrInvalidState
}
