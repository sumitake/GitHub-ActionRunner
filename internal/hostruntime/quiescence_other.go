//go:build !darwin && !linux

package hostruntime

import "errors"

func proveBrokerRootEmpty(string) error {
	return errors.New("hostruntime: broker root proof unsupported")
}
