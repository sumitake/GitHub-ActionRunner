//go:build !linux

package hostruntime

import "errors"

// CreateSlotDirectories is Linux-only; elsewhere it always fails closed.
func CreateSlotDirectories(string, string, uint32, uint32) error {
	return errors.New("hostruntime: slot directories require linux")
}

// RemoveEmptySlotDirectories is Linux-only; elsewhere it always fails closed.
func RemoveEmptySlotDirectories(string, string) error {
	return errors.New("hostruntime: slot directories require linux")
}
