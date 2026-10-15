//go:build !linux

package main

import "github.com/sumitake/portable-ghar/internal/networkjail"

// newPermitClock has no implementation off Linux: the acquiring controller
// runs only on Linux hosts.
func newPermitClock() (networkjail.MonotonicClock, error) {
	return nil, errCommandUnavailable
}
