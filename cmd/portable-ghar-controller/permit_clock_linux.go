//go:build linux

package main

import "github.com/sumitake/portable-ghar/internal/networkjail"

// newPermitClock returns the boot-time clock the permit authority measures
// leases with.
func newPermitClock() (networkjail.MonotonicClock, error) {
	return networkjail.NewSystemMonotonicClock()
}
