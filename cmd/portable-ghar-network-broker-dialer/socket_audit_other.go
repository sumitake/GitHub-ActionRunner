//go:build !linux

package main

import "errors"

func inspectHeldInternetSockets() (heldSocketAuditReport, error) {
	return heldSocketAuditReport{},
		errors.New("broker-dialer: socket audit unavailable")
}
