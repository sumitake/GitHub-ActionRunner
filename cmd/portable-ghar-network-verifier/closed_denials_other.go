//go:build !linux

package main

func closedDenialsPlatform() error {
	return ErrClosedDenialsUnsupportedPlatform
}

func defaultClosedDenialsProbeRuntime() closedDenialsProbeRuntime {
	return closedDenialsProbeRuntime{}
}
