//go:build !linux

package linuxcap

// The immutable helper and verifier execute only on Linux. These Linux UAPI
// values keep their wire validators unit-testable on non-Linux development
// hosts; the production Linux build derives them from x/sys/unix.
const (
	netAdminCapability   = 12
	kernelLastCapability = 40
)
