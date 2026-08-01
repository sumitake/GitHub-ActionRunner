//go:build linux

package linuxcap

import "golang.org/x/sys/unix"

const (
	netAdminCapability   = unix.CAP_NET_ADMIN
	kernelLastCapability = unix.CAP_LAST_CAP
)
