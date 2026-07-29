//go:build darwin

package fleetfence

import (
	"context"
	"fmt"

	"golang.org/x/sys/unix"
)

type systemIdentitySource struct {
	bootTime func(string) (*unix.Timeval, error)
	process  func(string, ...int) (*unix.KinfoProc, error)
}

func NewSystemIdentitySource() IdentitySource {
	return &systemIdentitySource{
		bootTime: unix.SysctlTimeval,
		process:  unix.SysctlKinfoProc,
	}
}

func (s *systemIdentitySource) Current(
	ctx context.Context,
	pid int,
) (ProcessIdentity, error) {
	if err := ctx.Err(); err != nil {
		return ProcessIdentity{}, err
	}
	if pid <= 0 {
		return ProcessIdentity{}, ErrInvalidState
	}
	if s == nil || s.bootTime == nil || s.process == nil {
		return ProcessIdentity{}, ErrInvalidState
	}
	boot, err := s.bootTime("kern.boottime")
	if err != nil || boot.Sec <= 0 || boot.Usec < 0 {
		return ProcessIdentity{}, ErrInvalidState
	}
	process, err := s.process("kern.proc.pid", pid)
	if err != nil || process.Proc.P_pid != int32(pid) ||
		process.Proc.P_starttime.Sec <= 0 ||
		process.Proc.P_starttime.Usec < 0 {
		return ProcessIdentity{}, ErrInvalidState
	}
	if err := ctx.Err(); err != nil {
		return ProcessIdentity{}, err
	}
	identity := ProcessIdentity{
		BootID: fmt.Sprintf(
			"darwin-%d-%d",
			boot.Sec,
			boot.Usec,
		),
		ProcessStartID: fmt.Sprintf(
			"darwin-process-%d-%d",
			process.Proc.P_starttime.Sec,
			process.Proc.P_starttime.Usec,
		),
	}
	if !validScalar(identity.BootID) ||
		!validScalar(identity.ProcessStartID) {
		return ProcessIdentity{}, ErrInvalidState
	}
	return identity, nil
}
