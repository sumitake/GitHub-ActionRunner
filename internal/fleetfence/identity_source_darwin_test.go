//go:build darwin

package fleetfence

import (
	"context"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDarwinIdentitySourceUsesKernelBootAndProcessStartIdentity(t *testing.T) {
	t.Parallel()

	source := &systemIdentitySource{
		bootTime: func(name string) (*unix.Timeval, error) {
			if name != "kern.boottime" {
				t.Fatalf("boot sysctl = %q", name)
			}
			return &unix.Timeval{Sec: 100, Usec: 200}, nil
		},
		process: func(name string, arguments ...int) (*unix.KinfoProc, error) {
			if name != "kern.proc.pid" ||
				len(arguments) != 1 ||
				arguments[0] != 1234 {
				t.Fatalf("process sysctl = %q %v", name, arguments)
			}
			return &unix.KinfoProc{
				Proc: unix.ExternProc{
					P_pid:       1234,
					P_starttime: unix.Timeval{Sec: 300, Usec: 400},
				},
			}, nil
		},
	}
	identity, err := source.Current(context.Background(), 1234)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if identity.BootID != "darwin-100-200" ||
		identity.ProcessStartID != "darwin-process-300-400" {
		t.Fatalf("identity = %+v", identity)
	}
}
