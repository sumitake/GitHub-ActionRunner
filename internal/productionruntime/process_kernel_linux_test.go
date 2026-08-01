//go:build linux

package productionruntime

import (
	"errors"
	"math"
	"slices"
	"testing"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"golang.org/x/sys/unix"
)

func TestObserveLinuxProcessTruthTable(t *testing.T) {
	t.Parallel()

	valid := newFakeProcessKernel(validProcessRecordFixture()).observation.Start
	partial := valid
	partial.ExecutableDigest = ""
	mismatched := valid
	mismatched.PID++
	for _, test := range []struct {
		name     string
		start    hostruntime.ProcessStartObservation
		startErr error
		pgid     int
		pgidErr  error
		want     ProcessObservation
		wantErr  bool
	}{
		{
			name:  "present",
			start: valid,
			pgid:  int(valid.PID),
			want: ProcessObservation{
				Present: true,
				Start:   valid,
				PGID:    valid.PID,
			},
		},
		{
			name:     "absent",
			startErr: hostruntime.ErrProcessIdentityUnavailable,
			pgid:     -1,
			pgidErr:  unix.ESRCH,
			want:     ProcessObservation{},
		},
		{
			name:    "exit-between-start-and-pgid",
			start:   valid,
			pgidErr: unix.ESRCH,
			wantErr: true,
		},
		{
			name:     "identity-unavailable-but-pid-present",
			startErr: hostruntime.ErrProcessIdentityUnavailable,
			pgid:     int(valid.PID),
			wantErr:  true,
		},
		{
			name:     "identity-unavailable-and-permission-denied",
			startErr: hostruntime.ErrProcessIdentityUnavailable,
			pgidErr:  unix.EPERM,
			wantErr:  true,
		},
		{
			name:     "partial-start-with-error",
			start:    partial,
			startErr: hostruntime.ErrProcessIdentityUnavailable,
			pgidErr:  unix.ESRCH,
			wantErr:  true,
		},
		{
			name:    "mismatched-pid",
			start:   mismatched,
			pgid:    int(valid.PID),
			wantErr: true,
		},
		{
			name:    "nonpositive-pgid",
			start:   valid,
			pgid:    0,
			wantErr: true,
		},
		{
			name:    "pgid-overflow",
			start:   valid,
			pgid:    int(^uint32(0)>>1) + 1,
			wantErr: true,
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var calls []string
			got, err := observeLinuxProcess(
				valid.PID,
				func(pid uint64) (
					hostruntime.ProcessStartObservation,
					string,
					error,
				) {
					calls = append(calls, "start")
					if pid != valid.PID {
						t.Fatalf("observeStart pid = %d", pid)
					}
					return test.start, "unused", test.startErr
				},
				func(pid int) (int, error) {
					calls = append(calls, "pgid")
					if pid != int(valid.PID) {
						t.Fatalf("getpgid pid = %d", pid)
					}
					return test.pgid, test.pgidErr
				},
			)
			if !slices.Equal(calls, []string{"start", "pgid"}) {
				t.Fatalf("callback order = %q", calls)
			}
			if test.wantErr {
				if !errors.Is(err, ErrProcessObservationUnavailable) {
					t.Fatalf("observeLinuxProcess() error = %v", err)
				}
				if got != (ProcessObservation{}) {
					t.Fatalf("failed observation = %#v", got)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("observeLinuxProcess() = %#v, %v; want %#v", got, err, test.want)
			}
		})
	}
}

func TestObserveLinuxProcessRejectsPIDOverflowBeforeCallbacks(t *testing.T) {
	t.Parallel()

	called := false
	_, err := observeLinuxProcess(
		uint64(math.MaxInt32)+1,
		func(uint64) (hostruntime.ProcessStartObservation, string, error) {
			called = true
			return hostruntime.ProcessStartObservation{}, "", nil
		},
		func(int) (int, error) {
			called = true
			return 0, nil
		},
	)
	if !errors.Is(err, ErrProcessObservationUnavailable) || called {
		t.Fatalf("overflow result error=%v called=%t", err, called)
	}
}

func TestObserveLinuxProcessDoesNotCacheAcrossCalls(t *testing.T) {
	t.Parallel()

	base := newFakeProcessKernel(validProcessRecordFixture()).observation.Start
	startCalls := 0
	pgidCalls := 0
	observeStart := func(uint64) (
		hostruntime.ProcessStartObservation,
		string,
		error,
	) {
		startCalls++
		observation := base
		observation.StartTimeTicks += uint64(startCalls - 1)
		return observation, "unused", nil
	}
	getpgid := func(int) (int, error) {
		pgidCalls++
		return int(base.PID), nil
	}
	first, firstErr := observeLinuxProcess(base.PID, observeStart, getpgid)
	second, secondErr := observeLinuxProcess(base.PID, observeStart, getpgid)
	if firstErr != nil || secondErr != nil || first == second ||
		startCalls != 2 || pgidCalls != 2 {
		t.Fatalf(
			"observations=%#v/%#v errors=%v/%v calls=%d/%d",
			first,
			second,
			firstErr,
			secondErr,
			startCalls,
			pgidCalls,
		)
	}
}
