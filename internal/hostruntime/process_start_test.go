package hostruntime

import (
	"errors"
	"strings"
	"testing"
)

const goldenProcessStartIdentity = "8a763ea92c8efe4e3359585e2cf682a49e9e31538c35a0ccbab3a9bf4ac09211"

func TestProcessStartIdentityGolden(t *testing.T) {
	t.Parallel()

	observation := goldenProcessStartObservation()
	identity, err := DeriveProcessStartIdentity(observation)
	if err != nil {
		t.Fatalf("DeriveProcessStartIdentity() error = %v", err)
	}
	if identity != goldenProcessStartIdentity {
		t.Fatalf(
			"DeriveProcessStartIdentity() = %q, want %q",
			identity,
			goldenProcessStartIdentity,
		)
	}
}

func TestParseLinuxProcStatUsesFinalDelimiterAndField22(t *testing.T) {
	t.Parallel()

	document := []byte(
		"4242 (worker ) with spaces) S 1 2 3 4 5 6 7 8 9 10 11 12 " +
			"13 14 15 16 17 18 987654 20",
	)
	start, err := ParseLinuxProcStatStartTime(document)
	if err != nil {
		t.Fatalf("ParseLinuxProcStatStartTime() error = %v", err)
	}
	if start != 987654 {
		t.Fatalf("ParseLinuxProcStatStartTime() = %d, want 987654", start)
	}
}

func TestParseLinuxProcStatRejectsMalformedAndOverflow(t *testing.T) {
	t.Parallel()

	valid := "7 (x) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20"
	tests := []string{
		"",
		"7 x) S 1 2 3",
		strings.Replace(valid, " 19 20", " -1 20", 1),
		strings.Replace(valid, " 19 20", " +1 20", 1),
		strings.Replace(valid, " 19 20", " 18446744073709551616 20", 1),
		strings.Replace(valid, " S ", " ? ", 1),
		valid + "\n",
	}
	for _, document := range tests {
		document := document
		t.Run(document, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseLinuxProcStatStartTime(
				[]byte(document),
			); !errors.Is(err, ErrProcessIdentityUnavailable) {
				t.Fatalf("ParseLinuxProcStatStartTime() error = %v", err)
			}
		})
	}
}

func TestStableProcessIdentityRejectsEverySecondReadChange(t *testing.T) {
	t.Parallel()

	base := goldenProcessStartObservation()
	mutations := []func(*ProcessStartObservation){
		func(value *ProcessStartObservation) { value.BootID = strings.Repeat("0", 36) },
		func(value *ProcessStartObservation) { value.PIDNamespaceInode++ },
		func(value *ProcessStartObservation) { value.PID++ },
		func(value *ProcessStartObservation) { value.StartTimeTicks++ },
		func(value *ProcessStartObservation) { value.ExecutableDigest = strings.Repeat("b", 64) },
		func(value *ProcessStartObservation) { value.ExecutableDevice++ },
		func(value *ProcessStartObservation) { value.ExecutableInode++ },
		func(value *ProcessStartObservation) { value.ExecutableFileSize++ },
	}
	for index, mutate := range mutations {
		second := base
		mutate(&second)
		observer := &scriptedProcessStartObserver{
			observations: []ProcessStartObservation{base, second},
		}
		if _, _, err := ObserveStableProcessStartIdentity(
			observer,
			base.PID,
		); !errors.Is(err, ErrProcessIdentityUnavailable) {
			t.Fatalf("mutation %d error = %v", index, err)
		}
	}
}

func TestStableProcessIdentityRequiresTwoPositiveObservations(t *testing.T) {
	t.Parallel()

	observation := goldenProcessStartObservation()
	observer := &scriptedProcessStartObserver{
		observations: []ProcessStartObservation{observation, observation},
	}
	got, identity, err := ObserveStableProcessStartIdentity(
		observer,
		observation.PID,
	)
	if err != nil {
		t.Fatalf("ObserveStableProcessStartIdentity() error = %v", err)
	}
	if got != observation || identity != goldenProcessStartIdentity {
		t.Fatalf(
			"ObserveStableProcessStartIdentity() = %#v, %q",
			got,
			identity,
		)
	}
}

type scriptedProcessStartObserver struct {
	observations []ProcessStartObservation
	index        int
}

func (observer *scriptedProcessStartObserver) ObserveProcessStart(
	uint64,
) (ProcessStartObservation, error) {
	if observer.index >= len(observer.observations) {
		return ProcessStartObservation{}, ErrProcessIdentityUnavailable
	}
	observation := observer.observations[observer.index]
	observer.index++
	return observation, nil
}

func goldenProcessStartObservation() ProcessStartObservation {
	return ProcessStartObservation{
		BootID:             "01234567-89ab-cdef-" + "0123-456789abcdef",
		PIDNamespaceInode:  100,
		PID:                4242,
		StartTimeTicks:     987654,
		ExecutableDigest:   strings.Repeat("a", 64),
		ExecutableDevice:   2,
		ExecutableInode:    3,
		ExecutableFileSize: 4,
	}
}
