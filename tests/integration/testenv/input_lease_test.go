package testenv

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

type scriptedInputLeaseOperations struct {
	trace      []string
	revalidate error
	unlink     error
	syncParent error
	absent     error
	close      error
	unlinks    int
	closes     int
}

func (o *scriptedInputLeaseOperations) Revalidate() error {
	o.trace = append(o.trace, "revalidate")
	return o.revalidate
}

func (o *scriptedInputLeaseOperations) Unlink() error {
	o.trace = append(o.trace, "unlink")
	o.unlinks++
	return o.unlink
}

func (o *scriptedInputLeaseOperations) SyncParent() error {
	o.trace = append(o.trace, "sync-parent")
	return o.syncParent
}

func (o *scriptedInputLeaseOperations) ProveAbsent() error {
	o.trace = append(o.trace, "prove-absent")
	return o.absent
}

func (o *scriptedInputLeaseOperations) Close() error {
	o.trace = append(o.trace, "close")
	o.closes++
	return o.close
}

func TestConformanceInputLeaseConsumesOnceInExactOrder(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	parsed := readValidParsedInput(t, now)
	operations := &scriptedInputLeaseOperations{}
	lease, err := newConformanceInputLease(parsed, operations)
	if err != nil {
		t.Fatalf("newConformanceInputLease: %v", err)
	}

	if err := lease.Consume(now); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if lease.state != inputLeaseConsumed || !lease.consumeProven {
		t.Fatalf(
			"state/proof = %v/%t",
			lease.state,
			lease.consumeProven,
		)
	}
	if !reflect.DeepEqual(operations.trace, []string{
		"revalidate",
		"unlink",
		"sync-parent",
		"prove-absent",
	}) {
		t.Fatalf("trace = %v", operations.trace)
	}

	if err := lease.Consume(now); !errors.Is(err, ErrAuthorizationLease) {
		t.Fatalf("second Consume = %v", err)
	}
	if operations.unlinks != 1 {
		t.Fatalf("unlink calls = %d, want 1", operations.unlinks)
	}
}

func TestConformanceInputLeasePreUnlinkFailuresRemainHeld(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		now        time.Time
		revalidate error
	}{
		{
			name:       "identity changed",
			now:        now,
			revalidate: errors.New("raw identity failure"),
		},
		{
			name: "expired",
			now:  now.Add(2 * time.Hour),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed := readValidParsedInput(t, now)
			operations := &scriptedInputLeaseOperations{
				revalidate: test.revalidate,
			}
			lease, err := newConformanceInputLease(parsed, operations)
			if err != nil {
				t.Fatalf("newConformanceInputLease: %v", err)
			}
			if err := lease.Consume(test.now); !errors.Is(
				err,
				ErrAuthorizationLease,
			) {
				t.Fatalf("Consume = %v", err)
			}
			if lease.state != inputLeaseHeld ||
				lease.consumeProven ||
				operations.unlinks != 0 {
				t.Fatalf(
					"held/proof/unlinks = %v/%t/%d",
					lease.state,
					lease.consumeProven,
					operations.unlinks,
				)
			}
		})
	}
}

func TestConformanceInputLeasePostUnlinkFailureSpendsCapability(
	t *testing.T,
) {
	t.Parallel()

	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		syncParent error
		absent     error
	}{
		{
			name:       "parent fsync",
			syncParent: errors.New("raw fsync failure"),
		},
		{
			name:   "recreated basename",
			absent: errors.New("raw replacement observation"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed := readValidParsedInput(t, now)
			operations := &scriptedInputLeaseOperations{
				syncParent: test.syncParent,
				absent:     test.absent,
			}
			lease, err := newConformanceInputLease(parsed, operations)
			if err != nil {
				t.Fatalf("newConformanceInputLease: %v", err)
			}
			if err := lease.Consume(now); !errors.Is(
				err,
				ErrAuthorizationConsumedRunAborted,
			) {
				t.Fatalf("Consume = %v", err)
			}
			if lease.state != inputLeaseConsumed ||
				lease.consumeProven ||
				operations.unlinks != 1 {
				t.Fatalf(
					"spent/proof/unlinks = %v/%t/%d",
					lease.state,
					lease.consumeProven,
					operations.unlinks,
				)
			}
			if err := lease.Consume(now); !errors.Is(
				err,
				ErrAuthorizationLease,
			) {
				t.Fatalf("second Consume = %v", err)
			}
			if operations.unlinks != 1 {
				t.Fatalf(
					"second consume unlinked again: %d",
					operations.unlinks,
				)
			}
		})
	}
}

func TestConformanceInputLeaseCloseZerosBytesAndRetainsDigest(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	parsed := readValidParsedInput(t, now)
	wantDigest := parsed.Digest
	operations := &scriptedInputLeaseOperations{}
	lease, err := newConformanceInputLease(parsed, operations)
	if err != nil {
		t.Fatalf("newConformanceInputLease: %v", err)
	}
	raw := lease.parsed.Document
	if len(raw) == 0 {
		t.Fatal("lease retained no input bytes")
	}
	if err := lease.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if lease.state != inputLeaseClosed ||
		lease.parsed.Digest != wantDigest ||
		len(lease.parsed.Document) != 0 {
		t.Fatalf(
			"closed state/digest/document = %v/%q/%d",
			lease.state,
			lease.parsed.Digest,
			len(lease.parsed.Document),
		)
	}
	for index, value := range raw {
		if value != 0 {
			t.Fatalf("retained byte %d not zero: %d", index, value)
		}
	}
	if err := lease.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if operations.closes != 1 {
		t.Fatalf("close calls = %d, want 1", operations.closes)
	}
}
