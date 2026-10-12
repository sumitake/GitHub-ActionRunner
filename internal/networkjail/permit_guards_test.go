package networkjail

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/state"
)

const (
	testBrokerStatus = "Name:\tbroker\nUid:\t1001\t1001\t1001\t1001\n"
	testBrokerStat   = "71 (broker) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 7001 20\n"
)

func procDocuments(documents map[string]string) boundedProcReader {
	return func(path string, maximum int64) ([]byte, error) {
		if maximum != maximumPermitProcDocumentBytes {
			return nil, fmt.Errorf("maximum = %d", maximum)
		}
		document, ok := documents[path]
		if !ok {
			return nil, fmt.Errorf("unexpected path %q", path)
		}
		return []byte(document), nil
	}
}

func brokerProc() boundedProcReader {
	return procDocuments(map[string]string{
		"/proc/71/status": testBrokerStatus,
		"/proc/71/stat":   testBrokerStat,
	})
}

func TestObservePermitPeerProcessRequiresStableProcIdentity(t *testing.T) {
	got, err := observePermitPeerProcess(context.Background(), 71, brokerProc())
	if err != nil || got != (PermitPeerProcess{UID: 1001, StartTime: 7001}) {
		t.Fatalf("observation/error = %+v/%v", got, err)
	}

	var statReads int
	unstable := func(path string, _ int64) ([]byte, error) {
		switch path {
		case "/proc/71/status":
			return []byte(testBrokerStatus), nil
		case "/proc/71/stat":
			statReads++
			if statReads == 2 {
				return []byte("71 (broker) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 7002 20\n"), nil
			}
			return []byte(testBrokerStat), nil
		}
		return nil, fmt.Errorf("unexpected path %q", path)
	}
	if _, err := observePermitPeerProcess(context.Background(), 71, unstable); !errors.Is(err, ErrPermitPeerInvalid) {
		t.Fatalf("unstable error = %v", err)
	}
}

func TestObservePermitPeerProcessRejectsMalformedStatusAndContext(t *testing.T) {
	mixedUID := procDocuments(map[string]string{
		"/proc/71/status": "Name:\tbroker\nUid:\t1001\t1002\t1001\t1001\n",
		"/proc/71/stat":   testBrokerStat,
	})
	if _, err := observePermitPeerProcess(context.Background(), 71, mixedUID); !errors.Is(err, ErrPermitPeerInvalid) {
		t.Fatalf("mixed uid error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := observePermitPeerProcess(ctx, 71, brokerProc()); !errors.Is(err, ErrPermitPeerInvalid) {
		t.Fatalf("canceled error = %v", err)
	}
}

func TestProcPermitPeerValidatorChecksClassUserAndProcess(t *testing.T) {
	validator, err := NewProcPermitPeerValidator(1001)
	if err != nil {
		t.Fatalf("NewProcPermitPeerValidator: %v", err)
	}
	validator.readFile = brokerProc()
	peer := newPermitPeer(71, 1001, 7001)
	for _, class := range []DialClass{DialClassJob, DialClassDoH} {
		if err := validator.ValidatePermitPeer(context.Background(), 3, 9, class, peer); err != nil {
			t.Fatalf("class %d: %v", class, err)
		}
	}
	rejected := map[string]struct {
		class DialClass
		peer  PermitPeer
		proc  boundedProcReader
	}{
		"unknown class":   {class: 0, peer: peer, proc: brokerProc()},
		"other user":      {class: DialClassJob, peer: newPermitPeer(71, 1002, 7001), proc: brokerProc()},
		"recycled pid":    {class: DialClassJob, peer: newPermitPeer(71, 1001, 7000), proc: brokerProc()},
		"zero start time": {class: DialClassJob, peer: newPermitPeer(71, 1001, 0), proc: brokerProc()},
		"process gone":    {class: DialClassJob, peer: peer, proc: procDocuments(nil)},
		"process changed uid": {class: DialClassJob, peer: peer, proc: procDocuments(map[string]string{
			"/proc/71/status": "Name:\tbroker\nUid:\t0\t0\t0\t0\n",
			"/proc/71/stat":   testBrokerStat,
		})},
	}
	for name, test := range rejected {
		t.Run(name, func(t *testing.T) {
			candidate := *validator
			candidate.readFile = test.proc
			if err := candidate.ValidatePermitPeer(context.Background(), 3, 9, test.class, test.peer); !errors.Is(err, ErrPermitPeerInvalid) {
				t.Fatalf("error = %v, want ErrPermitPeerInvalid", err)
			}
		})
	}
	if _, err := NewProcPermitPeerValidator(0); err == nil {
		t.Fatal("NewProcPermitPeerValidator(0) succeeded; root must never be the broker user")
	}
}

type fakeRecoverableLister struct {
	rows []state.RecoverableAssignment
	err  error
}

func (lister fakeRecoverableLister) ListRecoverable(context.Context) ([]state.RecoverableAssignment, error) {
	return lister.rows, lister.err
}

func TestStateLedgerReferenceGuardReportsSlotsHeldByRecoverableAssignments(t *testing.T) {
	guard, err := NewStateLedgerReferenceGuard(fakeRecoverableLister{rows: []state.RecoverableAssignment{
		{Slot: controller.RunnerSlot{CapacitySlotID: 3}},
	}})
	if err != nil {
		t.Fatalf("NewStateLedgerReferenceGuard: %v", err)
	}
	if referenced, err := guard.HasLedgerReferences(context.Background(), 3); err != nil || !referenced {
		t.Fatalf("slot 3 referenced/error = %v/%v, want true", referenced, err)
	}
	if referenced, err := guard.HasLedgerReferences(context.Background(), 4); err != nil || referenced {
		t.Fatalf("slot 4 referenced/error = %v/%v, want false", referenced, err)
	}

	failing, _ := NewStateLedgerReferenceGuard(fakeRecoverableLister{err: errors.New("store closed")})
	if _, err := failing.HasLedgerReferences(context.Background(), 3); !errors.Is(err, ErrPermitAuthorityUnavailable) {
		t.Fatalf("store error = %v, want ErrPermitAuthorityUnavailable", err)
	}
	if _, err := guard.HasLedgerReferences(context.Background(), 0); !errors.Is(err, ErrPermitAuthorityUnavailable) {
		t.Fatalf("slot 0 error = %v, want ErrPermitAuthorityUnavailable", err)
	}
	if _, err := NewStateLedgerReferenceGuard(nil); err == nil {
		t.Fatal("NewStateLedgerReferenceGuard(nil) succeeded")
	}
}

func TestRejectEmptyConntrackRebaseAlwaysFailsClosed(t *testing.T) {
	if err := (RejectEmptyConntrackRebase{}).ValidateEmptyConntrack(
		context.Background(), 1, BootID{1}, BootID{2}, EmptyConntrackProof{},
	); !errors.Is(err, ErrEmptyConntrackProofInvalid) {
		t.Fatalf("error = %v", err)
	}
}
