package networkjail

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
)

func TestDialPermitRequestFrameIsExactAndTimeFree(t *testing.T) {
	request := DialPermitRequest{
		SlotID:        17,
		JobGeneration: 29,
		Class:         DialClassJob,
		Sequence:      41,
	}
	frame, err := request.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if len(frame) != dialPermitRequestFrameBytes {
		t.Fatalf("frame length = %d, want %d", len(frame), dialPermitRequestFrameBytes)
	}
	decoded, err := ParseDialPermitRequest(frame)
	if err != nil {
		t.Fatalf("ParseDialPermitRequest: %v", err)
	}
	if decoded != request {
		t.Fatalf("decoded = %#v, want %#v", decoded, request)
	}

	gotFields := make([]string, 0, reflect.TypeOf(request).NumField())
	for index := 0; index < reflect.TypeOf(request).NumField(); index++ {
		gotFields = append(gotFields, reflect.TypeOf(request).Field(index).Name)
	}
	wantFields := []string{"SlotID", "JobGeneration", "Class", "Sequence"}
	if !reflect.DeepEqual(gotFields, wantFields) {
		t.Fatalf("request fields = %v, want exactly %v", gotFields, wantFields)
	}

	for _, invalid := range [][]byte{
		nil,
		frame[:len(frame)-1],
		append(append([]byte(nil), frame...), 0),
		func() []byte {
			value := append([]byte(nil), frame...)
			value[0]++
			return value
		}(),
		func() []byte {
			value := append([]byte(nil), frame...)
			value[13] = 0
			return value
		}(),
	} {
		if _, err := ParseDialPermitRequest(invalid); err == nil {
			t.Fatalf("ParseDialPermitRequest(%x) = nil error", invalid)
		}
	}
}

func TestPermitAuthorityReservesBlocksBeforeIssuing(t *testing.T) {
	fixture := newPermitFixture(t, 3)
	fixture.activate(7)
	writesAfterActivation := fixture.store.writeCount()

	for sequence := uint64(1); sequence <= 3; sequence++ {
		permit, err := fixture.consume(7, DialClassJob, sequence)
		if err != nil {
			t.Fatalf("Consume sequence %d: %v", sequence, err)
		}
		if permit.number != sequence {
			t.Fatalf("permit number = %d, want %d", permit.number, sequence)
		}
	}
	if got := fixture.store.writeCount(); got != writesAfterActivation+1 {
		t.Fatalf("durable writes = %d, want %d after one reservation block", got, writesAfterActivation+1)
	}
	state := fixture.store.mustLoad(t, fixture.slot)
	if state.Job.ReservedHighWater != 3 || state.Job.IssuedHighWater != 0 {
		t.Fatalf("durable job watermarks = reserved:%d issued:%d, want 3:0",
			state.Job.ReservedHighWater, state.Job.IssuedHighWater)
	}
}

func TestPermitAuthorityCrashWastesUnissuedReservation(t *testing.T) {
	fixture := newPermitFixture(t, 3)
	fixture.activate(7)
	first, err := fixture.consume(7, DialClassJob, 1)
	if err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	if first.number != 1 {
		t.Fatalf("first permit = %d, want 1", first.number)
	}

	fixture.clock.advance(1_000_000_000)
	restarted := fixture.restart(t)
	next, err := restarted.consume(7, DialClassJob, 4)
	if err != nil {
		t.Fatalf("post-crash Consume: %v", err)
	}
	if next.number != 4 {
		t.Fatalf("post-crash permit = %d, want 4 (2 and 3 wasted)", next.number)
	}
}

func TestPermitAuthoritySlotReuseDoesNotResetBucket(t *testing.T) {
	fixture := newPermitFixture(t, 2)
	fixture.activate(7)
	if _, err := fixture.consume(7, DialClassJob, 1); err != nil {
		t.Fatalf("Consume generation 7: %v", err)
	}
	if err := fixture.authority.Deactivate(context.Background(), fixture.slot, 7); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}
	fixture.activate(8)

	if _, err := fixture.consume(8, DialClassJob, 1); !errors.Is(err, ErrPermitBudgetExhausted) {
		t.Fatalf("immediate reused-slot Consume = %v, want ErrPermitBudgetExhausted", err)
	}
	fixture.clock.advance(1_000_000_000)
	permit, err := fixture.consume(8, DialClassJob, 1)
	if err != nil {
		t.Fatalf("refilled reused-slot Consume: %v", err)
	}
	if permit.number <= 2 {
		t.Fatalf("reused-slot permit number = %d, want above prior reservation high-water", permit.number)
	}
}

func TestPermitAuthorityRejectsClockRegressionWithoutMutation(t *testing.T) {
	fixture := newPermitFixture(t, 2)
	fixture.activate(7)
	if _, err := fixture.consume(7, DialClassJob, 1); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	before := fixture.store.mustLoad(t, fixture.slot)
	fixture.clock.setMonotonic(1)

	if _, err := fixture.consume(7, DialClassJob, 2); !errors.Is(err, ErrMonotonicClockRegression) {
		t.Fatalf("regressing Consume = %v, want ErrMonotonicClockRegression", err)
	}
	after := fixture.store.mustLoad(t, fixture.slot)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("durable state mutated on clock regression\n before=%#v\n after=%#v", before, after)
	}
}

func TestPermitAuthorityNewBootRequiresOneUseEmptyConntrackProof(t *testing.T) {
	fixture := newPermitFixture(t, 2)
	fixture.activate(7)
	if _, err := fixture.consume(7, DialClassJob, 1); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	fixture.clock.setBoot(testBootID(2), 10)

	if _, err := fixture.consume(7, DialClassJob, 2); !errors.Is(err, ErrBootRebaseRequired) {
		t.Fatalf("new-boot Consume = %v, want ErrBootRebaseRequired", err)
	}
	if err := fixture.authority.Rebase(
		context.Background(),
		fixture.slot,
		EmptyConntrackProof{},
	); !errors.Is(err, ErrEmptyConntrackProofInvalid) {
		t.Fatalf("zero-proof Rebase = %v, want ErrEmptyConntrackProofInvalid", err)
	}
	proof := fixture.rebaseProof()
	if err := fixture.authority.Rebase(context.Background(), fixture.slot, proof); err != nil {
		t.Fatalf("Rebase: %v", err)
	}
	if err := fixture.authority.Rebase(context.Background(), fixture.slot, proof); !errors.Is(err, ErrBootRebaseReplay) {
		t.Fatalf("replayed Rebase = %v, want ErrBootRebaseReplay", err)
	}

	fixture.activate(8)
	permit, err := fixture.consume(8, DialClassJob, 1)
	if err != nil {
		t.Fatalf("post-rebase Consume: %v", err)
	}
	if permit.number != 1 {
		t.Fatalf("post-rebase permit number = %d, want 1", permit.number)
	}
}

func TestPermitAuthorityCollectRequiresElapsedTailAndNoReferences(t *testing.T) {
	fixture := newPermitFixture(t, 2)
	fixture.activate(7)
	if _, err := fixture.consume(7, DialClassJob, 1); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if err := fixture.authority.Deactivate(context.Background(), fixture.slot, 7); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}

	if err := fixture.authority.Collect(context.Background(), fixture.slot); !errors.Is(err, ErrLedgerRetained) {
		t.Fatalf("early Collect = %v, want ErrLedgerRetained", err)
	}
	fixture.clock.advance(fixture.tailNanos)
	fixture.references.set(true)
	if err := fixture.authority.Collect(context.Background(), fixture.slot); !errors.Is(err, ErrLedgerReferenced) {
		t.Fatalf("referenced Collect = %v, want ErrLedgerReferenced", err)
	}
	fixture.references.set(false)
	if err := fixture.authority.Collect(context.Background(), fixture.slot); err != nil {
		t.Fatalf("eligible Collect: %v", err)
	}
	if _, found, err := fixture.store.load(context.Background(), fixture.slot); err != nil || found {
		t.Fatalf("ledger after Collect = found:%v err:%v, want absent", found, err)
	}
}

func TestPermitAuthorityConcurrentDuplicateSequenceIssuesOnce(t *testing.T) {
	fixture := newPermitFixture(t, 8)
	fixture.activate(7)

	const callers = 32
	start := make(chan struct{})
	results := make(chan error, callers)
	var wait sync.WaitGroup
	for index := 0; index < callers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := fixture.consume(7, DialClassJob, 1)
			results <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)

	var successes int
	for err := range results {
		if err == nil {
			successes++
			continue
		}
		if !errors.Is(err, ErrPermitSequence) {
			t.Fatalf("duplicate Consume error = %v, want ErrPermitSequence", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful duplicate requests = %d, want 1", successes)
	}
}

func TestPermitAuthorityNeverRefundsLostOrFailedPermits(t *testing.T) {
	fixture := newPermitFixture(t, 2)
	fixture.activate(7)
	first, err := fixture.consume(7, DialClassJob, 1)
	if err != nil {
		t.Fatalf("lost-reply Consume: %v", err)
	}
	second, err := fixture.consume(7, DialClassJob, 2)
	if err != nil {
		t.Fatalf("failed-dial Consume: %v", err)
	}
	if second.number != first.number+1 {
		t.Fatalf("permit numbers = %d, %d; want monotonic without refund", first.number, second.number)
	}
	if _, err := fixture.consume(7, DialClassJob, 3); !errors.Is(err, ErrPermitBudgetExhausted) {
		t.Fatalf("third Consume = %v, want exhausted after two permits", err)
	}
}

func TestPermitAuthorityClassBudgetsAreIndependent(t *testing.T) {
	fixture := newPermitFixture(t, 1)
	fixture.activate(7)
	if _, err := fixture.consume(7, DialClassJob, 1); err != nil {
		t.Fatalf("job Consume: %v", err)
	}
	if _, err := fixture.consume(7, DialClassJob, 2); !errors.Is(err, ErrPermitBudgetExhausted) {
		t.Fatalf("exhausted job Consume = %v, want ErrPermitBudgetExhausted", err)
	}
	permit, err := fixture.consume(7, DialClassDoH, 1)
	if err != nil {
		t.Fatalf("DoH Consume after job exhaustion: %v", err)
	}
	if permit.class != DialClassDoH || permit.number != 1 {
		t.Fatalf("DoH permit = %#v, want class DoH number 1", permit)
	}
}

func TestPermitAuthorityRejectsGenerationAndPeerMismatch(t *testing.T) {
	fixture := newPermitFixture(t, 2)
	fixture.activate(7)
	if _, err := fixture.consume(8, DialClassJob, 1); !errors.Is(err, ErrPermitAssignment) {
		t.Fatalf("wrong-generation Consume = %v, want ErrPermitAssignment", err)
	}
	_, err := fixture.authority.Consume(
		context.Background(),
		DialPermitRequest{
			SlotID:        fixture.slot,
			JobGeneration: 7,
			Class:         DialClassJob,
			Sequence:      1,
		},
		PermitPeer{},
	)
	if !errors.Is(err, ErrPermitPeerInvalid) {
		t.Fatalf("zero-peer Consume = %v, want ErrPermitPeerInvalid", err)
	}
}

func TestPermitAuthorityStoreFailureCannotIssueOrSpend(t *testing.T) {
	fixture := newPermitFixture(t, 2)
	fixture.activate(7)
	before := fixture.store.mustLoad(t, fixture.slot)
	fixture.store.failNextWrite()
	if _, err := fixture.consume(7, DialClassJob, 1); !errors.Is(err, ErrPermitAuthorityUnavailable) {
		t.Fatalf("failed-reservation Consume = %v, want ErrPermitAuthorityUnavailable", err)
	}
	after := fixture.store.mustLoad(t, fixture.slot)
	if after != before {
		t.Fatalf("durable ledger changed after failed reservation\n before=%#v\n after=%#v", before, after)
	}
	permit, err := fixture.consume(7, DialClassJob, 1)
	if err != nil {
		t.Fatalf("retry after failed reservation: %v", err)
	}
	if permit.number != 1 {
		t.Fatalf("permit after failed reservation = %d, want 1", permit.number)
	}
}
