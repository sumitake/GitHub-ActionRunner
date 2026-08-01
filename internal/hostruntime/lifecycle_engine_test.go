package hostruntime

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLifecycleEngineCompletesAndReplaysWithoutDuplicateEffects(t *testing.T) {
	t.Parallel()

	binding := goldenUpgradeBinding(t)
	store := openTestLifecycleStore(t)
	effects := newTestLifecycleEffects(t, binding)
	reservation := goldenStorageReservation(
		t,
		binding,
		time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC),
	)
	engine := LifecycleEngine{
		Store:        store,
		Effects:      effects,
		Storage:      allowTestStorage{},
		PollInterval: time.Millisecond,
		Now: monotonicTestClock(
			time.Date(2026, 7, 29, 12, 0, 1, 0, time.UTC),
		),
	}
	request := LifecycleRequest{
		Binding:        binding,
		PriorManifest:  goldenManifest(t),
		TargetManifest: goldenManifest(t),
		Reservation:    reservation,
	}

	first, err := engine.Execute(context.Background(), request)
	if err != nil {
		t.Fatalf("Execute(first) error = %v", err)
	}
	if first.Status != HostActionComplete ||
		first.TargetProofDigest == nil ||
		first.OperationID != binding.OperationID {
		t.Fatalf("Execute(first) = %#v", first)
	}
	firstCounts := effects.countsCopy()

	second, err := engine.Execute(context.Background(), request)
	if err != nil {
		t.Fatalf("Execute(replay) error = %v", err)
	}
	if second.SchemaVersion != first.SchemaVersion ||
		second.Status != first.Status ||
		second.OperationID != first.OperationID ||
		second.JournalDigest != first.JournalDigest ||
		second.TargetProofDigest == nil ||
		first.TargetProofDigest == nil ||
		*second.TargetProofDigest != *first.TargetProofDigest ||
		second.FenceGeneration != first.FenceGeneration ||
		second.ActiveFleet != first.ActiveFleet ||
		second.ErrorClass != first.ErrorClass {
		t.Fatalf("Execute(replay) = %#v, want %#v", second, first)
	}
	if got := effects.countsCopy(); !equalPhaseCounts(got, firstCounts) {
		t.Fatalf("replay effect counts = %#v, want %#v", got, firstCounts)
	}

	reservationDocument, err := store.ReadCanonical(
		LifecycleReservations,
		lifecycleReservationName(binding.OperationID),
		maxLifecycleReservationBytes,
	)
	if err != nil {
		t.Fatalf("ReadCanonical(reservation) error = %v", err)
	}
	committed, _, err := ParseStorageReservation(
		reservationDocument,
		maxLifecycleReservationBytes,
	)
	if err != nil || committed.State != ReservationStateCommitted ||
		committed.CommittedTargetProofDigest == nil ||
		*committed.CommittedTargetProofDigest != *first.TargetProofDigest {
		t.Fatalf("committed reservation = %#v, error = %v", committed, err)
	}
}

func TestLifecycleEngineExecuteCloseFailureUpgradesSuccessToIntegrity(t *testing.T) {
	t.Parallel()

	binding := goldenUpgradeBinding(t)
	store := openTestLifecycleStore(t)
	effects := newTestLifecycleEffects(t, binding)
	closeErr := errors.New("lease close failed")
	lease := &testLifecycleOperationLease{closeErr: closeErr}
	engine := LifecycleEngine{
		Store:        store,
		Effects:      effects,
		Storage:      allowTestStorage{},
		PollInterval: time.Millisecond,
		Now: monotonicTestClock(
			time.Date(2026, 7, 29, 12, 30, 0, 0, time.UTC),
		),
		leaseAcquire: func(
			context.Context,
			time.Duration,
		) (lifecycleOperationLease, error) {
			return lease, nil
		},
	}
	request := lifecycleTestRequest(
		t,
		binding,
		time.Date(2026, 7, 29, 12, 30, 0, 0, time.UTC),
	)

	result, err := engine.Execute(context.Background(), request)
	if !errors.Is(err, ErrLifecycleExecution) ||
		!errors.Is(err, closeErr) ||
		result.Status != HostActionFailed ||
		result.ErrorClass != LifecycleErrorIntegrity ||
		result.TargetProofDigest != nil ||
		lease.closeCount != 1 {
		t.Fatalf(
			"Execute() = %#v, error=%v, lease=%#v",
			result,
			err,
			lease,
		)
	}
}

func TestLifecycleEngineCloseFailurePreservesPrimaryFailure(t *testing.T) {
	t.Parallel()

	binding := goldenUpgradeBinding(t)
	store := openTestLifecycleStore(t)
	effects := newTestLifecycleEffects(t, binding)
	effects.ambiguous[OperationPhasePrepared] = true
	closeErr := errors.New("lease close failed")
	lease := &testLifecycleOperationLease{closeErr: closeErr}
	engine := LifecycleEngine{
		Store:        store,
		Effects:      effects,
		Storage:      allowTestStorage{},
		PollInterval: time.Millisecond,
		Now: monotonicTestClock(
			time.Date(2026, 7, 29, 12, 45, 0, 0, time.UTC),
		),
		leaseAcquire: func(
			context.Context,
			time.Duration,
		) (lifecycleOperationLease, error) {
			return lease, nil
		},
	}
	request := lifecycleTestRequest(
		t,
		binding,
		time.Date(2026, 7, 29, 12, 45, 0, 0, time.UTC),
	)

	result, err := engine.Execute(context.Background(), request)
	if !errors.Is(err, ErrLifecycleRecoverable) ||
		!errors.Is(err, closeErr) ||
		result.Status != HostActionRecoverable ||
		result.ErrorClass != LifecycleErrorAmbiguousEffect ||
		lease.closeCount != 1 {
		t.Fatalf(
			"Execute() = %#v, error=%v, lease=%#v",
			result,
			err,
			lease,
		)
	}
}

func TestLifecycleEngineRecoverValidatesLeaseBeforePrepareOrEffects(t *testing.T) {
	t.Parallel()

	binding := goldenUpgradeBinding(t)
	store := openTestLifecycleStore(t)
	effects := newTestLifecycleEffects(t, binding)
	validateErr := errors.New("lease identity changed")
	lease := &testLifecycleOperationLease{validateErr: validateErr}
	engine := LifecycleEngine{
		Store:        store,
		Effects:      effects,
		Storage:      allowTestStorage{},
		Compensation: rejectTestCompensationAuthority{},
		PollInterval: time.Millisecond,
		Now: monotonicTestClock(
			time.Date(2026, 7, 29, 12, 50, 0, 0, time.UTC),
		),
		leaseAcquire: func(
			context.Context,
			time.Duration,
		) (lifecycleOperationLease, error) {
			return lease, nil
		},
	}
	request := lifecycleTestRequest(
		t,
		binding,
		time.Date(2026, 7, 29, 12, 50, 0, 0, time.UTC),
	)

	result, err := engine.Recover(context.Background(), request)
	if !errors.Is(err, ErrLifecycleExecution) ||
		result.Status != HostActionFailed ||
		result.ErrorClass != LifecycleErrorIntegrity ||
		lease.validateCount != 1 ||
		lease.closeCount != 1 ||
		len(effects.countsCopy()) != 0 {
		t.Fatalf(
			"Recover() = %#v, error=%v, lease=%#v, effects=%#v",
			result,
			err,
			lease,
			effects.countsCopy(),
		)
	}
	names, listErr := store.ListCanonicalNames(LifecycleJournals)
	if listErr != nil || len(names) != 0 {
		t.Fatalf("journal names = %v, error=%v", names, listErr)
	}
}

type rejectTestCompensationAuthority struct{}

func (rejectTestCompensationAuthority) AuthorizeCompensation(
	context.Context,
	OperationBinding,
	OperationJournal,
	TargetPostcondition,
) (CompensationAuthorization, error) {
	return CompensationAuthorization{}, errors.New("test compensation rejected")
}

func TestLifecycleEngineRecoverRevalidatesLeaseAfterPrepareBeforeEffects(
	t *testing.T,
) {
	t.Parallel()

	binding := goldenUpgradeBinding(t)
	store := openTestLifecycleStore(t)
	effects := newTestLifecycleEffects(t, binding)
	validateErr := errors.New("lease identity changed after prepare")
	lease := &testLifecycleOperationLease{
		validateErrors: []error{nil, validateErr},
	}
	engine := LifecycleEngine{
		Store:        store,
		Effects:      effects,
		Storage:      allowTestStorage{},
		Compensation: rejectTestCompensationAuthority{},
		PollInterval: time.Millisecond,
		Now: monotonicTestClock(
			time.Date(2026, 7, 29, 12, 51, 0, 0, time.UTC),
		),
		leaseAcquire: func(
			context.Context,
			time.Duration,
		) (lifecycleOperationLease, error) {
			return lease, nil
		},
	}
	request := lifecycleTestRequest(
		t,
		binding,
		time.Date(2026, 7, 29, 12, 51, 0, 0, time.UTC),
	)

	result, err := engine.Recover(context.Background(), request)
	if !errors.Is(err, ErrLifecycleExecution) ||
		result.Status != HostActionFailed ||
		result.ErrorClass != LifecycleErrorIntegrity ||
		lease.validateCount != 2 ||
		lease.closeCount != 1 ||
		len(effects.countsCopy()) != 0 {
		t.Fatalf(
			"Recover() = %#v, error=%v, lease=%#v, effects=%#v",
			result,
			err,
			lease,
			effects.countsCopy(),
		)
	}
}

func TestLifecycleEngineRecoverCloseFailureUpgradesSuccessToIntegrity(t *testing.T) {
	t.Parallel()

	binding := goldenUpgradeBinding(t)
	store := openTestLifecycleStore(t)
	effects := newTestLifecycleEffects(t, binding)
	engine := LifecycleEngine{
		Store:        store,
		Effects:      effects,
		Storage:      allowTestStorage{},
		PollInterval: time.Millisecond,
		Now: monotonicTestClock(
			time.Date(2026, 7, 29, 12, 55, 0, 0, time.UTC),
		),
	}
	authority := &testCompensationAuthority{
		engine: &engine,
		path:   CompensationInstallUpgradePostSelection,
	}
	engine.Compensation = authority
	request := lifecycleTestRequest(
		t,
		binding,
		time.Date(2026, 7, 29, 12, 55, 0, 0, time.UTC),
	)
	prepared, err := engine.prepare(context.Background(), request)
	if err != nil {
		t.Fatalf("prepare() error = %v", err)
	}
	for prepared.journal.Phase != OperationPhaseCurrentSelected {
		if _, err := engine.ensurePhaseApplied(
			context.Background(),
			request,
			prepared,
		); err != nil {
			t.Fatalf(
				"ensurePhaseApplied(%q) error = %v",
				prepared.journal.Phase,
				err,
			)
		}
		if err := engine.advanceJournal(binding, prepared); err != nil {
			t.Fatalf(
				"advanceJournal(%q) error = %v",
				prepared.journal.Phase,
				err,
			)
		}
	}
	closeErr := errors.New("lease close failed")
	lease := &testLifecycleOperationLease{closeErr: closeErr}
	engine.leaseAcquire = func(
		context.Context,
		time.Duration,
	) (lifecycleOperationLease, error) {
		return lease, nil
	}

	result, err := engine.Recover(context.Background(), request)
	if !errors.Is(err, ErrLifecycleExecution) ||
		!errors.Is(err, closeErr) ||
		result.Status != HostActionFailed ||
		result.ErrorClass != LifecycleErrorIntegrity ||
		result.TargetProofDigest != nil ||
		lease.closeCount != 1 {
		t.Fatalf(
			"Recover() = %#v, error=%v, lease=%#v",
			result,
			err,
			lease,
		)
	}
}

func TestLifecycleEngineRecoversApplyingReceiptFromTargetReadback(t *testing.T) {
	t.Parallel()

	binding := goldenUpgradeBinding(t)
	store := openTestLifecycleStore(t)
	effects := newTestLifecycleEffects(t, binding)
	reservation := goldenStorageReservation(
		t,
		binding,
		time.Date(2026, 7, 29, 13, 0, 0, 0, time.UTC),
	)
	engine := LifecycleEngine{
		Store:        store,
		Effects:      effects,
		Storage:      allowTestStorage{},
		PollInterval: time.Millisecond,
		Now: monotonicTestClock(
			time.Date(2026, 7, 29, 13, 0, 1, 0, time.UTC),
		),
	}
	request := LifecycleRequest{
		Binding:        binding,
		PriorManifest:  goldenManifest(t),
		TargetManifest: goldenManifest(t),
		Reservation:    reservation,
	}

	if _, err := engine.prepare(context.Background(), request); err != nil {
		t.Fatalf("prepare() error = %v", err)
	}
	phase := OperationPhasePrepared
	effectKey, err := DeriveOperationEffectKey(binding, phase)
	if err != nil {
		t.Fatalf("DeriveOperationEffectKey() error = %v", err)
	}
	applying := operationApplyingReceipt(
		t,
		binding,
		phase,
		strings.Repeat("0", 64),
		time.Date(2026, 7, 29, 13, 0, 2, 0, time.UTC),
	)
	applyingDocument, _, err := MarshalOperationReceipt(applying)
	if err != nil {
		t.Fatalf("MarshalOperationReceipt() error = %v", err)
	}
	if err := store.CreateCanonical(
		LifecycleReceipts,
		lifecycleReceiptName(effectKey),
		applyingDocument,
		maxLifecycleReceiptBytes,
	); err != nil {
		t.Fatalf("CreateCanonical(applying) error = %v", err)
	}
	postcondition := effects.commitWithoutApply(t, phase)
	postconditionDocument, _, err := MarshalTargetPostcondition(postcondition)
	if err != nil {
		t.Fatalf("MarshalTargetPostcondition() error = %v", err)
	}
	if err := store.CreateCanonical(
		LifecycleReceipts,
		lifecyclePostconditionName(effectKey),
		postconditionDocument,
		maxLifecyclePostconditionBytes,
	); err != nil {
		t.Fatalf("CreateCanonical(postcondition) error = %v", err)
	}

	result, err := engine.Execute(context.Background(), request)
	if err != nil || result.Status != HostActionComplete {
		t.Fatalf("Execute() = %#v, error = %v", result, err)
	}
	if got := effects.count(phase); got != 0 {
		t.Fatalf("prepared Apply count = %d, want 0", got)
	}
}

func TestLifecycleEngineLeavesAmbiguousApplyingEffectRecoverable(t *testing.T) {
	t.Parallel()

	binding := goldenUpgradeBinding(t)
	store := openTestLifecycleStore(t)
	effects := newTestLifecycleEffects(t, binding)
	effects.ambiguous[OperationPhasePrepared] = true
	reservation := goldenStorageReservation(
		t,
		binding,
		time.Date(2026, 7, 29, 14, 0, 0, 0, time.UTC),
	)
	engine := LifecycleEngine{
		Store:        store,
		Effects:      effects,
		Storage:      allowTestStorage{},
		PollInterval: time.Millisecond,
		Now: monotonicTestClock(
			time.Date(2026, 7, 29, 14, 0, 1, 0, time.UTC),
		),
	}
	request := LifecycleRequest{
		Binding:        binding,
		PriorManifest:  goldenManifest(t),
		TargetManifest: goldenManifest(t),
		Reservation:    reservation,
	}

	result, err := engine.Execute(context.Background(), request)
	if !errors.Is(err, ErrLifecycleRecoverable) ||
		result.Status != HostActionRecoverable ||
		result.ErrorClass != LifecycleErrorAmbiguousEffect ||
		result.TargetProofDigest != nil {
		t.Fatalf("Execute() = %#v, error = %v", result, err)
	}
	journalDocument, readErr := store.ReadCanonical(
		LifecycleJournals,
		lifecycleJournalName(binding.OperationID),
		maxLifecycleJournalBytes,
	)
	if readErr != nil {
		t.Fatalf("ReadCanonical(journal) error = %v", readErr)
	}
	journal, _, parseErr := ParseOperationJournal(
		journalDocument,
		maxLifecycleJournalBytes,
	)
	if parseErr != nil || journal.Phase != OperationPhasePrepared {
		t.Fatalf("journal = %#v, error = %v", journal, parseErr)
	}
}

func TestLifecycleEngineRejectsChangedBindingForExistingOperation(t *testing.T) {
	t.Parallel()

	binding := goldenUpgradeBinding(t)
	store := openTestLifecycleStore(t)
	effects := newTestLifecycleEffects(t, binding)
	engine := LifecycleEngine{
		Store:        store,
		Effects:      effects,
		Storage:      allowTestStorage{},
		PollInterval: time.Millisecond,
		Now: monotonicTestClock(
			time.Date(2026, 7, 29, 15, 0, 0, 0, time.UTC),
		),
	}
	request := LifecycleRequest{
		Binding:        binding,
		PriorManifest:  goldenManifest(t),
		TargetManifest: goldenManifest(t),
		Reservation: goldenStorageReservation(
			t,
			binding,
			time.Date(2026, 7, 29, 15, 0, 0, 0, time.UTC),
		),
	}
	if _, err := engine.prepare(context.Background(), request); err != nil {
		t.Fatalf("prepare() error = %v", err)
	}

	changed := request
	changed.Binding.ExpectedGeneration++
	changed.Binding.OperationID = strings.Repeat("f", 64)
	result, err := engine.Execute(context.Background(), changed)
	if !errors.Is(err, ErrLifecycleExecution) ||
		result.Status != HostActionFailed ||
		result.ErrorClass != LifecycleErrorInvalidRequest {
		t.Fatalf("Execute(changed) = %#v, error = %v", result, err)
	}
}

func TestLifecycleEnginePersistsAndReplaysOneCompensationPath(t *testing.T) {
	t.Parallel()

	binding := goldenUpgradeBinding(t)
	store := openTestLifecycleStore(t)
	effects := newTestLifecycleEffects(t, binding)
	engine := LifecycleEngine{
		Store:        store,
		Effects:      effects,
		Storage:      allowTestStorage{},
		PollInterval: time.Millisecond,
		Now: monotonicTestClock(
			time.Date(2026, 7, 29, 15, 30, 0, 0, time.UTC),
		),
	}
	authority := &testCompensationAuthority{
		engine: &engine,
		path:   CompensationInstallUpgradePostSelection,
	}
	engine.Compensation = authority
	request := LifecycleRequest{
		Binding:        binding,
		PriorManifest:  goldenManifest(t),
		TargetManifest: goldenManifest(t),
		Reservation: goldenStorageReservation(
			t,
			binding,
			time.Date(2026, 7, 29, 15, 30, 0, 0, time.UTC),
		),
	}
	prepared, err := engine.prepare(context.Background(), request)
	if err != nil {
		t.Fatalf("prepare() error = %v", err)
	}
	for prepared.journal.Phase != OperationPhaseCurrentSelected {
		if _, err := engine.ensurePhaseApplied(
			context.Background(),
			request,
			prepared,
		); err != nil {
			t.Fatalf(
				"ensurePhaseApplied(%q) error = %v",
				prepared.journal.Phase,
				err,
			)
		}
		if err := engine.advanceJournal(binding, prepared); err != nil {
			t.Fatalf(
				"advanceJournal(%q) error = %v",
				prepared.journal.Phase,
				err,
			)
		}
	}

	result, err := engine.Recover(context.Background(), request)
	if err != nil ||
		result.Status != HostActionCompensated ||
		result.TargetProofDigest != nil ||
		result.ErrorClass != "compensated" ||
		authority.calls != 1 {
		t.Fatalf(
			"Recover() = %#v, error=%v, authority calls=%d",
			result,
			err,
			authority.calls,
		)
	}
	counts := effects.countsCopy()
	replay, err := engine.Execute(context.Background(), request)
	if err != nil ||
		replay.Status != HostActionCompensated ||
		authority.calls != 1 ||
		!equalPhaseCounts(counts, effects.countsCopy()) {
		t.Fatalf(
			"Execute(replay) = %#v, error=%v, authority calls=%d",
			replay,
			err,
			authority.calls,
		)
	}
	journalDocument, err := store.ReadCanonical(
		LifecycleJournals,
		lifecycleJournalName(binding.OperationID),
		maxLifecycleJournalBytes,
	)
	if err != nil {
		t.Fatalf("ReadCanonical(journal) error = %v", err)
	}
	journal, _, err := ParseOperationJournal(
		journalDocument,
		maxLifecycleJournalBytes,
	)
	if err != nil ||
		journal.CompensationPath == nil ||
		*journal.CompensationPath !=
			CompensationInstallUpgradePostSelection ||
		!terminalOperationJournal(journal) {
		t.Fatalf("compensated journal = %#v, error=%v", journal, err)
	}
}

type allowTestStorage struct{}

func (allowTestStorage) Revalidate(
	context.Context,
	StorageReservation,
) error {
	return nil
}

type testLifecycleOperationLease struct {
	validateErr    error
	validateErrors []error
	closeErr       error
	validateCount  int
	closeCount     int
}

func (lease *testLifecycleOperationLease) Validate() error {
	lease.validateCount++
	if lease.validateCount <= len(lease.validateErrors) {
		return lease.validateErrors[lease.validateCount-1]
	}
	return lease.validateErr
}

func (lease *testLifecycleOperationLease) Close() error {
	lease.closeCount++
	return lease.closeErr
}

func lifecycleTestRequest(
	t *testing.T,
	binding OperationBinding,
	now time.Time,
) LifecycleRequest {
	t.Helper()
	return LifecycleRequest{
		Binding:        binding,
		PriorManifest:  goldenManifest(t),
		TargetManifest: goldenManifest(t),
		Reservation:    goldenStorageReservation(t, binding, now),
	}
}

type testCompensationAuthority struct {
	engine *LifecycleEngine
	path   CompensationPath
	calls  int
}

func (authority *testCompensationAuthority) AuthorizeCompensation(
	_ context.Context,
	binding OperationBinding,
	journal OperationJournal,
	source TargetPostcondition,
) (CompensationAuthorization, error) {
	authority.calls++
	_, sourceProofDigest, err := MarshalTargetPostcondition(source)
	if err != nil {
		return CompensationAuthorization{}, err
	}
	receiptDigest, sourcePhase, err :=
		authority.engine.compensationSourceAnchor(binding, authority.path)
	if err != nil {
		return CompensationAuthorization{}, err
	}
	return CompensationAuthorization{
		path:                authority.path,
		sourcePhase:         sourcePhase,
		sourceProofDigest:   sourceProofDigest,
		sourceReceiptDigest: receiptDigest,
	}, nil
}

type testLifecycleEffects struct {
	t         *testing.T
	binding   OperationBinding
	mu        sync.Mutex
	applied   map[OperationPhase]TargetPostcondition
	counts    map[OperationPhase]int
	ambiguous map[OperationPhase]bool
}

func newTestLifecycleEffects(
	t *testing.T,
	binding OperationBinding,
) *testLifecycleEffects {
	t.Helper()
	return &testLifecycleEffects{
		t:         t,
		binding:   binding,
		applied:   make(map[OperationPhase]TargetPostcondition),
		counts:    make(map[OperationPhase]int),
		ambiguous: make(map[OperationPhase]bool),
	}
}

func (effects *testLifecycleEffects) Observe(
	_ context.Context,
	binding OperationBinding,
	phase OperationPhase,
) (LifecycleEffectObservation, error) {
	effects.mu.Lock()
	defer effects.mu.Unlock()
	if effects.ambiguous[phase] {
		return LifecycleEffectObservation{
			State: LifecycleEffectAmbiguous,
		}, nil
	}
	postcondition, ok := effects.applied[phase]
	if !ok {
		return LifecycleEffectObservation{
			State: LifecycleEffectAbsent,
		}, nil
	}
	return LifecycleEffectObservation{
		State:         LifecycleEffectPresent,
		Postcondition: &postcondition,
	}, nil
}

func (effects *testLifecycleEffects) Apply(
	_ context.Context,
	binding OperationBinding,
	phase OperationPhase,
) (TargetPostcondition, error) {
	effects.mu.Lock()
	defer effects.mu.Unlock()
	effects.counts[phase]++
	postcondition := testPostconditionForPhase(
		effects.t,
		binding,
		phase,
		time.Date(
			2026,
			7,
			29,
			16,
			0,
			effects.counts[phase],
			0,
			time.UTC,
		),
	)
	effects.applied[phase] = postcondition
	return postcondition, nil
}

func (effects *testLifecycleEffects) commitWithoutApply(
	t *testing.T,
	phase OperationPhase,
) TargetPostcondition {
	t.Helper()
	effects.mu.Lock()
	defer effects.mu.Unlock()
	postcondition := testPostconditionForPhase(
		t,
		effects.binding,
		phase,
		time.Date(2026, 7, 29, 16, 30, 0, 0, time.UTC),
	)
	effects.applied[phase] = postcondition
	return postcondition
}

func (effects *testLifecycleEffects) count(phase OperationPhase) int {
	effects.mu.Lock()
	defer effects.mu.Unlock()
	return effects.counts[phase]
}

func (effects *testLifecycleEffects) countsCopy() map[OperationPhase]int {
	effects.mu.Lock()
	defer effects.mu.Unlock()
	result := make(map[OperationPhase]int, len(effects.counts))
	for phase, count := range effects.counts {
		result[phase] = count
	}
	return result
}

func equalPhaseCounts(
	left map[OperationPhase]int,
	right map[OperationPhase]int,
) bool {
	if len(left) != len(right) {
		return false
	}
	for phase, count := range left {
		if right[phase] != count {
			return false
		}
	}
	return true
}

func testPostconditionForPhase(
	t *testing.T,
	binding OperationBinding,
	phase OperationPhase,
	observed time.Time,
) TargetPostcondition {
	t.Helper()
	effectKey, err := DeriveOperationEffectKey(binding, phase)
	if err != nil {
		t.Fatalf("DeriveOperationEffectKey(%q) error = %v", phase, err)
	}
	postcondition := goldenPostcondition(t, binding, effectKey)
	postcondition.Phase = phase
	postcondition.ObservedAt = observed
	if phase == OperationPhaseCurrentSelected ||
		phase == OperationPhaseVerified {
		postcondition.CurrentSelection = &CurrentSelectionProjection{
			ReleaseDirectoryDeviceMajor: 8,
			ReleaseDirectoryDeviceMinor: 1,
			ReleaseDirectoryInode:       100,
			SymlinkDeviceMajor:          8,
			SymlinkDeviceMinor:          1,
			SymlinkInode:                101,
			RelativeLinkText:            "release-a",
			ManifestDeviceMajor:         8,
			ManifestDeviceMinor:         1,
			ManifestInode:               102,
			ManifestDigest:              *binding.TargetManifestDigest,
			FenceGeneration:             binding.ExpectedGeneration,
			ActiveFleet:                 binding.TargetFleet,
		}
	}
	return postcondition
}

func operationApplyingReceipt(
	t *testing.T,
	binding OperationBinding,
	phase OperationPhase,
	prior string,
	now time.Time,
) OperationReceipt {
	t.Helper()
	effectKey, err := DeriveOperationEffectKey(binding, phase)
	if err != nil {
		t.Fatalf("DeriveOperationEffectKey() error = %v", err)
	}
	return OperationReceipt{
		SchemaVersion:             1,
		OperationID:               binding.OperationID,
		BindingDigest:             goldenBindingDigestFor(t, binding),
		EffectKey:                 effectKey,
		Phase:                     phase,
		State:                     ReceiptStateApplying,
		PriorReceiptDigest:        prior,
		TargetPostconditionDigest: nil,
		CreatedAt:                 now,
		UpdatedAt:                 now,
	}
}

func openTestLifecycleStore(t *testing.T) *LifecycleStore {
	t.Helper()
	store, err := OpenLifecycleStore(makeLifecycleRoot(t), true)
	if err != nil {
		t.Fatalf("OpenLifecycleStore() error = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("LifecycleStore.Close() error = %v", err)
		}
	})
	return store
}

func goldenManifest(t *testing.T) *RuntimeManifest {
	t.Helper()
	manifest, _, err := ParseRuntimeManifest(
		[]byte(validRuntimeManifestJSON),
		len(validRuntimeManifestJSON),
	)
	if err != nil {
		t.Fatalf("ParseRuntimeManifest() error = %v", err)
	}
	return &manifest
}

func monotonicTestClock(start time.Time) func() time.Time {
	var mu sync.Mutex
	current := start.Add(-time.Nanosecond)
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		current = current.Add(time.Nanosecond)
		return current
	}
}
