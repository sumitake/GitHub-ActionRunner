package hostruntime

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLifecycleCompensationAuthoritySelectsExactPath(t *testing.T) {
	t.Parallel()

	engine, request, prepared, source := lifecycleCompensationFixture(t)
	authority, err := NewLifecycleCompensationAuthority(engine.Store)
	if err != nil {
		t.Fatalf("NewLifecycleCompensationAuthority() error = %v", err)
	}
	authorization, err := authority.AuthorizeCompensation(
		context.Background(),
		request.Binding,
		prepared.journal,
		source,
	)
	if err != nil {
		t.Fatalf("AuthorizeCompensation() error = %v", err)
	}
	if authorization.path != CompensationInstallUpgradePostSelection ||
		authorization.sourcePhase != OperationPhaseCurrentSelected ||
		authorization.sourceProofDigest == "" ||
		authorization.sourceReceiptDigest == "" {
		t.Fatalf("authorization = %#v", authorization)
	}
	if err := engine.validateCompensationAuthorization(
		request.Binding,
		prepared.journal,
		source,
		authorization,
	); err != nil {
		t.Fatalf("validateCompensationAuthorization() error = %v", err)
	}
}

func TestLifecycleCompensationAuthorityRejectsUnboundSource(t *testing.T) {
	t.Parallel()

	engine, request, prepared, source := lifecycleCompensationFixture(t)
	authority, err := NewLifecycleCompensationAuthority(engine.Store)
	if err != nil {
		t.Fatalf("NewLifecycleCompensationAuthority() error = %v", err)
	}

	source.OperationID = strings.Repeat("f", 64)
	if _, err := authority.AuthorizeCompensation(
		context.Background(),
		request.Binding,
		prepared.journal,
		source,
	); !errors.Is(err, ErrLifecycleCompensationAuthority) {
		t.Fatalf("AuthorizeCompensation(tampered) error = %v", err)
	}
	if prepared.journal.CompensationPath != nil {
		t.Fatal("rejected authorization changed journal")
	}
}

func TestLifecycleCompensationAuthorityRejectsNoOrAmbiguousPath(t *testing.T) {
	t.Parallel()

	engine, request, prepared, source := lifecycleCompensationFixture(t)
	authority, err := NewLifecycleCompensationAuthority(engine.Store)
	if err != nil {
		t.Fatalf("NewLifecycleCompensationAuthority() error = %v", err)
	}

	prepared.journal.Phase = OperationPhaseVerified
	source.Phase = OperationPhaseVerified
	effectKey, err := DeriveOperationEffectKey(
		request.Binding,
		OperationPhaseVerified,
	)
	if err != nil {
		t.Fatalf("DeriveOperationEffectKey() error = %v", err)
	}
	source.EffectKey = effectKey
	if _, err := authority.AuthorizeCompensation(
		context.Background(),
		request.Binding,
		prepared.journal,
		source,
	); !errors.Is(err, ErrLifecycleCompensationAuthority) {
		t.Fatalf("AuthorizeCompensation(no path) error = %v", err)
	}
}

func TestLifecycleCompensationAuthorityEngineCrashReentryMintsOnce(
	t *testing.T,
) {
	t.Parallel()

	engine, request, prepared, _ := lifecycleCompensationFixture(t)
	authority, err := NewLifecycleCompensationAuthority(engine.Store)
	if err != nil {
		t.Fatalf("NewLifecycleCompensationAuthority() error = %v", err)
	}
	counted := &countingCompensationAuthority{delegate: authority}
	engine.Compensation = counted

	result, err := engine.Recover(context.Background(), request)
	if err != nil || result.Status != HostActionCompensated {
		t.Fatalf("Recover() = %#v, error=%v", result, err)
	}
	if counted.calls != 1 {
		t.Fatalf("AuthorizeCompensation calls = %d, want 1", counted.calls)
	}
	replay, err := engine.Recover(context.Background(), request)
	if err != nil || replay.Status != HostActionCompensated {
		t.Fatalf("Recover(replay) = %#v, error=%v", replay, err)
	}
	if counted.calls != 1 {
		t.Fatalf("replay authorization calls = %d, want 1", counted.calls)
	}
	if prepared.journal.CompensationPath != nil {
		t.Fatal("fixture journal pointer mutated outside durable store")
	}
}

type countingCompensationAuthority struct {
	delegate LifecycleCompensationAuthority
	calls    int
}

func (authority *countingCompensationAuthority) AuthorizeCompensation(
	ctx context.Context,
	binding OperationBinding,
	journal OperationJournal,
	source TargetPostcondition,
) (CompensationAuthorization, error) {
	authority.calls++
	return authority.delegate.AuthorizeCompensation(
		ctx,
		binding,
		journal,
		source,
	)
}

func lifecycleCompensationFixture(
	t *testing.T,
) (
	LifecycleEngine,
	LifecycleRequest,
	*lifecyclePrepared,
	TargetPostcondition,
) {
	t.Helper()
	binding := goldenUpgradeBinding(t)
	store := openTestLifecycleStore(t)
	effects := newTestLifecycleEffects(t, binding)
	engine := LifecycleEngine{
		Store:        store,
		Effects:      effects,
		Storage:      allowTestStorage{},
		PollInterval: time.Millisecond,
		Now: monotonicTestClock(
			time.Date(2026, 7, 30, 5, 30, 0, 0, time.UTC),
		),
	}
	request := lifecycleTestRequest(
		t,
		binding,
		time.Date(2026, 7, 30, 5, 30, 0, 0, time.UTC),
	)
	prepared, err := engine.prepare(context.Background(), request)
	if err != nil {
		t.Fatalf("prepare() error = %v", err)
	}
	for prepared.journal.Phase != OperationPhaseCurrentSelected {
		_, err = engine.ensurePhaseApplied(
			context.Background(),
			request,
			prepared,
		)
		if err != nil {
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
	source, err := engine.ensurePhaseApplied(
		context.Background(),
		request,
		prepared,
	)
	if err != nil {
		t.Fatalf("ensurePhaseApplied(current-selected) error = %v", err)
	}
	return engine, request, prepared, source
}
