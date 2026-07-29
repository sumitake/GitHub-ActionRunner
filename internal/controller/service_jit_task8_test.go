package controller

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/githubscale"
	"github.com/sumitake/portable-ghar/internal/redaction"
)

type task8JITSession struct {
	*fakeSession

	mu       sync.Mutex
	calls    []githubscale.JITRequest
	config   githubscale.JITConfig
	err      error
	entered  chan struct{}
	release  chan struct{}
	waitDone bool
}

func (s *task8JITSession) GenerateJIT(
	ctx context.Context,
	request githubscale.JITRequest,
) (githubscale.JITConfig, error) {
	s.mu.Lock()
	s.calls = append(s.calls, request)
	entered, release, waitDone := s.entered, s.release, s.waitDone
	config, err := s.config, s.err
	s.mu.Unlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if release != nil {
		if waitDone {
			<-ctx.Done()
		}
		<-release
	}
	return config, err
}

func (s *task8JITSession) Calls() []githubscale.JITRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]githubscale.JITRequest(nil), s.calls...)
}

func TestGenerateJITAuthorizedBindsCurrentAcquiredReservation(t *testing.T) {
	t.Parallel()

	service, request, session, _, _ := newTask8JITFixture(t)
	config, err := service.GenerateJITAuthorized(context.Background(), request)
	if err != nil {
		t.Fatalf("GenerateJITAuthorized: %v", err)
	}
	if config.Runner.ID != 71 || config.Runner.Name != request.RunnerName ||
		config.Encoded == nil {
		t.Fatalf("config = %+v", config)
	}
	defer config.Encoded.Destroy()
	if got := session.Calls(); len(got) != 1 || got[0] != request.Request {
		t.Fatalf("GenerateJIT calls = %+v", got)
	}
}

func TestGenerateJITAuthorizedRejectsEveryStaleDurableBindingBeforeCall(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*JITAuthorizationRequest, *fakeDurableState, *fakeAdmissionBroker)
	}{
		{
			name: "not acquired",
			mutate: func(request *JITAuthorizationRequest, state *fakeDurableState, _ *fakeAdmissionBroker) {
				state.acquisitionOutcomes[request.Assignment.Key] = AssignmentAcquisitionRecord{
					Key:     request.Assignment.Key,
					Outcome: AssignmentRejected,
				}
			},
		},
		{
			name: "revoked",
			mutate: func(request *JITAuthorizationRequest, state *fakeDurableState, _ *fakeAdmissionBroker) {
				state.acquisitionOutcomes[request.Assignment.Key] = AssignmentAcquisitionRecord{
					Key:          request.Assignment.Key,
					Outcome:      AssignmentAcquired,
					RevokedEpoch: 99,
				}
			},
		},
		{
			name: "wrong lifecycle state",
			mutate: func(_ *JITAuthorizationRequest, state *fakeDurableState, _ *fakeAdmissionBroker) {
				state.recoverable[0].State = StateJobRunning
			},
		},
		{
			name: "wrong slot",
			mutate: func(_ *JITAuthorizationRequest, state *fakeDurableState, _ *fakeAdmissionBroker) {
				state.recoverable[0].Slot.CapacitySlotID++
			},
		},
		{
			name: "wrong durable admission",
			mutate: func(_ *JITAuthorizationRequest, state *fakeDurableState, _ *fakeAdmissionBroker) {
				state.recoverable[0].Admission.SlotID++
			},
		},
		{
			name: "missing live reference",
			mutate: func(_ *JITAuthorizationRequest, _ *fakeDurableState, broker *fakeAdmissionBroker) {
				broker.referencePresent = false
				broker.live = false
			},
		},
		{
			name: "wrong live reference",
			mutate: func(_ *JITAuthorizationRequest, _ *fakeDurableState, broker *fakeAdmissionBroker) {
				broker.reference.SlotID++
			},
		},
		{
			name: "wrong scale set",
			mutate: func(request *JITAuthorizationRequest, _ *fakeDurableState, _ *fakeAdmissionBroker) {
				request.ScaleSetName = "other-scale-set"
			},
		},
		{
			name: "wrong runner name",
			mutate: func(request *JITAuthorizationRequest, _ *fakeDurableState, _ *fakeAdmissionBroker) {
				request.RunnerName = "pghar-slot-invalid-fixture"
				request.Request.RunnerName = request.RunnerName
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service, request, session, state, broker := newTask8JITFixture(t)
			test.mutate(&request, state, broker)
			config, err := service.GenerateJITAuthorized(context.Background(), request)
			if err == nil {
				if config.Encoded != nil {
					config.Encoded.Destroy()
				}
				t.Fatal("GenerateJITAuthorized succeeded")
			}
			if got := session.Calls(); len(got) != 0 {
				t.Fatalf("GenerateJIT called for stale binding: %+v", got)
			}
		})
	}
}

func TestGenerateJITAuthorizedMarksPostBoundaryFailuresAmbiguous(t *testing.T) {
	t.Parallel()

	t.Run("provider error", func(t *testing.T) {
		service, request, session, _, _ := newTask8JITFixture(t)
		session.err = errors.New("upstream failed")
		_, err := service.GenerateJITAuthorized(context.Background(), request)
		if !errors.Is(err, ErrJITMayHaveActed) {
			t.Fatalf("err = %v, want ErrJITMayHaveActed", err)
		}
		if len(session.Calls()) != 1 {
			t.Fatalf("GenerateJIT calls = %d, want 1", len(session.Calls()))
		}
	})

	t.Run("authority close", func(t *testing.T) {
		service, request, session, _, _ := newTask8JITFixture(t)
		permit := &task8RecordingGuard{err: errors.New("close failed")}
		service.permits = &task8PermitProvider{guard: permit}
		_, err := service.GenerateJITAuthorized(context.Background(), request)
		if !errors.Is(err, ErrJITMayHaveActed) ||
			!errors.Is(err, ErrAcquisitionGuardClose) {
			t.Fatalf("err = %v, want ambiguous close failure", err)
		}
		if session.config.Encoded == nil ||
			!errors.Is(
				session.config.Encoded.Use(func(_ io.Reader) error {
					return nil
				}),
				redaction.ErrSecretScopeClosed,
			) {
			t.Fatal("secret was not destroyed after post-call authority failure")
		}
	})
}

func newTask8JITFixture(
	t *testing.T,
) (
	*Service,
	JITAuthorizationRequest,
	*task8JITSession,
	*fakeDurableState,
	*fakeAdmissionBroker,
) {
	t.Helper()
	now := time.Date(2026, 7, 28, 23, 0, 0, 0, time.UTC)
	key := AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 9301}
	offer := githubscale.Offer{JobRef: githubscale.JobRef{
		RunnerRequestID: key.RunnerRequestID,
		JobID:           "job-jit",
		RequestLabels:   []string{"portable-ghar"},
	}}
	slot := RunnerSlot{
		OpaqueName:         OpaqueSlotName(key),
		CapacitySlotID:     17,
		AdapterContainerID: "adapter-id",
		BrokerContainerID:  "broker-id",
		RunnerContainerID:  "runner-id",
	}
	assignment, err := NewAssignment(key, offer, slot)
	if err != nil {
		t.Fatalf("NewAssignment: %v", err)
	}
	ref := AdmissionReference{
		Key:             key,
		Offer:           offer,
		Phase:           AdmissionActive,
		SlotID:          slot.CapacitySlotID,
		FullCharge:      task8JITResources(2),
		LedgerCharge:    task8JITResources(1),
		LedgerCreatedAt: now.Add(-time.Minute),
		LedgerEverUsed:  true,
	}
	durableRef := ref
	durableRef.Offer = githubscale.Offer{}
	state := &fakeDurableState{
		recoverable: []RecoverableAssignment{{
			Key:       key,
			State:     StateReleaseArmed,
			Offer:     offer,
			Admission: durableRef,
			Slot:      slot,
			UpdatedAt: now.Add(-time.Minute),
		}},
		acquisitionOutcomes: map[AssignmentKey]AssignmentAcquisitionRecord{
			key: {Key: key, Outcome: AssignmentAcquired},
		},
	}
	broker := &fakeAdmissionBroker{
		reference:        ref,
		referencePresent: true,
		live:             true,
	}
	service, _ := startPollService(
		t,
		now,
		nil,
		state,
		broker,
		&fakeEventRecorder{},
	)
	encoded := redaction.SecretFromBytes([]byte("one-use-jit"))
	session := &task8JITSession{
		fakeSession: &fakeSession{},
		config: githubscale.JITConfig{
			Runner:  githubscale.RunnerRef{ID: 71, Name: slot.OpaqueName},
			Encoded: encoded,
		},
	}
	request := JITAuthorizationRequest{
		Assignment:   assignment,
		ScaleSetName: "portable-ghar",
		Session:      session,
		RunnerName:   slot.OpaqueName,
		Request: githubscale.JITRequest{
			RunnerName: slot.OpaqueName,
			WorkFolder: "_work",
		},
	}
	return service, request, session, state, broker
}

func task8JITResources(multiplier int64) ResourceProjection {
	return ResourceProjection{
		MilliCPU:          multiplier,
		MemoryBytes:       multiplier,
		PIDs:              multiplier,
		FileDescriptors:   multiplier,
		TmpfsBytes:        multiplier,
		ScratchBytes:      multiplier,
		SocketStateBytes:  multiplier,
		DurableStateBytes: multiplier,
		Inodes:            multiplier,
	}
}
