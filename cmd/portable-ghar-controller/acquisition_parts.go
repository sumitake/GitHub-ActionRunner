package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/observability"
)

// fixedHostCapacity reports the overlay's capacity as always available. No
// production host-capacity probe exists yet. The canary runs at capacity 1,
// which the overlay's resource sizing already covers, and the evidence is
// the overlay revision, so a changed overlay shows in every report.
type fixedHostCapacity struct {
	capacity int
	evidence string
	now      func() time.Time
}

func (provider fixedHostCapacity) Evaluate(
	ctx context.Context,
) (controller.HostCapacityReport, error) {
	if ctx == nil || ctx.Err() != nil || provider.capacity <= 0 {
		return controller.HostCapacityReport{}, controller.ErrServiceNotReady
	}
	return controller.HostCapacityReport{
		State:             controller.HostCapacityNormal,
		EffectiveCapacity: provider.capacity,
		EvidenceDigest:    provider.evidence,
		ObservedAt:        provider.now(),
	}, nil
}

// processTerminator ends the run once the service has persisted a fatal
// state: it logs the reason and cancels the run. Service.Run treats a
// canceled context as a clean stop, so the process checks Fired and exits
// with an error instead.
type processTerminator struct {
	mu     sync.Mutex
	stderr io.Writer
	cancel context.CancelFunc
	reason *controller.ReasonCode
}

func (terminator *processTerminator) TerminateAfterPersist(reason controller.ReasonCode) {
	terminator.mu.Lock()
	defer terminator.mu.Unlock()
	if terminator.reason != nil {
		return
	}
	terminator.reason = &reason
	fmt.Fprintf(terminator.stderr, "portable-ghar-controller: fatal reason %d persisted; stopping\n", reason)
	terminator.cancel()
}

func (terminator *processTerminator) Fired() bool {
	terminator.mu.Lock()
	defer terminator.mu.Unlock()
	return terminator.reason != nil
}

// logEventSink writes each validated observability event as one JSON line.
type logEventSink struct {
	mu  sync.Mutex
	out io.Writer
}

func (sink *logEventSink) Emit(_ context.Context, event observability.Event) error {
	if err := event.Validate(); err != nil {
		return err
	}
	line, err := json.Marshal(event)
	if err != nil {
		return err
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	_, err = sink.out.Write(append(line, '\n'))
	return err
}

// jitAuthorizerSlot breaks a construction cycle: the lifecycle runtime needs
// the service as its JIT authorizer, and the service needs the lifecycle
// runtime. It refuses every request until the service is set.
type jitAuthorizerSlot struct {
	mu     sync.RWMutex
	target controller.JITAuthorizer
}

func (slot *jitAuthorizerSlot) Set(target controller.JITAuthorizer) {
	slot.mu.Lock()
	defer slot.mu.Unlock()
	slot.target = target
}

func (slot *jitAuthorizerSlot) GenerateJITAuthorized(
	ctx context.Context,
	request controller.JITAuthorizationRequest,
) (controller.JITAuthorizationResult, error) {
	slot.mu.RLock()
	target := slot.target
	slot.mu.RUnlock()
	if target == nil {
		return controller.JITAuthorizationResult{}, controller.ErrServiceNotReady
	}
	return target.GenerateJITAuthorized(ctx, request)
}
