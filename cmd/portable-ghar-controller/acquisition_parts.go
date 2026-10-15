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
	if ctx == nil || provider.capacity <= 0 {
		return controller.HostCapacityReport{}, controller.ErrServiceNotReady
	}
	// A cancelled caller gets its cancellation back, which the service's
	// loops treat as a stop rather than a failure.
	if err := ctx.Err(); err != nil {
		return controller.HostCapacityReport{}, err
	}
	return controller.HostCapacityReport{
		State:             controller.HostCapacityNormal,
		EffectiveCapacity: provider.capacity,
		EvidenceDigest:    provider.evidence,
		ObservedAt:        provider.now(),
	}, nil
}

// processTerminator ends the run once the service has persisted a fatal
// state: it cancels the run, then logs the reason. Service.Run treats a
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
	terminator.cancel()
	fmt.Fprintf(terminator.stderr, "portable-ghar-controller: fatal reason %d persisted; stopping\n", reason)
}

func (terminator *processTerminator) Fired() bool {
	terminator.mu.Lock()
	defer terminator.mu.Unlock()
	return terminator.reason != nil
}

// nonBlockingLog hands each write to one goroutine that copies it to out.
// Write never blocks: when the queue is full the line is dropped. A stalled
// stderr can then lose log lines, but never stall reconciliation, a fatal
// stop, or shutdown, which all write here.
type nonBlockingLog struct {
	lines chan []byte
}

// nonBlockingLogDepth is how many lines may wait for a slow stderr.
const nonBlockingLogDepth = 256

func newNonBlockingLog(out io.Writer) *nonBlockingLog {
	log := &nonBlockingLog{lines: make(chan []byte, nonBlockingLogDepth)}
	go func() {
		for line := range log.lines {
			_, _ = out.Write(line)
		}
	}()
	return log
}

func (log *nonBlockingLog) Write(p []byte) (int, error) {
	select {
	case log.lines <- append([]byte(nil), p...):
	default:
	}
	return len(p), nil
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
