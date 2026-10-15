package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/health"
	"github.com/sumitake/portable-ghar/internal/observability"
)

func TestFixedHostCapacityReportsTheOverlayCapacity(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	provider := fixedHostCapacity{capacity: 1, evidence: strings.Repeat("c", 64), now: func() time.Time { return now }}
	report, err := provider.Evaluate(context.Background())
	if err != nil || report.State != controller.HostCapacityNormal ||
		report.EffectiveCapacity != 1 || !report.ObservedAt.Equal(now) {
		t.Fatalf("Evaluate = %+v, %v", report, err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := provider.Evaluate(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("Evaluate on a canceled context = %v, want the cancellation", err)
	}
}

func TestProcessTerminatorFiresOnceAndCancelsTheRun(t *testing.T) {
	var stderr bytes.Buffer
	cancels := 0
	terminator := &processTerminator{stderr: &stderr, cancel: func() { cancels++ }}
	if terminator.Fired() {
		t.Fatal("terminator fired before any fatal state")
	}
	terminator.TerminateAfterPersist(controller.ReasonCode(3))
	terminator.TerminateAfterPersist(controller.ReasonCode(4))
	if !terminator.Fired() || cancels != 1 ||
		strings.Count(stderr.String(), "fatal reason") != 1 ||
		!strings.Contains(stderr.String(), "fatal reason 3") {
		t.Fatalf("fired %v, cancels %d, stderr %q", terminator.Fired(), cancels, stderr.String())
	}
}

func TestLogEventSinkWritesOnlyValidEvents(t *testing.T) {
	var out bytes.Buffer
	sink := &logEventSink{out: &out}
	event := observability.Event{
		Kind:    observability.EventHistoryPressureEvaluated,
		Reasons: observability.PressureReasonHistoryRows,
		Snapshot: health.HistorySnapshot{
			ObservedAt:          time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
			Pressure:            health.PressureWarning,
			OldestRetainedAge:   time.Minute,
			EffectiveCapacity:   1,
			PolicyEpoch:         9,
			HistoryRows:         10,
			HistoryLogicalBytes: 11,
		},
	}
	if err := sink.Emit(context.Background(), event); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n"); len(lines) != 1 ||
		!strings.HasPrefix(lines[0], "{") {
		t.Fatalf("output = %q, want one JSON line", out.String())
	}
	out.Reset()
	if err := sink.Emit(context.Background(), observability.Event{}); err == nil || out.Len() != 0 {
		t.Fatalf("Emit(invalid) = %v, wrote %q", err, out.String())
	}
}

type recordingJITAuthorizer struct{ calls int }

func (authorizer *recordingJITAuthorizer) GenerateJITAuthorized(
	context.Context,
	controller.JITAuthorizationRequest,
) (controller.JITAuthorizationResult, error) {
	authorizer.calls++
	return controller.JITAuthorizationResult{}, nil
}

func TestJITAuthorizerSlotRefusesUntilSet(t *testing.T) {
	slot := &jitAuthorizerSlot{}
	if _, err := slot.GenerateJITAuthorized(
		context.Background(),
		controller.JITAuthorizationRequest{},
	); !errors.Is(err, controller.ErrServiceNotReady) {
		t.Fatalf("unset slot error = %v, want ErrServiceNotReady", err)
	}
	target := &recordingJITAuthorizer{}
	slot.Set(target)
	if _, err := slot.GenerateJITAuthorized(
		context.Background(),
		controller.JITAuthorizationRequest{},
	); err != nil || target.calls != 1 {
		t.Fatalf("set slot = %v, calls %d", err, target.calls)
	}
}

func TestNonBlockingLogNeverBlocksAndKeepsOrder(t *testing.T) {
	blocked := blockedWriter{release: make(chan struct{})}
	stalled := newNonBlockingLog(blocked)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 2 * nonBlockingLogDepth {
			if n, err := stalled.Write([]byte("line\n")); n != 5 || err != nil {
				t.Errorf("Write = %d, %v", n, err)
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Write blocked on a stalled writer")
	}
	close(blocked.release)

	lines := make(chan string, 3)
	ordered := newNonBlockingLog(writerFunc(func(p []byte) (int, error) {
		lines <- string(p)
		return len(p), nil
	}))
	for _, line := range []string{"a\n", "b\n", "c\n"} {
		_, _ = ordered.Write([]byte(line))
	}
	for _, want := range []string{"a\n", "b\n", "c\n"} {
		select {
		case got := <-lines:
			if got != want {
				t.Fatalf("line = %q, want %q", got, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("line %q not written", want)
		}
	}
}

type writerFunc func([]byte) (int, error)

func (write writerFunc) Write(p []byte) (int, error) { return write(p) }

func TestProcessTerminatorCancelsBeforeLogging(t *testing.T) {
	cancelled := false
	var loggedAfterCancel bool
	terminator := &processTerminator{
		stderr: writerFunc(func(p []byte) (int, error) {
			loggedAfterCancel = cancelled
			return len(p), nil
		}),
		cancel: func() { cancelled = true },
	}
	terminator.TerminateAfterPersist(controller.ReasonCode(3))
	if !cancelled || !loggedAfterCancel {
		t.Fatalf("cancelled %v, logged after cancel %v", cancelled, loggedAfterCancel)
	}
}
