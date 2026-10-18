package failoverclient

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCanaryGenerationReadsAuthenticatedEnrollmentWithoutAnotherSession(t *testing.T) {
	var absent *HeartbeatSession
	if absent.CurrentLeaseGeneration() != 0 {
		t.Fatal("nil session supplied generation")
	}
	f := newHeartbeatSessionFixture(t)
	if f.session.CurrentLeaseGeneration() != 0 {
		t.Fatal("unenrolled session supplied generation")
	}
	f.transport.steps = []heartbeatStep{f.sessionStep(strings.Repeat("c", 64), 1, 4), f.noLeaseStep(4), f.noLeaseStep(5)}
	if err := f.session.Publish(context.Background(), heartbeatHealthSnapshot()); err != nil {
		t.Fatal(err)
	}
	if f.session.CurrentLeaseGeneration() != 4 {
		t.Fatal("authenticated session generation lost")
	}
	if err := f.session.Publish(context.Background(), heartbeatHealthSnapshot()); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if f.session.CurrentLeaseGeneration() != 5 {
			t.Fatal("authenticated maintenance generation lost")
		}
	}
	if len(f.sessionRequests()) != 1 || len(f.heartbeatRequests()) != 2 {
		t.Fatal("readback created transport work")
	}
	if err := f.session.Close(); err != nil {
		t.Fatal(err)
	}
	if f.session.CurrentLeaseGeneration() != 0 {
		t.Fatal("closed session supplied generation")
	}
}

func TestCanaryGenerationReadDoesNotWaitForPublishNetwork(t *testing.T) {
	for _, phase := range []string{"enrollment", "heartbeat"} {
		t.Run(phase, func(t *testing.T) {
			f := newHeartbeatSessionFixture(t)
			entered := make(chan struct{})
			release := make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			gate := func(step heartbeatStep) heartbeatStep {
				return func(exchange heartbeatExchange) (*http.Response, error) {
					close(entered)
					<-release
					return step(exchange)
				}
			}
			var before, after uint64
			if phase == "enrollment" {
				f.transport.steps = []heartbeatStep{
					gate(f.sessionStep(strings.Repeat("c", 64), 1, 4)), f.noLeaseStep(4),
				}
				after = 4
			} else {
				f.transport.steps = []heartbeatStep{
					f.sessionStep(strings.Repeat("c", 64), 1, 4), f.noLeaseStep(4),
					gate(f.noLeaseStep(5)),
				}
				if err := f.session.Publish(context.Background(), heartbeatHealthSnapshot()); err != nil {
					t.Fatal(err)
				}
				before, after = 4, 5
			}
			published := make(chan error, 1)
			go func() { published <- f.session.Publish(context.Background(), heartbeatHealthSnapshot()) }()
			joined := false
			defer func() {
				unblock()
				if !joined {
					<-published
				}
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("Publish did not enter the gated transport")
			}
			read := make(chan uint64, 1)
			go func() { read <- f.session.CurrentLeaseGeneration() }()
			select {
			case generation := <-read:
				if generation != before {
					t.Fatalf("in-flight generation = %d, want completed snapshot %d", generation, before)
				}
			case <-time.After(time.Second):
				t.Fatal("generation read waited for Publish network I/O")
			}
			unblock()
			err := <-published
			joined = true
			if err != nil {
				t.Fatal(err)
			}
			if generation := f.session.CurrentLeaseGeneration(); generation != after {
				t.Fatalf("completed generation = %d, want %d", generation, after)
			}
			wantHeartbeats := 1
			if phase == "heartbeat" {
				wantHeartbeats = 2
			}
			if len(f.sessionRequests()) != 1 || len(f.heartbeatRequests()) != wantHeartbeats {
				t.Fatal("metadata read created transport work")
			}
		})
	}
}

func TestCanaryGenerationSnapshotPreservesFailedPublishEnrollmentSemantics(t *testing.T) {
	f := newHeartbeatSessionFixture(t)
	f.transport.steps = []heartbeatStep{
		f.sessionStep(strings.Repeat("c", 64), 1, 4),
		func(heartbeatExchange) (*http.Response, error) {
			return nil, errors.New("synthetic transport failure")
		},
		f.noLeaseStep(3), // Authenticated regression discards the retained enrollment.
	}
	if err := f.session.Publish(context.Background(), heartbeatHealthSnapshot()); err == nil {
		t.Fatal("transport failure was accepted")
	}
	if generation := f.session.CurrentLeaseGeneration(); generation != 4 {
		t.Fatalf("retained authenticated enrollment = %d, want 4", generation)
	}
	if err := f.session.Publish(context.Background(), heartbeatHealthSnapshot()); err == nil {
		t.Fatal("regressing generation was accepted")
	}
	if generation := f.session.CurrentLeaseGeneration(); generation != 0 {
		t.Fatalf("discarded enrollment supplied generation %d", generation)
	}
	if len(f.sessionRequests()) != 1 || len(f.heartbeatRequests()) != 2 {
		t.Fatal("metadata read created transport work")
	}
}
