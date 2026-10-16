package failoverclient

import (
	"context"
	"strings"
	"testing"
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
