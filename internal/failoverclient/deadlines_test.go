package failoverclient

import (
	"testing"
	"time"
)

func TestOperationDeadlineUsesTheEarlierBound(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	lease := now.Add(10 * time.Second)
	got, err := OperationDeadline(now, lease, 3*time.Second, time.Second)
	if err != nil {
		t.Fatalf("OperationDeadline: %v", err)
	}
	if !got.Equal(now.Add(3 * time.Second)) {
		t.Fatalf("got %s", got)
	}
	got, err = OperationDeadline(now, lease, 20*time.Second, time.Second)
	if err != nil {
		t.Fatalf("lease-bound: %v", err)
	}
	if !got.Equal(lease.Add(-time.Second)) {
		t.Fatalf("got %s", got)
	}
	if _, err := OperationDeadline(now, now.Add(time.Second), time.Second, time.Second); err == nil {
		t.Fatal("accepted zero slack")
	}
}

func TestListenerAuthorizationBindsSessionGenerationAndDeadline(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 5, 0, time.UTC)
	deadline := now.Add(time.Second)
	if !ListenerAuthorized(now, deadline, "sess", 3, "sess", 3) {
		t.Fatal("current listener rejected")
	}
	if ListenerAuthorized(deadline, deadline, "sess", 3, "sess", 3) {
		t.Fatal("exact deadline remained authorized")
	}
	if ListenerAuthorized(now, deadline, "sess", 3, "other", 3) {
		t.Fatal("superseded session authorized")
	}
	if ListenerAuthorized(now, deadline, "sess", 3, "sess", 4) {
		t.Fatal("superseded generation authorized")
	}
}
