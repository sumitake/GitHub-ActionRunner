package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestSharedFenceGuardLendsConcurrentViewsOfOneGuard(t *testing.T) {
	failure := make(chan error, 1)
	shared := newSharedFenceGuard(failure)
	defer shared.Close()

	// A heartbeat and several acquisitions hold views at once; closing one
	// leaves the others, and later ones, unaffected.
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			view, err := shared.AcquirePortable(context.Background())
			if err == nil {
				err = view.Close()
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent view: %v", err)
		}
	}
	if _, err := shared.AcquirePortable(context.Background()); err != nil {
		t.Fatalf("view after closed views: %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := shared.AcquirePortable(canceled); err == nil {
		t.Fatal("view granted on a canceled context")
	}
}

func TestSharedFenceGuardRefusesViewsOnceTheGuardFails(t *testing.T) {
	failure := make(chan error, 1)
	shared := newSharedFenceGuard(failure)
	defer shared.Close()
	renewFailure := errors.New("renew failed")
	failure <- renewFailure
	select {
	case <-shared.Lost():
	case <-time.After(time.Second):
		t.Fatal("Lost was not closed after the guard failed")
	}
	_, err := shared.AcquirePortable(context.Background())
	if !errors.Is(err, errAcquisitionFenceLost) || !errors.Is(err, renewFailure) {
		t.Fatalf("view after failure = %v, want the fence-lost error and its cause", err)
	}
}

func TestSharedFenceGuardCloseStopsWatchingWithoutReportingLoss(t *testing.T) {
	shared := newSharedFenceGuard(make(chan error))
	if err := shared.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := shared.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	select {
	case <-shared.Lost():
		t.Fatal("Close reported the guard as lost")
	case <-time.After(10 * time.Millisecond):
	}
}

func TestSharedFenceViewReportsALossThatHappenedWhileHeld(t *testing.T) {
	failure := make(chan error, 1)
	shared := newSharedFenceGuard(failure)
	defer shared.Close()
	view, err := shared.AcquirePortable(context.Background())
	if err != nil {
		t.Fatalf("AcquirePortable: %v", err)
	}
	failure <- errors.New("renew failed")
	<-shared.Lost()
	if err := view.Close(); !errors.Is(err, errAcquisitionFenceLost) {
		t.Fatalf("view Close after loss = %v, want the fence-lost error", err)
	}
}
