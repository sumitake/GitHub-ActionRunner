package failoverclient

import (
	"errors"
	"math"
	"strings"
	"sync"
	"testing"
	"time"
)

func cachedLeaseForTest(t *testing.T, lease AcquisitionLeaseV1, sequence, fence uint64, anchor, deadline time.Time) CachedLease {
	t.Helper()
	key, err := lease.AdmissionAuthorityKey()
	if err != nil {
		t.Fatalf("AdmissionAuthorityKey: %v", err)
	}
	return CachedLease{
		Lease:         lease,
		Key:           key,
		Sequence:      sequence,
		Fence:         fence,
		LocalDeadline: deadline,
		SendAnchor:    anchor,
	}
}

func TestLeaseCacheDeepCopiesIngressSnapshotAndRevalidation(t *testing.T) {
	anchor := time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC)
	lease := testLease(LeaseCanaryOnly)
	lease.ArchivedDisabledAliases = []string{"repo-a", "repo-b"}
	next := cachedLeaseForTest(t, lease, 1, 7, anchor, anchor.Add(5*time.Second))
	cache := &LeaseCache{}

	revision, err := cache.CompareAndSwap(0, &next)
	if err != nil {
		t.Fatalf("CompareAndSwap: %v", err)
	}
	next.Lease.ArchivedDisabledAliases[0] = "mutated-input"
	*next.Lease.CanaryScaleSet = "mutated-input"

	first, err := cache.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if first.MutationRevision != revision || first.Lease.ArchivedDisabledAliases[0] != "repo-a" ||
		first.Lease.CanaryScaleSet == nil || *first.Lease.CanaryScaleSet != "canary-set" {
		t.Fatalf("ingress aliasing changed cache: %+v", first)
	}
	first.Lease.ArchivedDisabledAliases[0] = "mutated-snapshot"
	*first.Lease.CanaryScaleSet = "mutated-snapshot"

	second, err := cache.Revalidate(first.AuthorityToken)
	if err != nil {
		t.Fatalf("Revalidate: %v", err)
	}
	if second.Lease.ArchivedDisabledAliases[0] != "repo-a" ||
		second.Lease.CanaryScaleSet == nil || *second.Lease.CanaryScaleSet != "canary-set" {
		t.Fatalf("snapshot aliasing changed cache: %+v", second)
	}
}

func TestLeaseCacheRejectsWrongDerivedKeyWithoutMutation(t *testing.T) {
	anchor := time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC)
	next := cachedLeaseForTest(t, testLease(LeaseEnabled), 1, 7, anchor, anchor.Add(5*time.Second))
	next.Key = "caller-controlled"
	cache := &LeaseCache{}

	if _, err := cache.CompareAndSwap(0, &next); !errors.Is(err, ErrLeaseCache) {
		t.Fatalf("wrong key error = %v", err)
	}
	if _, err := cache.Snapshot(); !errors.Is(err, ErrLeaseCache) {
		t.Fatalf("wrong key mutated cache: %v", err)
	}

	next.Key, _ = next.Lease.AdmissionAuthorityKey()
	revision, err := cache.CompareAndSwap(0, &next)
	if err != nil || revision != 1 {
		t.Fatalf("valid install = (%d, %v), want (1, nil)", revision, err)
	}
}

func TestLeaseCachePreservesEmptyArchiveArrayInAuthorityKey(t *testing.T) {
	anchor := time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC)
	lease := testLease(LeaseEnabled)
	lease.ArchivedDisabledAliases = []string{}
	next := cachedLeaseForTest(t, lease, 1, 7, anchor, anchor.Add(5*time.Second))
	cache := &LeaseCache{}

	if _, err := cache.CompareAndSwap(0, &next); err != nil {
		t.Fatalf("empty archive array rejected: %v", err)
	}
	snapshot, err := cache.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snapshot.Lease.ArchivedDisabledAliases == nil {
		t.Fatal("empty archive array collapsed to null")
	}
}

func TestLeaseCacheCASRejectsStaleReplacementAndClear(t *testing.T) {
	anchor := time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC)
	a := cachedLeaseForTest(t, testLease(LeaseEnabled), 1, 7, anchor, anchor.Add(5*time.Second))
	bLease := testLease(LeaseEnabled)
	bLease.MaxCapacity = 3
	b := cachedLeaseForTest(t, bLease, 2, 7, anchor.Add(time.Second), anchor.Add(6*time.Second))
	cache := &LeaseCache{}

	revision, err := cache.CompareAndSwap(0, &a)
	if err != nil {
		t.Fatalf("install A: %v", err)
	}
	if _, err := cache.CompareAndSwap(0, &b); !errors.Is(err, ErrLeaseCache) {
		t.Fatalf("stale replacement error = %v", err)
	}
	if _, err := cache.CompareAndSwap(0, nil); !errors.Is(err, ErrLeaseCache) {
		t.Fatalf("stale clear error = %v", err)
	}
	current, err := cache.Snapshot()
	if err != nil || current.MutationRevision != revision || current.Key != a.Key {
		t.Fatalf("stale mutation changed A: (%+v, %v)", current, err)
	}

	clearedRevision, err := cache.CompareAndSwap(revision, nil)
	if err != nil || clearedRevision != revision+1 {
		t.Fatalf("clear = (%d, %v)", clearedRevision, err)
	}
	if _, err := cache.Snapshot(); !errors.Is(err, ErrLeaseCache) {
		t.Fatalf("cleared cache snapshot error = %v", err)
	}
	if _, err := cache.CompareAndSwap(revision, &b); !errors.Is(err, ErrLeaseCache) {
		t.Fatalf("pre-clear revision reinstalled authority: %v", err)
	}
}

func TestLeaseCacheAuthorityTokenRejectsABAAndSurvivesPureRenewal(t *testing.T) {
	anchor := time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC)
	a := cachedLeaseForTest(t, testLease(LeaseEnabled), 1, 7, anchor, anchor.Add(5*time.Second))
	cache := &LeaseCache{}
	revision, err := cache.CompareAndSwap(0, &a)
	if err != nil {
		t.Fatalf("install A: %v", err)
	}
	aSnapshot, _ := cache.Snapshot()

	renewal := a
	renewal.Sequence = 2
	renewal.Lease.Expiry = "2026-01-01T00:00:09.000Z"
	revision, err = cache.CompareAndSwap(revision, &renewal)
	if err != nil {
		t.Fatalf("renew A: %v", err)
	}
	renewed, _ := cache.Snapshot()
	if renewed.AuthorityToken != aSnapshot.AuthorityToken || renewed.MutationRevision == aSnapshot.MutationRevision {
		t.Fatalf("pure renewal token/revision = (%+v, %d), prior (%+v, %d)",
			renewed.AuthorityToken, renewed.MutationRevision, aSnapshot.AuthorityToken, aSnapshot.MutationRevision)
	}
	if _, err := cache.Revalidate(aSnapshot.AuthorityToken); err != nil {
		t.Fatalf("pure renewal revoked token: %v", err)
	}

	bLease := testLease(LeaseEnabled)
	bLease.MaxCapacity = 3
	b := cachedLeaseForTest(t, bLease, 3, 7, anchor.Add(time.Second), anchor.Add(4*time.Second))
	revision, err = cache.CompareAndSwap(revision, &b)
	if err != nil {
		t.Fatalf("replace with B: %v", err)
	}
	if _, err := cache.Revalidate(aSnapshot.AuthorityToken); !errors.Is(err, ErrLeaseCache) {
		t.Fatalf("A token survived B: %v", err)
	}

	aAgain := a
	aAgain.Sequence = 4
	aAgain.SendAnchor = anchor.Add(2 * time.Second)
	aAgain.LocalDeadline = anchor.Add(6 * time.Second)
	_, err = cache.CompareAndSwap(revision, &aAgain)
	if err != nil {
		t.Fatalf("replace with A again: %v", err)
	}
	latest, _ := cache.Snapshot()
	if latest.AuthorityToken == aSnapshot.AuthorityToken {
		t.Fatalf("A-B-A revived old authority token: %+v", latest.AuthorityToken)
	}
	if _, err := cache.Revalidate(aSnapshot.AuthorityToken); !errors.Is(err, ErrLeaseCache) {
		t.Fatalf("old A token revalidated after A-B-A: %v", err)
	}
}

func TestLeaseCacheRejectsRegressingRenewalAndSessionFields(t *testing.T) {
	anchor := time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC)
	base := cachedLeaseForTest(t, testLease(LeaseEnabled), 4, 7, anchor, anchor.Add(5*time.Second))
	cache := &LeaseCache{}
	revision, err := cache.CompareAndSwap(0, &base)
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*CachedLease)
	}{
		{name: "equal sequence", mutate: func(next *CachedLease) { next.Sequence = base.Sequence }},
		{name: "anchor regression", mutate: func(next *CachedLease) { next.SendAnchor = anchor.Add(-time.Nanosecond) }},
		{name: "deadline regression", mutate: func(next *CachedLease) { next.LocalDeadline = base.LocalDeadline.Add(-time.Nanosecond) }},
		{name: "lease generation regression", mutate: func(next *CachedLease) {
			next.Lease.LeaseGeneration--
			next.Key, _ = next.Lease.AdmissionAuthorityKey()
		}},
		{name: "fence regression", mutate: func(next *CachedLease) { next.Fence-- }},
		{name: "same session changed epoch", mutate: func(next *CachedLease) {
			next.Lease.ServerEpoch++
			next.Key, _ = next.Lease.AdmissionAuthorityKey()
		}},
		{name: "new session without newer epoch", mutate: func(next *CachedLease) {
			next.Lease.SessionID = strings.Repeat("c", 64)
			next.Key, _ = next.Lease.AdmissionAuthorityKey()
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			next := base
			next.Sequence++
			test.mutate(&next)
			if _, err := cache.CompareAndSwap(revision, &next); !errors.Is(err, ErrLeaseCache) {
				t.Fatalf("regression error = %v", err)
			}
			current, snapshotErr := cache.Snapshot()
			if snapshotErr != nil || current.MutationRevision != revision || current.Sequence != base.Sequence {
				t.Fatalf("rejection mutated cache: (%+v, %v)", current, snapshotErr)
			}
		})
	}

	equalAnchor := base
	equalAnchor.Sequence++
	if _, err := cache.CompareAndSwap(revision, &equalAnchor); err != nil {
		t.Fatalf("equal anchor with newer sequence rejected: %v", err)
	}
}

func TestLeaseCacheAllowsSequenceResetOnlyForNewerSession(t *testing.T) {
	anchor := time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC)
	base := cachedLeaseForTest(t, testLease(LeaseEnabled), 12, 7, anchor, anchor.Add(5*time.Second))
	cache := &LeaseCache{}
	revision, err := cache.CompareAndSwap(0, &base)
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	nextLease := base.Lease
	nextLease.SessionID = strings.Repeat("c", 64)
	nextLease.ServerEpoch++
	nextLease.LeaseGeneration++
	next := cachedLeaseForTest(t, nextLease, 1, 7, anchor, anchor.Add(4*time.Second))
	if _, err := cache.CompareAndSwap(revision, &next); err != nil {
		t.Fatalf("newer session sequence reset rejected: %v", err)
	}
}

func TestLeaseCacheConcurrentCASHasOneWinner(t *testing.T) {
	anchor := time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC)
	a := cachedLeaseForTest(t, testLease(LeaseEnabled), 1, 7, anchor, anchor.Add(5*time.Second))
	bLease := testLease(LeaseEnabled)
	bLease.MaxCapacity = 3
	b := cachedLeaseForTest(t, bLease, 1, 7, anchor, anchor.Add(5*time.Second))
	cache := &LeaseCache{}

	start := make(chan struct{})
	results := make(chan error, 2)
	var writers sync.WaitGroup
	for _, candidate := range []*CachedLease{&a, &b} {
		candidate := candidate
		writers.Add(1)
		go func() {
			defer writers.Done()
			<-start
			_, err := cache.CompareAndSwap(0, candidate)
			results <- err
		}()
	}
	close(start)
	writers.Wait()
	close(results)

	successes := 0
	stale := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrLeaseCache):
			stale++
		default:
			t.Fatalf("unexpected writer error: %v", err)
		}
	}
	if successes != 1 || stale != 1 {
		t.Fatalf("CAS results success/stale = %d/%d", successes, stale)
	}
}

func TestLeaseCacheRevisionOverflowClearsAndPoisons(t *testing.T) {
	anchor := time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC)
	next := cachedLeaseForTest(t, testLease(LeaseEnabled), 1, 7, anchor, anchor.Add(5*time.Second))
	cache := &LeaseCache{mutationRevision: math.MaxUint64}

	if _, err := cache.CompareAndSwap(math.MaxUint64, &next); !errors.Is(err, ErrLeaseCache) {
		t.Fatalf("overflow error = %v", err)
	}
	if _, err := cache.Snapshot(); !errors.Is(err, ErrLeaseCache) {
		t.Fatalf("poisoned snapshot error = %v", err)
	}
	if _, err := cache.CompareAndSwap(math.MaxUint64, &next); !errors.Is(err, ErrLeaseCache) {
		t.Fatalf("poisoned cache accepted install: %v", err)
	}
}
