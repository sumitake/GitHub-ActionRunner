package failoverclient

import (
	"context"
	"errors"
	"testing"

	"github.com/sumitake/portable-ghar/internal/controller"
)

func TestEmptyLeaseCacheIsPendingButNeverGrantsAPermit(t *testing.T) {
	f := newCachedPermitFixture(t, LeaseEnabled)
	if err := f.provider.Invalidate(context.Background()); err != nil {
		t.Fatal(err)
	}
	permit, err := f.provider.Acquire(context.Background(), f.request)
	if permit != nil || !errors.Is(err, controller.ErrAcquisitionLeasePending) || !errors.Is(err, controller.ErrAcquisitionPermitAuthority) {
		t.Fatal("empty post-transition cache was not distinguished from broken authority", err)
	}
	if _, err := f.cache.Revalidate(LeaseAuthorityToken{}); errors.Is(err, errLeaseCacheEmpty) {
		t.Fatal("issued-permit revalidation became a pending wait")
	}
	f.cache.mu.Lock()
	f.cache.poisoned = true
	f.cache.mu.Unlock()
	permit, err = f.provider.Acquire(context.Background(), f.request)
	if permit != nil || errors.Is(err, controller.ErrAcquisitionLeasePending) || !errors.Is(err, controller.ErrAcquisitionPermitAuthority) {
		t.Fatal("poisoned cache became a normal wait", err)
	}
}

func TestAnIssuedPermitNeverBecomesAPendingWaitAfterCacheClear(t *testing.T) {
	f := newCachedPermitFixture(t, LeaseEnabled)
	permit, err := f.provider.Acquire(context.Background(), f.request)
	if err != nil {
		t.Fatal(err)
	}
	defer permit.Close()
	if err := f.provider.Invalidate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := permit.Revalidate(); err == nil || errors.Is(err, controller.ErrAcquisitionLeasePending) {
		t.Fatal("issued permit waited instead of dropping authority", err)
	}
	if err := permit.Admit(); err == nil || errors.Is(err, controller.ErrAcquisitionLeasePending) {
		t.Fatal("cleared permit was admitted or waited", err)
	}
}
