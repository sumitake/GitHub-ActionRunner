//go:build !darwin && !linux

package hostruntime

import (
	"context"
	"time"
)

type LifecycleStore struct{}
type LifecycleLease struct{}

func OpenLifecycleStore(string, bool) (*LifecycleStore, error) {
	return nil, ErrLifecycleIntegrity
}

func OpenLifecycleStoreLayout(
	LifecycleStoreLayout,
	bool,
) (*LifecycleStore, error) {
	return nil, ErrLifecycleIntegrity
}

func (*LifecycleStore) Close() error {
	return nil
}

func (*LifecycleStore) ReadCanonical(
	LifecycleDirectory,
	string,
	int,
) ([]byte, error) {
	return nil, ErrLifecycleIntegrity
}

func (*LifecycleStore) CreateCanonical(
	LifecycleDirectory,
	string,
	[]byte,
	int,
) error {
	return ErrLifecycleIntegrity
}

func (*LifecycleStore) ReplaceCanonical(
	LifecycleDirectory,
	string,
	[]byte,
	[]byte,
	int,
) error {
	return ErrLifecycleIntegrity
}

func (*LifecycleStore) RemoveCanonical(
	LifecycleDirectory,
	string,
	[]byte,
	int,
) error {
	return ErrLifecycleIntegrity
}

func (*LifecycleStore) ListCanonicalNames(
	LifecycleDirectory,
) ([]string, error) {
	return nil, ErrLifecycleIntegrity
}

func (*LifecycleStore) Acquire(
	context.Context,
	time.Duration,
) (*LifecycleLease, error) {
	return nil, ErrLifecycleIntegrity
}

func (*LifecycleLease) Validate() error {
	return ErrLifecycleIntegrity
}

func (*LifecycleLease) Close() error {
	return nil
}
