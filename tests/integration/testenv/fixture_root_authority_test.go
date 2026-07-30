package testenv

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type fakeFixtureRootLeaseOperations struct {
	trace       []string
	observation fixtureRootObservation
	lockErr     error
	observeErr  error
	removeErr   error
	syncErr     error
	absentErr   error
	closeErr    error
}

func (o *fakeFixtureRootLeaseOperations) Lock() error {
	o.trace = append(o.trace, "lock")
	return o.lockErr
}

func (o *fakeFixtureRootLeaseOperations) ObserveEmpty() (
	fixtureRootObservation,
	error,
) {
	o.trace = append(o.trace, "observe-empty")
	return o.observation, o.observeErr
}

func (o *fakeFixtureRootLeaseOperations) Remove() error {
	o.trace = append(o.trace, "remove")
	return o.removeErr
}

func (o *fakeFixtureRootLeaseOperations) SyncParent() error {
	o.trace = append(o.trace, "sync-parent")
	return o.syncErr
}

func (o *fakeFixtureRootLeaseOperations) ProveAbsent() error {
	o.trace = append(o.trace, "prove-absent")
	return o.absentErr
}

func (o *fakeFixtureRootLeaseOperations) Close() error {
	o.trace = append(o.trace, "close")
	return o.closeErr
}

func TestFixtureRootAuthorityLocksRevalidatesAndRemovesExactRoot(
	t *testing.T,
) {
	t.Parallel()

	binding, observation := validFixtureRootBinding(t)
	operations := &fakeFixtureRootLeaseOperations{
		observation: observation,
	}
	authority, err := newLockedFixtureRootAuthority(operations)
	if err != nil {
		t.Fatalf("newLockedFixtureRootAuthority: %v", err)
	}
	handle, err := authority.Acquire(context.Background(), binding)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if handle.kind != CleanupFixtureRoot ||
		handle.id != binding.RequiredEmptyDigest {
		t.Fatalf("root handle = %+v", handle)
	}
	if err := authority.RemoveRoot(
		context.Background(),
		handle,
	); err != nil {
		t.Fatalf("RemoveRoot: %v", err)
	}
	if !reflect.DeepEqual(operations.trace, []string{
		"lock",
		"observe-empty",
		"observe-empty",
		"remove",
		"sync-parent",
		"prove-absent",
		"close",
	}) {
		t.Fatalf("root authority trace = %v", operations.trace)
	}
	if err := authority.Close(); err != nil {
		t.Fatalf("cached Close: %v", err)
	}
	if len(operations.trace) != 7 {
		t.Fatalf("Close repeated operation: %v", operations.trace)
	}
}

func TestFixtureRootAuthorityPreservesUnknownOrReplacedRoot(
	t *testing.T,
) {
	t.Parallel()

	for name, mutate := range map[string]func(
		*fakeFixtureRootLeaseOperations,
	){
		"unknown object": func(operations *fakeFixtureRootLeaseOperations) {
			operations.observeErr = ErrFixtureUnexpectedObject
		},
		"replaced inode": func(operations *fakeFixtureRootLeaseOperations) {
			operations.observation.RootInode++
		},
	} {
		t.Run(name, func(t *testing.T) {
			binding, observation := validFixtureRootBinding(t)
			operations := &fakeFixtureRootLeaseOperations{
				observation: observation,
			}
			authority, err := newLockedFixtureRootAuthority(operations)
			if err != nil {
				t.Fatalf("newLockedFixtureRootAuthority: %v", err)
			}
			handle, err := authority.Acquire(
				context.Background(),
				binding,
			)
			if err != nil {
				t.Fatalf("Acquire: %v", err)
			}
			mutate(operations)
			err = authority.RemoveRoot(context.Background(), handle)
			if err == nil {
				t.Fatal("RemoveRoot accepted unsafe root")
			}
			for _, operation := range operations.trace {
				if operation == "remove" {
					t.Fatalf("unsafe root was removed: %v", operations.trace)
				}
			}
			if operations.trace[len(operations.trace)-1] != "close" {
				t.Fatalf("unsafe root lock not released: %v", operations.trace)
			}
		})
	}
}

func TestFixtureRootAuthorityRejectsWrongDigestAndLockContention(
	t *testing.T,
) {
	t.Parallel()

	binding, observation := validFixtureRootBinding(t)
	binding.RequiredEmptyDigest = inputDigestA
	operations := &fakeFixtureRootLeaseOperations{
		observation: observation,
	}
	authority, err := newLockedFixtureRootAuthority(operations)
	if err != nil {
		t.Fatalf("newLockedFixtureRootAuthority: %v", err)
	}
	if _, err := authority.Acquire(
		context.Background(),
		binding,
	); err == nil {
		t.Fatal("Acquire accepted wrong digest")
	}
	if !reflect.DeepEqual(operations.trace, []string{
		"lock",
		"observe-empty",
		"close",
	}) {
		t.Fatalf("wrong-digest trace = %v", operations.trace)
	}

	binding, observation = validFixtureRootBinding(t)
	operations = &fakeFixtureRootLeaseOperations{
		observation: observation,
		lockErr:     ErrFixtureRootInUse,
	}
	authority, err = newLockedFixtureRootAuthority(operations)
	if err != nil {
		t.Fatalf("newLockedFixtureRootAuthority: %v", err)
	}
	if _, err := authority.Acquire(
		context.Background(),
		binding,
	); !errors.Is(err, ErrFixtureRootInUse) {
		t.Fatalf("Acquire contention = %v", err)
	}
	if !reflect.DeepEqual(operations.trace, []string{"lock", "close"}) {
		t.Fatalf("contention trace = %v", operations.trace)
	}
}

func validFixtureRootBinding(
	t *testing.T,
) (FixtureBinding, fixtureRootObservation) {
	t.Helper()
	observation := fixtureRootObservation{
		SchemaVersion:  1,
		ParentDevice:   7,
		ParentInode:    11,
		ParentOwnerUID: 1000,
		ParentMode:     0o700,
		RootDevice:     7,
		RootInode:      13,
		OwnerUID:       1000,
		Mode:           0o700,
	}
	digest, err := computeFixtureEmptyDigest(observation)
	if err != nil {
		t.Fatalf("computeFixtureEmptyDigest: %v", err)
	}
	return FixtureBinding{
		Root:                         "/private/tmp/portable-ghar-fixture",
		ParentDevice:                 observation.ParentDevice,
		ParentInode:                  observation.ParentInode,
		RequiredEmptyDigest:          digest,
		ExecutionOwnerUID:            observation.OwnerUID,
		ExecutionOwnerIdentityDigest: inputDigestB,
	}, observation
}
