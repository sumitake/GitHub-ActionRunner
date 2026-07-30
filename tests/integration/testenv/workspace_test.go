package testenv

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type fakeFixtureWorkspaceOperations struct {
	trace       *[]string
	prepareErr  error
	removeErr   error
	database    string
	prepareUID  uint32
	prepareGID  uint32
	removeCalls int
	closeCalls  int
}

func (o *fakeFixtureWorkspaceOperations) Prepare(
	uid uint32,
	gid uint32,
) error {
	*o.trace = append(*o.trace, "prepare")
	o.prepareUID = uid
	o.prepareGID = gid
	return o.prepareErr
}

func (o *fakeFixtureWorkspaceOperations) StateDatabasePath() (
	string,
	error,
) {
	*o.trace = append(*o.trace, "database")
	return o.database, nil
}

func (o *fakeFixtureWorkspaceOperations) Remove() error {
	*o.trace = append(*o.trace, "remove")
	o.removeCalls++
	return o.removeErr
}

func (o *fakeFixtureWorkspaceOperations) Close() error {
	*o.trace = append(*o.trace, "close")
	o.closeCalls++
	return nil
}

func TestFixtureWorkspaceRegistersBeforePreparationAndBindsUser(
	t *testing.T,
) {
	t.Parallel()

	trace := []string{}
	handle, err := compositionCleanupHandle(
		CleanupTestProcess,
		"portable-ghar.task11.workspace.v1\x00",
		inputDigestA,
	)
	if err != nil {
		t.Fatalf("compositionCleanupHandle: %v", err)
	}
	operations := &fakeFixtureWorkspaceOperations{
		trace:    &trace,
		database: "/fixture/state/controller.db",
	}
	workspace, err := newFixtureWorkspace(operations, handle)
	if err != nil {
		t.Fatalf("newFixtureWorkspace: %v", err)
	}
	if err := workspace.Acquire(
		context.Background(),
		"65532:65531",
		func(recorded cleanupHandle) error {
			trace = append(trace, "record")
			if recorded != handle {
				t.Fatalf("recorded = %+v", recorded)
			}
			return nil
		},
	); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	database, err := workspace.StateDatabasePath()
	if err != nil || database != operations.database {
		t.Fatalf("database/error = %q/%v", database, err)
	}
	if !reflect.DeepEqual(trace, []string{
		"record",
		"prepare",
		"database",
	}) {
		t.Fatalf("trace = %v", trace)
	}
	if operations.prepareUID != 65532 ||
		operations.prepareGID != 65531 {
		t.Fatalf(
			"uid/gid = %d/%d",
			operations.prepareUID,
			operations.prepareGID,
		)
	}
}

func TestFixtureWorkspacePartialPreparationRemainsCleanupReachable(
	t *testing.T,
) {
	t.Parallel()

	trace := []string{}
	handle, err := compositionCleanupHandle(
		CleanupTestProcess,
		"portable-ghar.task11.workspace.v1\x00",
		inputDigestA,
	)
	if err != nil {
		t.Fatalf("compositionCleanupHandle: %v", err)
	}
	operations := &fakeFixtureWorkspaceOperations{
		trace:      &trace,
		prepareErr: errors.New("partial prepare"),
	}
	workspace, err := newFixtureWorkspace(operations, handle)
	if err != nil {
		t.Fatalf("newFixtureWorkspace: %v", err)
	}
	if err := workspace.Acquire(
		context.Background(),
		"65532:65532",
		func(recorded cleanupHandle) error {
			trace = append(trace, "record")
			return nil
		},
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("Acquire error = %v", err)
	}
	if err := workspace.Remove(
		context.Background(),
		handle,
	); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if !reflect.DeepEqual(trace, []string{
		"record",
		"prepare",
		"remove",
		"close",
	}) {
		t.Fatalf("trace = %v", trace)
	}
	if operations.removeCalls != 1 || operations.closeCalls != 1 {
		t.Fatalf(
			"remove/close = %d/%d",
			operations.removeCalls,
			operations.closeCalls,
		)
	}
}

func TestFixtureWorkspaceRejectsInvalidOrDuplicateAuthority(t *testing.T) {
	t.Parallel()

	trace := []string{}
	handle, err := compositionCleanupHandle(
		CleanupTestProcess,
		"portable-ghar.task11.workspace.v1\x00",
		inputDigestA,
	)
	if err != nil {
		t.Fatalf("compositionCleanupHandle: %v", err)
	}
	workspace, err := newFixtureWorkspace(
		&fakeFixtureWorkspaceOperations{trace: &trace},
		handle,
	)
	if err != nil {
		t.Fatalf("newFixtureWorkspace: %v", err)
	}
	if err := workspace.Acquire(
		context.Background(),
		"root",
		func(cleanupHandle) error { return nil },
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("invalid user error = %v", err)
	}
	if err := workspace.Acquire(
		context.Background(),
		"65532:65532",
		func(cleanupHandle) error { return nil },
	); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if err := workspace.Acquire(
		context.Background(),
		"65532:65532",
		func(cleanupHandle) error { return nil },
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("duplicate error = %v", err)
	}
}
