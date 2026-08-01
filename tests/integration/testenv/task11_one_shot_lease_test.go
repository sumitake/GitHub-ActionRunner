package testenv

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

const task11LeaseTestName = "pghar-task11-verifier-" +
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-denials"

func TestTask11OneShotLeaseAuthorityRecordsBeforeUseAndRetiresAbsent(
	t *testing.T,
) {
	t.Parallel()

	var recorded []cleanupHandle
	runner := &orderedClosedRunner{}
	authority, err := newTask11OneShotLeaseAuthority(
		"/usr/bin/docker",
		64<<10,
		runner,
		func(handle cleanupHandle) error {
			recorded = append(recorded, handle)
			return nil
		},
	)
	if err != nil {
		t.Fatalf("newTask11OneShotLeaseAuthority: %v", err)
	}
	handle := cleanupHandle{
		kind: CleanupVerifier,
		id:   inputDigestA,
	}
	if err := authority.Register(
		handle,
		task11LeaseTestName,
	); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !reflect.DeepEqual(recorded, []cleanupHandle{handle}) {
		t.Fatalf("recorded = %+v", recorded)
	}
	if err := authority.Retire(handle); err != nil {
		t.Fatalf("Retire: %v", err)
	}
	if authority.RecordedRemoved(handle) {
		t.Fatal("retired handle was removed before fixture cleanup")
	}
	if err := authority.Remove(
		context.Background(),
		handle,
	); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if !authority.RecordedRemoved(handle) {
		t.Fatal("retired handle was not marked removed")
	}
	if len(runner.argv) != 0 {
		t.Fatalf("retired cleanup executed commands: %#v", runner.argv)
	}
}

func TestTask11OneShotLeaseAuthorityRemovesAmbiguousExactName(
	t *testing.T,
) {
	t.Parallel()

	name := task11LeaseTestName
	runner := &orderedClosedRunner{
		results: []orderedClosedResult{
			{result: hostruntime.Result{
				Stdout: []byte(name + "\n"),
			}},
			{result: hostruntime.Result{
				ExitCode: 1,
				Stderr: []byte(
					"Error: No such object: " + name + "\n",
				),
			}},
		},
	}
	authority, err := newTask11OneShotLeaseAuthority(
		"/usr/bin/docker",
		64<<10,
		runner,
		func(cleanupHandle) error { return nil },
	)
	if err != nil {
		t.Fatalf("newTask11OneShotLeaseAuthority: %v", err)
	}
	handle := cleanupHandle{
		kind: CleanupVerifier,
		id:   inputDigestA,
	}
	if err := authority.Register(handle, name); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := authority.Remove(
		context.Background(),
		handle,
	); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	want := [][]string{
		{"/usr/bin/docker", "rm", "-f", name},
		{
			"/usr/bin/docker",
			"inspect",
			"--type",
			"container",
			name,
		},
	}
	if !reflect.DeepEqual(runner.argv, want) {
		t.Fatalf("argv = %#v, want %#v", runner.argv, want)
	}
	if !authority.RecordedRemoved(handle) {
		t.Fatal("active handle cleanup was not recorded")
	}
}

func TestTask11OneShotLeaseAuthorityFailsClosedOnDrift(
	t *testing.T,
) {
	t.Parallel()

	authority, err := newTask11OneShotLeaseAuthority(
		"/usr/bin/docker",
		64<<10,
		&orderedClosedRunner{},
		func(cleanupHandle) error { return nil },
	)
	if err != nil {
		t.Fatalf("newTask11OneShotLeaseAuthority: %v", err)
	}
	handle := cleanupHandle{
		kind: CleanupVerifier,
		id:   inputDigestA,
	}
	if err := authority.Register(
		handle,
		task11LeaseTestName,
	); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := authority.Register(
		handle,
		"pghar-task11-verifier-"+
			"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-denials",
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("duplicate handle error = %v", err)
	}
	if err := authority.Register(
		cleanupHandle{
			kind: CleanupVerifier,
			id:   inputDigestB,
		},
		task11LeaseTestName,
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("duplicate name error = %v", err)
	}
	if err := authority.Retire(cleanupHandle{
		kind: CleanupVerifier,
		id:   inputDigestB,
	}); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("unknown retire error = %v", err)
	}
	if err := authority.Remove(
		context.Background(),
		handle,
	); !errors.Is(err, ErrFixtureCleanup) {
		t.Fatalf("ambiguous cleanup error = %v", err)
	}
	if authority.RecordedRemoved(handle) {
		t.Fatal("failed cleanup was recorded as removed")
	}
}
