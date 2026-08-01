//go:build integration && linux

package testenv

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"
)

type unusedFixtureAuthorizationUsage struct{}

func (unusedFixtureAuthorizationUsage) Used(string) bool {
	return false
}

// StartDockerFixture owns the Linux opt-in boundary and transfers every
// retained capability to the fixture's one cleanup authority before effects.
func StartDockerFixture(t *testing.T) *Fixture {
	t.Helper()
	decision, err := decideFixtureStartup(runtime.GOOS, os.LookupEnv)
	if err != nil {
		t.Fatal(ErrFixtureOptIn)
	}
	if decision.Skip {
		t.Skip(decision.Reason)
	}

	lease, err := acquireConformanceInputLease(
		decision.InputPath,
		ConformanceInputReadOptions{
			ExpectedOwner: uint32(os.Geteuid()),
			ExpectedMode:  0o400,
			MaximumBytes:  maximumConformanceInputBytes,
			Now:           time.Now,
			Usage:         unusedFixtureAuthorizationUsage{},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	leaseOwned := true
	defer func() {
		if leaseOwned {
			_ = lease.Close()
		}
	}()
	parsed, err := lease.Parsed()
	if err != nil {
		t.Fatal(err)
	}
	startupTimeout := durationMilliseconds(
		parsed.Input.Limits.CaseTimeouts[0].TimeoutMilliseconds,
	)
	if startupTimeout <= 0 {
		t.Fatal(ErrFixtureStart)
	}
	ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()

	preflight, err := runLinuxStaticPreflight(ctx, parsed)
	if err != nil {
		t.Fatal(err)
	}
	root, err := newLinuxFixtureRootAuthority(parsed.Input.Fixture)
	if err != nil {
		t.Fatal(err)
	}
	rootOwned := true
	defer func() {
		if rootOwned {
			_ = root.Close()
		}
	}()
	backend, err := newLinuxFixtureRuntimeBackend(
		parsed.Input,
		preflight,
		root,
	)
	if err != nil {
		t.Fatal(err)
	}
	backendOwned := true
	defer func() {
		if backendOwned {
			_ = backend.CloseUnstarted()
		}
	}()
	authorization, err := newFixtureStartAuthorization(
		lease,
		root,
		backend,
		time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	// The composite authorization now owns all pre-effect handles. Its Close
	// remains idempotent after the fixture cleanup state machine takes over.
	leaseOwned = false
	rootOwned = false
	backendOwned = false

	plan, err := compositionPlanFrom(parsed.Input, preflight.Overlay)
	if err != nil {
		_ = authorization.Close()
		t.Fatal(err)
	}
	runtimes := task11MatrixRuntimes{
		Namespace:   backend,
		Broker:      backend,
		MountSecret: backend,
		Sandbox:     backend,
		Runner:      backend,
		OneJob:      backend,
		Cleanup:     backend,
		Reclamation: backend,
		Workflow:    backend,
		Seed:        backend,
		Recovery:    backend,
	}
	matrix, err := newTask11MatrixComposition(
		parsed.Input,
		preflight.Overlay,
		preflight.Result,
		preflight.Graph,
		plan,
		runtimes,
	)
	if err != nil {
		_ = authorization.Close()
		t.Fatal(err)
	}
	fixture, err := startFixtureCore(
		ctx,
		parsed,
		preflight.Result.HostFacts,
		fixtureStartDependencies{
			RegisterCleanup: t.Cleanup,
			Authorization:   authorization,
			Root:            root,
			Effects:         backend,
			Cleanup:         backend,
			Cases:           matrix.Cases,
			Finalizer:       matrix.Finalizer,
		},
	)
	if err != nil {
		_ = authorization.Close()
		t.Fatal(err)
	}
	return fixture
}
