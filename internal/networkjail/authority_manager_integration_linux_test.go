//go:build integration && linux

package networkjail

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestShutdownIntegrationAuthorityStopsOnlyExactTuple(t *testing.T) {
	fixture := newPermitFixture(t, 3)
	manager, err := NewUnixAuthorityManager(
		fixture.authority,
		4,
		time.Second,
	)
	if err != nil {
		t.Fatalf("NewUnixAuthorityManager: %v", err)
	}
	directory := permitSocketTempDir(t)
	if err := prepareAuthorityTestDirectory(directory); err != nil {
		t.Fatalf("prepare directory: %v", err)
	}
	generation := JobGeneration(19)
	lease, err := manager.Start(context.Background(), authorityRequest{
		slotID:        uint32(fixture.slot),
		jobGeneration: uint64(generation),
		directory:     directory,
		user: strconv.Itoa(os.Getuid()) + ":" +
			strconv.Itoa(os.Getgid()),
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := manager.ShutdownIntegrationAuthority(
		context.Background(),
		fixture.slot,
		generation,
		directory,
	); err != nil {
		t.Fatalf("ShutdownIntegrationAuthority: %v", err)
	}
	if _, err := os.Lstat(lease.socketPath); !errors.Is(
		err,
		os.ErrNotExist,
	) {
		t.Fatalf("socket remains: %v", err)
	}
	if _, err := fixture.authority.ActiveRevision(
		context.Background(),
		fixture.slot,
		generation,
	); !errors.Is(err, ErrPermitAssignment) {
		t.Fatalf("authority remains active: %v", err)
	}
	if err := manager.ShutdownIntegrationAuthority(
		context.Background(),
		fixture.slot,
		generation,
		directory,
	); err != nil {
		t.Fatalf("idempotent absent shutdown: %v", err)
	}
}

func TestShutdownIntegrationAuthorityAcceptsExactInactiveAbsence(
	t *testing.T,
) {
	fixture := newPermitFixture(t, 3)
	manager, err := NewUnixAuthorityManager(
		fixture.authority,
		4,
		time.Second,
	)
	if err != nil {
		t.Fatalf("NewUnixAuthorityManager: %v", err)
	}
	directory := permitSocketTempDir(t)
	if err := prepareAuthorityTestDirectory(directory); err != nil {
		t.Fatalf("prepare directory: %v", err)
	}
	if err := manager.ShutdownIntegrationAuthority(
		context.Background(),
		fixture.slot,
		23,
		directory,
	); err != nil {
		t.Fatalf("absent shutdown: %v", err)
	}
}

func TestProveIntegrationAuthorityAbsentIsReadOnly(t *testing.T) {
	fixture := newPermitFixture(t, 3)
	manager, err := NewUnixAuthorityManager(
		fixture.authority,
		4,
		time.Second,
	)
	if err != nil {
		t.Fatalf("NewUnixAuthorityManager: %v", err)
	}
	directory := permitSocketTempDir(t)
	if err := prepareAuthorityTestDirectory(directory); err != nil {
		t.Fatalf("prepare directory: %v", err)
	}
	generation := JobGeneration(29)
	lease, err := manager.Start(context.Background(), authorityRequest{
		slotID:        uint32(fixture.slot),
		jobGeneration: uint64(generation),
		directory:     directory,
		user: strconv.Itoa(os.Getuid()) + ":" +
			strconv.Itoa(os.Getgid()),
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := manager.ProveIntegrationAuthorityAbsent(
		context.Background(),
		fixture.slot,
		generation,
		directory,
	); !errors.Is(err, ErrPermitAuthorityUnavailable) {
		t.Fatalf("live absence proof error = %v", err)
	}
	if _, err := os.Lstat(lease.socketPath); err != nil {
		t.Fatalf("read-only proof removed socket: %v", err)
	}
	if _, err := fixture.authority.ActiveRevision(
		context.Background(),
		fixture.slot,
		generation,
	); err != nil {
		t.Fatalf("read-only proof deactivated authority: %v", err)
	}
	if err := manager.Stop(context.Background(), lease); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := manager.ProveIntegrationAuthorityAbsent(
		context.Background(),
		fixture.slot,
		generation,
		directory,
	); err != nil {
		t.Fatalf("absent proof: %v", err)
	}
}

func TestShutdownIntegrationAuthorityRejectsPartialOrAmbiguousClaim(
	t *testing.T,
) {
	tests := map[string]func(
		*UnixAuthorityManager,
		string,
		*managedUnixAuthority,
	){
		"reserved socket": func(
			manager *UnixAuthorityManager,
			socket string,
			_ *managedUnixAuthority,
		) {
			manager.active[socket] = nil
		},
		"wrong slot": func(
			manager *UnixAuthorityManager,
			socket string,
			endpoint *managedUnixAuthority,
		) {
			manager.active[socket] = &managedUnixAuthority{
				socketPath: endpoint.socketPath,
				socket:     endpoint.socket,
				slot:       endpoint.slot + 1,
				generation: endpoint.generation,
			}
		},
		"wrong generation": func(
			manager *UnixAuthorityManager,
			socket string,
			endpoint *managedUnixAuthority,
		) {
			manager.active[socket] = &managedUnixAuthority{
				socketPath: endpoint.socketPath,
				socket:     endpoint.socket,
				slot:       endpoint.slot,
				generation: endpoint.generation + 1,
			}
		},
		"wrong map key": func(
			manager *UnixAuthorityManager,
			socket string,
			endpoint *managedUnixAuthority,
		) {
			delete(manager.active, socket)
			manager.active[socket+"-drift"] = endpoint
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			fixture := newPermitFixture(t, 3)
			manager, err := NewUnixAuthorityManager(
				fixture.authority,
				4,
				time.Second,
			)
			if err != nil {
				t.Fatalf("NewUnixAuthorityManager: %v", err)
			}
			directory := permitSocketTempDir(t)
			if err := prepareAuthorityTestDirectory(directory); err != nil {
				t.Fatalf("prepare directory: %v", err)
			}
			generation := JobGeneration(29)
			lease, err := manager.Start(
				context.Background(),
				authorityRequest{
					slotID:        uint32(fixture.slot),
					jobGeneration: uint64(generation),
					directory:     directory,
					user: strconv.Itoa(os.Getuid()) + ":" +
						strconv.Itoa(os.Getgid()),
				},
			)
			if err != nil {
				t.Fatalf("Start: %v", err)
			}
			endpoint := lease.endpoint.(*managedUnixAuthority)
			manager.mu.Lock()
			mutate(manager, lease.socketPath, endpoint)
			manager.mu.Unlock()
			if err := manager.ShutdownIntegrationAuthority(
				context.Background(),
				fixture.slot,
				generation,
				directory,
			); !errors.Is(err, ErrPermitAuthorityUnavailable) {
				t.Fatalf("shutdown error = %v", err)
			}
			manager.mu.Lock()
			for key := range manager.active {
				delete(manager.active, key)
			}
			manager.active[lease.socketPath] = endpoint
			manager.mu.Unlock()
			if err := manager.Stop(
				context.Background(),
				lease,
			); err != nil {
				t.Fatalf("restore cleanup: %v", err)
			}
		})
	}
}

func TestShutdownIntegrationAuthorityRejectsOpenInputs(t *testing.T) {
	fixture := newPermitFixture(t, 3)
	manager, err := NewUnixAuthorityManager(
		fixture.authority,
		4,
		time.Second,
	)
	if err != nil {
		t.Fatalf("NewUnixAuthorityManager: %v", err)
	}
	directory := permitSocketTempDir(t)
	tests := []struct {
		ctx        context.Context
		slot       CapacitySlotID
		generation JobGeneration
		directory  string
	}{
		{nil, fixture.slot, 1, directory},
		{context.Background(), 0, 1, directory},
		{context.Background(), fixture.slot, 0, directory},
		{context.Background(), fixture.slot, 1, "relative"},
		{
			context.Background(),
			fixture.slot,
			1,
			directory + string(filepath.Separator) + ".",
		},
	}
	for _, test := range tests {
		if err := manager.ShutdownIntegrationAuthority(
			test.ctx,
			test.slot,
			test.generation,
			test.directory,
		); !errors.Is(err, ErrPermitAuthorityUnavailable) {
			t.Fatalf("invalid shutdown error = %v", err)
		}
	}
}
