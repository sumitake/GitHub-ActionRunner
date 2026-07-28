//go:build linux || darwin

package networkjail

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestUnixAuthorityManagerBindsExactSocketAndDeactivates(t *testing.T) {
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
	request := authorityRequest{
		slotID:        uint32(fixture.slot),
		jobGeneration: 13,
		directory:     directory,
		user: strconv.Itoa(os.Getuid()) + ":" +
			strconv.Itoa(os.Getgid()),
	}
	lease, err := manager.Start(context.Background(), request)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !lease.valid || lease.socketPath != filepath.Join(
		directory,
		"dial-authority.sock",
	) || lease.socket.Inode == 0 || lease.socket.Mode != 0o600 {
		t.Fatalf("lease identity invalid: %+v", lease)
	}
	client, err := NewUnixPermitClient(lease.socketPath, time.Second)
	if err != nil {
		t.Fatalf("NewUnixPermitClient: %v", err)
	}
	if _, err := client.Request(context.Background(), DialPermitRequest{
		SlotID:        fixture.slot,
		JobGeneration: JobGeneration(request.jobGeneration),
		Class:         DialClassJob,
		Sequence:      1,
	}); err != nil {
		t.Fatalf("Request: %v", err)
	}
	if _, err := manager.Start(context.Background(), request); !errors.Is(
		err,
		ErrPermitAuthorityUnavailable,
	) {
		t.Fatalf("duplicate Start error = %v", err)
	}
	if err := manager.Stop(context.Background(), lease); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if _, err := os.Lstat(lease.socketPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket remains after Stop: %v", err)
	}
	record := fixture.store.mustLoad(t, fixture.slot)
	if record.ActiveJobGeneration != 0 || record.RetainedUntilNanos == 0 {
		t.Fatalf("Stop did not retain an inactive ledger: %+v", record)
	}
	if err := manager.Stop(context.Background(), lease); err != nil {
		t.Fatalf("idempotent Stop: %v", err)
	}
}

func TestUnixAuthorityManagerRejectsSocketReplacementWithoutDeactivation(t *testing.T) {
	fixture := newPermitFixture(t, 2)
	manager, err := NewUnixAuthorityManager(
		fixture.authority,
		2,
		time.Second,
	)
	if err != nil {
		t.Fatalf("NewUnixAuthorityManager: %v", err)
	}
	directory := permitSocketTempDir(t)
	if err := prepareAuthorityTestDirectory(directory); err != nil {
		t.Fatalf("prepare directory: %v", err)
	}
	request := authorityRequest{
		slotID:        uint32(fixture.slot),
		jobGeneration: 15,
		directory:     directory,
		user: strconv.Itoa(os.Getuid()) + ":" +
			strconv.Itoa(os.Getgid()),
	}
	lease, err := manager.Start(context.Background(), request)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	endpoint := lease.endpoint.(*managedUnixAuthority)
	if err := endpoint.server.close(); err != nil {
		t.Fatalf("close server: %v", err)
	}
	if err := os.Remove(lease.socketPath); err != nil {
		t.Fatalf("remove original socket: %v", err)
	}
	replacement, err := net.ListenUnix(
		"unix",
		&net.UnixAddr{Name: lease.socketPath, Net: "unix"},
	)
	if err != nil {
		t.Fatalf("replacement listener: %v", err)
	}
	defer replacement.Close()
	if err := os.Chmod(lease.socketPath, 0o600); err != nil {
		t.Fatalf("replacement chmod: %v", err)
	}
	if err := manager.Stop(context.Background(), lease); !errors.Is(
		err,
		ErrPermitAuthorityUnavailable,
	) {
		t.Fatalf("Stop error = %v, want authority unavailable", err)
	}
	record := fixture.store.mustLoad(t, fixture.slot)
	if record.ActiveJobGeneration != JobGeneration(request.jobGeneration) {
		t.Fatalf("replacement deactivated live ledger: %+v", record)
	}
}

func prepareAuthorityTestDirectory(path string) error {
	if err := os.Chmod(path, 0o700); err != nil {
		return err
	}
	return os.Chown(path, os.Getuid(), os.Getgid())
}
