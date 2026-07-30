//go:build linux || darwin

package networkjail

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
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
	endpoint := lease.endpoint.(*managedUnixAuthority)
	if endpoint.socketPin == nil {
		t.Fatal("Start did not retain a socket inode pin")
	}
	if err := endpoint.socketPin.verify(); err != nil {
		t.Fatalf("retained socket pin is not exact: %v", err)
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
	_, replacementIdentity, err := readAuthorityPathIdentity(
		lease.socketPath,
		true,
	)
	if err != nil {
		t.Fatalf("replacement identity: %v", err)
	}
	if runtime.GOOS == "linux" && replacementIdentity == lease.socket {
		t.Fatalf(
			"replacement reused pinned socket identity: %+v",
			replacementIdentity,
		)
	}
	if err := endpoint.socketPin.verify(); !errors.Is(
		err,
		ErrPermitAuthorityUnavailable,
	) {
		t.Fatalf("socket pin accepted replacement: %v", err)
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
	if endpoint.closed {
		t.Fatal("pre-close replacement closed the original listener")
	}
	if err := endpoint.server.close(); err != nil {
		t.Fatalf("cleanup original server: %v", err)
	}
	if err := endpoint.socketPin.close(); err != nil {
		t.Fatalf("cleanup socket pin: %v", err)
	}
}

func TestUnixAuthorityManagerQuarantinesPostCloseSocketReplacement(t *testing.T) {
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
		jobGeneration: 16,
		directory:     directory,
		user: strconv.Itoa(os.Getuid()) + ":" +
			strconv.Itoa(os.Getgid()),
	}
	lease, err := manager.Start(context.Background(), request)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	endpoint := lease.endpoint.(*managedUnixAuthority)
	if err := endpoint.socketPin.verify(); err != nil {
		t.Fatalf("pre-close pin verification: %v", err)
	}
	if err := endpoint.server.close(); err != nil {
		t.Fatalf("close server: %v", err)
	}
	endpoint.closed = true
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
		t.Fatalf("post-close mismatch deactivated live ledger: %+v", record)
	}
	if endpoint.socketRemoved ||
		endpoint.socketPinClosed ||
		endpoint.deactivated {
		t.Fatalf("post-close mismatch escaped quarantine: %+v", endpoint)
	}
	if _, err := os.Lstat(lease.socketPath); err != nil {
		t.Fatalf("replacement socket was removed: %v", err)
	}
	if err := endpoint.socketPin.close(); err != nil {
		t.Fatalf("cleanup socket pin: %v", err)
	}
}

func TestUnixAuthorityManagerRejectsParentDirectoryReplacement(t *testing.T) {
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
		jobGeneration: 17,
		directory:     directory,
		user: strconv.Itoa(os.Getuid()) + ":" +
			strconv.Itoa(os.Getgid()),
	}
	lease, err := manager.Start(context.Background(), request)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	endpoint := lease.endpoint.(*managedUnixAuthority)
	relocated := directory + "-relocated"
	if err := os.Rename(directory, relocated); err != nil {
		t.Fatalf("relocate authority directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(relocated); err != nil {
			t.Errorf("remove relocated authority directory: %v", err)
		}
	})
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create replacement directory: %v", err)
	}
	replacementPath := filepath.Join(directory, authoritySocketLiteral)
	replacement, err := net.ListenUnix(
		"unix",
		&net.UnixAddr{Name: replacementPath, Net: "unix"},
	)
	if err != nil {
		t.Fatalf("replacement listener: %v", err)
	}
	defer replacement.Close()
	if err := os.Chmod(replacementPath, 0o600); err != nil {
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
		t.Fatalf("parent replacement deactivated live ledger: %+v", record)
	}
	if endpoint.closed {
		t.Fatal("parent replacement closed the original listener")
	}
	if _, err := os.Lstat(replacementPath); err != nil {
		t.Fatalf("replacement socket was removed: %v", err)
	}
	if err := endpoint.server.close(); err != nil {
		t.Fatalf("cleanup original server: %v", err)
	}
	if err := endpoint.socketPin.close(); err != nil {
		t.Fatalf("cleanup socket pin: %v", err)
	}
}

func prepareAuthorityTestDirectory(path string) error {
	if err := os.Chmod(path, 0o700); err != nil {
		return err
	}
	return os.Chown(path, os.Getuid(), os.Getgid())
}
