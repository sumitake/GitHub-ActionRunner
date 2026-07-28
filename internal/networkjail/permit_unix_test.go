//go:build linux || darwin

package networkjail

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestUnixPermitServerPersistsBeforeCanonicalReply(t *testing.T) {
	fixture := newPermitFixture(t, 4)
	const generation JobGeneration = 9
	fixture.activate(generation)
	socket := filepath.Join(permitSocketTempDir(t), "dial-authority.sock")
	server := startTestPermitServer(t, fixture.authority, socket)
	defer func() {
		if err := server.close(); err != nil {
			t.Fatalf("close server: %v", err)
		}
	}()
	client, err := NewUnixPermitClient(socket, time.Second)
	if err != nil {
		t.Fatalf("NewUnixPermitClient: %v", err)
	}
	request := DialPermitRequest{
		SlotID:        fixture.slot,
		JobGeneration: generation,
		Class:         DialClassJob,
		Sequence:      1,
	}
	permit, err := client.Request(context.Background(), request)
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if !permit.validFor(fixture.slot, DialClassJob) {
		t.Fatal("Unix permit response was not request-bound")
	}
	durable := fixture.store.mustLoad(t, fixture.slot)
	if durable.Job.ReservedHighWater == 0 ||
		durable.Job.ReservedSequence < request.Sequence {
		t.Fatalf("reply preceded durable reservation: %+v", durable.Job)
	}
	if _, err := client.Request(
		context.Background(),
		request,
	); !errors.Is(err, ErrPermitAuthorityUnavailable) {
		t.Fatalf("duplicate Request error = %v, want authority unavailable", err)
	}
}

func TestUnixPermitServerRejectsAncillaryDescriptorsWithoutConsuming(t *testing.T) {
	fixture := newPermitFixture(t, 2)
	const generation JobGeneration = 11
	fixture.activate(generation)
	socket := filepath.Join(permitSocketTempDir(t), "dial-authority.sock")
	server := startTestPermitServer(t, fixture.authority, socket)
	defer func() { _ = server.close() }()

	request := DialPermitRequest{
		SlotID:        fixture.slot,
		JobGeneration: generation,
		Class:         DialClassJob,
		Sequence:      1,
	}
	frame, err := request.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	connection, err := net.DialUnix(
		"unix",
		nil,
		&net.UnixAddr{Name: socket, Net: "unix"},
	)
	if err != nil {
		t.Fatalf("DialUnix: %v", err)
	}
	descriptor, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	rights := unix.UnixRights(int(descriptor.Fd()))
	if _, _, err := connection.WriteMsgUnix(frame, rights, nil); err != nil {
		t.Fatalf("WriteMsgUnix: %v", err)
	}
	if err := connection.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	_ = descriptor.Close()
	_ = connection.Close()

	client, err := NewUnixPermitClient(socket, time.Second)
	if err != nil {
		t.Fatalf("NewUnixPermitClient: %v", err)
	}
	if _, err := client.Request(context.Background(), request); err != nil {
		t.Fatalf("legitimate request after ancillary rejection: %v", err)
	}
}

func TestUnixPermitClientRejectsNoncanonicalResponse(t *testing.T) {
	socket := filepath.Join(permitSocketTempDir(t), "dial-authority.sock")
	listener, err := net.ListenUnix(
		"unix",
		&net.UnixAddr{Name: socket, Net: "unix"},
	)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	defer listener.Close()
	go func() {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		if _, readErr := readExactUnixFrame(
			connection,
			dialPermitRequestFrameBytes,
		); readErr != nil {
			return
		}
		response := make([]byte, dialPermitResponseFrameBytes)
		copy(response[:8], dialPermitResponseMagic[:])
		response[8] = dialPermitResponseVersion
		response[10] = 1
		if writeExactUnixFrame(connection, response) == nil {
			_ = connection.CloseWrite()
		}
	}()

	client, err := NewUnixPermitClient(socket, time.Second)
	if err != nil {
		t.Fatalf("NewUnixPermitClient: %v", err)
	}
	_, err = client.Request(context.Background(), DialPermitRequest{
		SlotID:        1,
		JobGeneration: 1,
		Class:         DialClassJob,
		Sequence:      1,
	})
	if !errors.Is(err, ErrPermitAuthorityUnavailable) {
		t.Fatalf("Request error = %v, want authority unavailable", err)
	}
}

func startTestPermitServer(
	t *testing.T,
	authority *PermitAuthority,
	path string,
) *unixPermitServer {
	t.Helper()
	listener, err := net.ListenUnix(
		"unix",
		&net.UnixAddr{Name: path, Net: "unix"},
	)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	server, err := newUnixPermitServer(authority, listener, 4, time.Second)
	if err != nil {
		_ = listener.Close()
		t.Fatalf("newUnixPermitServer: %v", err)
	}
	server.start(context.Background())
	return server
}

func permitSocketTempDir(t *testing.T) string {
	t.Helper()
	root := "/tmp"
	if runtime.GOOS == "darwin" {
		root = "/private/tmp"
	}
	directory, err := os.MkdirTemp(root, "pghar-permit-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("RemoveAll: %v", err)
		}
	})
	return directory
}
