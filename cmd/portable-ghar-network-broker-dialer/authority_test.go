package main

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestInspectAuthorityFilesystemReturnsCanonicalExactIdentity(t *testing.T) {
	root := shortBrokerTempDir(t)
	directory := filepath.Join(root, "authority")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chown(directory, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatalf("chown directory: %v", err)
	}
	socket := filepath.Join(directory, "dial-authority.sock")
	listener, err := net.ListenUnix(
		"unix",
		&net.UnixAddr{Name: socket, Net: "unix"},
	)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	listener.SetUnlinkOnClose(false)
	defer func() {
		_ = listener.Close()
		_ = os.Remove(socket)
	}()
	if err := os.Chmod(socket, 0o600); err != nil {
		t.Fatalf("chmod socket: %v", err)
	}
	if err := os.Chown(socket, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatalf("chown socket: %v", err)
	}
	document, err := inspectAuthorityFilesystemAt(directory, socket)
	if err != nil {
		t.Fatalf("inspectAuthorityFilesystemAt: %v", err)
	}
	var wire authorityFilesystemDocument
	if err := json.Unmarshal(document, &wire); err != nil ||
		wire.Version != 1 ||
		wire.Directory.Device == 0 ||
		wire.Directory.Inode == 0 ||
		wire.Directory.Mode != 0o700 ||
		wire.Socket.Name != "dial-authority.sock" ||
		wire.Socket.Device != wire.Directory.Device ||
		wire.Socket.Inode == 0 ||
		wire.Socket.Mode != 0o600 {
		t.Fatalf("wire=%+v err=%v", wire, err)
	}
	if !bytes.HasPrefix(document, []byte(`{"version":1,"directory":`)) ||
		!bytes.Contains(document, []byte(`"name":"dial-authority.sock"`)) ||
		!bytes.HasSuffix(document, []byte("}\n")) {
		t.Fatalf("document=%q", document)
	}
}

func TestInspectAuthorityFilesystemRejectsIndirectDirectory(t *testing.T) {
	root := shortBrokerTempDir(t)
	directory := filepath.Join(root, "authority")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chown(directory, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatalf("chown directory: %v", err)
	}
	indirect := filepath.Join(root, "indirect")
	if err := os.Symlink(directory, indirect); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := inspectAuthorityFilesystemAt(
		indirect,
		filepath.Join(indirect, "dial-authority.sock"),
	); err == nil {
		t.Fatal("indirect authority directory was accepted")
	}
}
