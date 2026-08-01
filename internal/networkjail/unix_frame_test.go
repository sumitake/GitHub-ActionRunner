//go:build linux || darwin

package networkjail

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestReadDialRequestUnixAcceptsOneExactDataMessage(t *testing.T) {
	reader, writer := unixStreamPair(t)
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	frame, err := EncodeDialRequest(DialRequest{Host: "example.com", Port: 443})
	if err != nil {
		t.Fatalf("EncodeDialRequest: %v", err)
	}
	if _, _, err := writer.WriteMsgUnix(frame, nil, nil); err != nil {
		t.Fatalf("WriteMsgUnix: %v", err)
	}
	if err := writer.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	request, err := ReadDialRequestUnix(
		context.Background(),
		reader,
		graph,
		time.Second,
	)
	if err != nil {
		t.Fatalf("ReadDialRequestUnix: %v", err)
	}
	if request != (DialRequest{Host: "example.com", Port: 443}) {
		t.Fatalf("request = %#v", request)
	}
}

func TestReadDialRequestUnixRejectsAndClosesSCMRights(t *testing.T) {
	reader, writer := unixStreamPair(t)
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	frame, _ := EncodeDialRequest(DialRequest{Host: "example.com", Port: 443})
	pipeReader, pipeWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer pipeReader.Close()
	defer pipeWriter.Close()
	rights := unix.UnixRights(int(pipeReader.Fd()))
	if _, _, err := writer.WriteMsgUnix(frame, rights, nil); err != nil {
		t.Fatalf("WriteMsgUnix: %v", err)
	}
	if err := writer.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if _, err := ReadDialRequestUnix(
		context.Background(),
		reader,
		graph,
		time.Second,
	); err == nil {
		t.Fatal("ReadDialRequestUnix SCM_RIGHTS = nil error")
	}
}

func TestReadDialRequestUnixRejectsTruncatedMessage(t *testing.T) {
	reader, writer := unixStreamPair(t)
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	oversized := make([]byte, MaxDialRequestFrameBytes+2)
	if _, _, err := writer.WriteMsgUnix(oversized, nil, nil); err != nil {
		t.Fatalf("WriteMsgUnix: %v", err)
	}
	if err := writer.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if _, err := ReadDialRequestUnix(
		context.Background(),
		reader,
		graph,
		time.Second,
	); err == nil {
		t.Fatal("ReadDialRequestUnix truncated data = nil error")
	}
}

func TestReadDialRequestUnixRejectsMissingHalfClose(t *testing.T) {
	reader, writer := unixStreamPair(t)
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	frame, err := EncodeDialRequest(DialRequest{Host: "example.com", Port: 443})
	if err != nil {
		t.Fatalf("EncodeDialRequest: %v", err)
	}
	if _, err := writer.Write(frame); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := ReadDialRequestUnix(
		context.Background(),
		reader,
		graph,
		20*time.Millisecond,
	); err == nil {
		t.Fatal("ReadDialRequestUnix accepted missing half-close")
	}
}

func TestReadDialRequestUnixRejectsExtraBytes(t *testing.T) {
	reader, writer := unixStreamPair(t)
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	frame, err := EncodeDialRequest(DialRequest{Host: "example.com", Port: 443})
	if err != nil {
		t.Fatalf("EncodeDialRequest: %v", err)
	}
	if _, err := writer.Write(append(frame, 'x')); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := writer.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if _, err := ReadDialRequestUnix(
		context.Background(),
		reader,
		graph,
		time.Second,
	); err == nil {
		t.Fatal("ReadDialRequestUnix accepted extra bytes")
	}
}

func unixStreamPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	descriptors, err := unix.Socketpair(
		unix.AF_UNIX,
		unix.SOCK_STREAM,
		0,
	)
	if err != nil {
		t.Fatalf("unix.Socketpair: %v", err)
	}
	unix.CloseOnExec(descriptors[0])
	unix.CloseOnExec(descriptors[1])
	files := []*os.File{
		os.NewFile(uintptr(descriptors[0]), "networkjail-reader"),
		os.NewFile(uintptr(descriptors[1]), "networkjail-writer"),
	}
	connections := make([]*net.UnixConn, 2)
	for index, file := range files {
		connection, err := net.FileConn(file)
		_ = file.Close()
		if err != nil {
			t.Fatalf("net.FileConn %d: %v", index, err)
		}
		unixConnection, ok := connection.(*net.UnixConn)
		if !ok {
			_ = connection.Close()
			t.Fatalf("connection %d type = %T", index, connection)
		}
		connections[index] = unixConnection
		t.Cleanup(func() { _ = unixConnection.Close() })
	}
	return connections[0], connections[1]
}
