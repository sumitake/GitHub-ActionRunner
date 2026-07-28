package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"golang.org/x/sys/unix"
)

func TestBrokerControlFIFOsSerializeArmReleaseAndAudit(t *testing.T) {
	directory := shortBrokerTempDir(t)
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	paths := brokerControlPaths{
		directory: directory,
		command:   filepath.Join(directory, brokerCommandFIFOName),
		response:  filepath.Join(directory, brokerResponseFIFOName),
	}
	token := [32]byte{}
	for index := range token {
		token[index] = byte(index + 1)
	}
	digest := sha256.Sum256(token[:])
	readiness := brokerTestReadiness()
	machine := newBrokerMachine(
		func(
			context.Context,
			hostruntime.BrokerReleaseCommand,
		) ([]byte, error) {
			return bytes.Clone(readiness), nil
		},
		func(context.Context) ([]byte, error) {
			return bytes.Clone(readiness), nil
		},
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- serveBrokerCommands(ctx, paths, machine)
	}()
	waitForFIFO(t, paths.command, done)
	waitForFIFO(t, paths.response, done)

	tests := []struct {
		name      string
		operation brokerOperation
		input     []byte
		want      []byte
	}{
		{"arm", brokerOpArm, brokerArmFrame(digest), []byte("OK\n")},
		{"release", brokerOpRelease, brokerReleaseFrame(t, token), readiness},
		{"audit", brokerOpAudit, nil, readiness},
	}
	for _, test := range tests {
		var output bytes.Buffer
		bounded, stop := context.WithTimeout(ctx, 2*time.Second)
		err := forwardBrokerAt(
			bounded,
			paths,
			test.operation,
			bytes.NewReader(test.input),
			&output,
		)
		stop()
		if err != nil || !bytes.Equal(output.Bytes(), test.want) {
			t.Fatalf(
				"%s output=%q err=%v",
				test.name,
				output.Bytes(),
				err,
			)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serveBrokerCommands: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serveBrokerCommands did not stop")
	}
}

func TestBrokerControlRejectsSymlinkedFIFO(t *testing.T) {
	directory := shortBrokerTempDir(t)
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	path := filepath.Join(directory, brokerCommandFIFOName)
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, _, err := openControlFIFO(path, unix.O_WRONLY); err == nil {
		t.Fatal("symlinked control path was accepted")
	}
}

func waitForFIFO(t *testing.T, path string, done <-chan error) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		select {
		case err := <-done:
			t.Fatalf("serveBrokerCommands stopped before fifo %s: %v", path, err)
		default:
		}
		info, err := os.Lstat(path)
		if err == nil && info.Mode()&os.ModeNamedPipe != 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("fifo %s unavailable: %v", path, err)
		}
		time.Sleep(time.Millisecond)
	}
}

func shortBrokerTempDir(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/private/tmp", "pgh-broker-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	if err := os.Chown(directory, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatalf("Chown temp directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}
