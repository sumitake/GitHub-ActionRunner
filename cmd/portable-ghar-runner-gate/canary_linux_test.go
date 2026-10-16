//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/canary"
	"golang.org/x/sys/unix"
)

func canaryWorkflowFixture(t *testing.T) []byte {
	t.Helper()
	value := canary.Workflow{Version: 1, ReportDigest: strings.Repeat("a", 64), WorkflowRunID: 42, Revision: strings.Repeat("b", 40), CheckoutHTTPS: true, SandboxVerified: true, InheritedJITAbsent: true, ListenerProcReadable: true, DecodedCredentialsReadable: true, CredentialProbeCompleted: true, Tools: canary.RequiredTools()}
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return document
}
func privateCanaryDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return directory
}
func serveCanary(t *testing.T, directory string, document []byte) {
	t.Helper()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(directory, canaryReportSocketName), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(listener.Addr().String(), 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := listener.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		_, _ = connection.Write(document)
	}()
}

func TestCanarySocketReturnsPendingUntilFinalStepListens(t *testing.T) {
	directory := privateCanaryDirectory(t)
	probe, err := readCanarySocket(directory, uint32(os.Geteuid()), time.Second)
	if err != nil || !probe.Pending || probe.Workflow != nil {
		t.Fatal("absent result not pending", err)
	}
	serveCanary(t, directory, canaryWorkflowFixture(t))
	probe, err = readCanarySocket(directory, uint32(os.Geteuid()), time.Second)
	if err != nil || probe.Pending || probe.Workflow == nil || probe.Workflow.WorkflowRunID != 42 {
		t.Fatal("valid result not observed", err)
	}
}
func TestCanarySocketRefusesUnboundedOrNoncanonicalData(t *testing.T) {
	for name, document := range map[string][]byte{
		"too large":     bytes.Repeat([]byte("x"), canary.MaxWorkflowBytes+1),
		"empty":         nil,
		"invalid":       []byte("{}"),
		"trailing data": append(canaryWorkflowFixture(t), '\n'),
	} {
		t.Run(name, func(t *testing.T) {
			directory := privateCanaryDirectory(t)
			serveCanary(t, directory, document)
			if _, err := readCanarySocket(directory, uint32(os.Geteuid()), time.Second); err == nil {
				t.Fatal("invalid workflow accepted")
			}
		})
	}
}
func TestCanarySocketRejectsIndirectPublicOrForeignEndpoints(t *testing.T) {
	for _, kind := range []string{"regular file", "public parent", "public socket", "wrong owner", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			directory := privateCanaryDirectory(t)
			uid := uint32(os.Geteuid())
			path := filepath.Join(directory, canaryReportSocketName)
			if kind == "regular file" {
				if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				serveCanary(t, directory, canaryWorkflowFixture(t))
			}
			switch kind {
			case "public parent":
				if err := os.Chmod(directory, 0755); err != nil {
					t.Fatal(err)
				}
			case "public socket":
				if err := os.Chmod(path, 0666); err != nil {
					t.Fatal(err)
				}
			case "wrong owner":
				uid++
			case "symlink":
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".original", path); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := readCanarySocket(directory, uid, time.Second); err == nil {
				t.Fatal("untrusted endpoint accepted")
			}
		})
	}
}

func TestCanarySocketStatRequiresEachIdentityAndPermissionFact(t *testing.T) {
	valid := unix.Stat_t{Mode: unix.S_IFSOCK | 0600, Uid: 42, Nlink: 1, Ino: 9}
	if !validCanarySocketStat(valid, 42) {
		t.Fatal("valid socket rejected")
	}
	for _, change := range []func(*unix.Stat_t){
		func(s *unix.Stat_t) { s.Mode = unix.S_IFREG | 0600 },
		func(s *unix.Stat_t) { s.Mode = unix.S_IFSOCK | 0666 },
		func(s *unix.Stat_t) { s.Uid++ },
		func(s *unix.Stat_t) { s.Nlink++ },
		func(s *unix.Stat_t) { s.Ino = 0 },
	} {
		stat := valid
		change(&stat)
		if validCanarySocketStat(stat, 42) {
			t.Fatal("incomplete socket identity accepted")
		}
	}
}
