package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	seedarchive "github.com/sumitake/portable-ghar/internal/archive"
	"github.com/sumitake/portable-ghar/internal/runtimeenv"
	"github.com/sumitake/portable-ghar/internal/runtimelock"
)

func TestGateMachineAcceptsExactOneUseSequence(t *testing.T) {
	token := bytes.Repeat([]byte{0x4a}, 32)
	digest := sha256.Sum256(token)
	namespace := []byte(`{"version":1,"device":11,"inode":22}` + "\n")
	var hydrated []string
	var executed []byte
	var machine *gateMachine
	machine = newGateMachine(
		func(ids []string) error {
			hydrated = slices.Clone(ids)
			return nil
		},
		func() ([]byte, error) { return slices.Clone(namespace), nil },
		func(jit []byte) error {
			if machine.phase != phaseConsumed {
				t.Fatalf("release executor observed phase %v, want consumed", machine.phase)
			}
			executed = slices.Clone(jit)
			return nil
		},
	)

	response, action, err := machine.apply(opHydrateSeeds, []byte(`["actions-checkout","tool-go"]`+"\n"))
	requireGateResponse(t, response, action, err, []byte("OK\n"), false)
	if !slices.Equal(hydrated, []string{"actions-checkout", "tool-go"}) {
		t.Fatalf("hydrated = %q", hydrated)
	}

	response, action, err = machine.apply(opNetNSID, nil)
	requireGateResponse(t, response, action, err, namespace, false)
	response, action, err = machine.apply(opArm, armFrame(digest[:]))
	requireGateResponse(t, response, action, err, []byte("OK\n"), false)
	response, action, err = machine.apply(opNetNSID, nil)
	requireGateResponse(t, response, action, err, namespace, false)
	response, action, err = machine.apply(opRelease, releaseFrame(token, []byte("opaque-jit")))
	requireGateResponse(t, response, action, err, []byte("OK\n"), true)
	if err := action(); err != nil {
		t.Fatalf("release action: %v", err)
	}
	if string(executed) != "opaque-jit" {
		t.Fatalf("executed JIT = %q", executed)
	}
	if err := action(); err == nil {
		t.Fatal("release action executed twice")
	}
	if _, _, err := machine.apply(opRelease, releaseFrame(token, []byte("opaque-jit"))); err == nil {
		t.Fatal("consumed machine accepted second release")
	}
}

func TestGateMachineRejectsOutOfOrderOrDuplicateOperationsTerminally(t *testing.T) {
	digest := sha256.Sum256(bytes.Repeat([]byte{0x51}, 32))
	tests := []struct {
		name string
		op   gateOperation
		data []byte
	}{
		{"arm before hydrate", opArm, armFrame(digest[:])},
		{"netns before hydrate", opNetNSID, nil},
		{"release before hydrate", opRelease, releaseFrame(bytes.Repeat([]byte{0x51}, 32), []byte("jit"))},
		{"unknown", gateOperation(255), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			machine := newGateMachine(noopHydrate, fixedNamespace, noopRelease)
			if _, _, err := machine.apply(tt.op, tt.data); err == nil {
				t.Fatal("invalid first operation accepted")
			}
			if machine.phase != phaseFailed {
				t.Fatalf("phase = %v, want failed", machine.phase)
			}
			if _, _, err := machine.apply(opHydrateSeeds, []byte("[]\n")); err == nil {
				t.Fatal("failed machine accepted later operation")
			}
		})
	}

	machine := newGateMachine(noopHydrate, fixedNamespace, noopRelease)
	if _, _, err := machine.apply(opHydrateSeeds, []byte("[]\n")); err != nil {
		t.Fatalf("first hydrate: %v", err)
	}
	if _, _, err := machine.apply(opHydrateSeeds, []byte("[]\n")); err == nil {
		t.Fatal("duplicate hydrate accepted")
	}
}

func TestParseArmFrameRejectsEveryShapeDivergence(t *testing.T) {
	digest := bytes.Repeat([]byte{0x33}, 32)
	valid := armFrame(digest)
	tests := map[string][]byte{
		"empty":              nil,
		"truncated":          valid[:len(valid)-1],
		"trailing":           append(slices.Clone(valid), 0),
		"bad magic":          mutate(valid, 0, 'X'),
		"bad version":        mutate(valid, 8, 2),
		"bad algorithm":      mutate(valid, 9, 2),
		"short digest field": mutateUint16(valid, 10, 31),
		"zero digest":        armFrame(make([]byte, 32)),
	}
	for name, frame := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseArmFrame(frame); err == nil {
				t.Fatal("parseArmFrame accepted malformed frame")
			}
		})
	}
	got, err := parseArmFrame(valid)
	if err != nil || !slices.Equal(got[:], digest) {
		t.Fatalf("valid parse = %x, %v", got, err)
	}
}

func TestParseReleaseFrameRejectsEveryShapeDivergence(t *testing.T) {
	token := bytes.Repeat([]byte{0x44}, 32)
	valid := releaseFrame(token, []byte("jit"))
	tests := map[string][]byte{
		"empty":        nil,
		"truncated":    valid[:len(valid)-1],
		"trailing":     append(slices.Clone(valid), 0),
		"bad magic":    mutate(valid, 0, 'X'),
		"bad version":  mutate(valid, 8, 2),
		"short token":  mutateUint16(valid, 9, 31),
		"zero token":   releaseFrame(make([]byte, 32), []byte("jit")),
		"zero jit":     releaseFrame(token, nil),
		"oversize jit": releaseFrame(token, bytes.Repeat([]byte{'x'}, maxJITLength+1)),
	}
	for name, frame := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseReleaseFrame(frame); err == nil {
				t.Fatal("parseReleaseFrame accepted malformed frame")
			}
		})
	}
	gotToken, gotJIT, err := parseReleaseFrame(valid)
	if err != nil || !slices.Equal(gotToken[:], token) || string(gotJIT) != "jit" {
		t.Fatalf("valid parse token=%x jit=%q err=%v", gotToken, gotJIT, err)
	}
}

func TestGateMachineWrongTokenConsumesAuthorityAndNeverExecutes(t *testing.T) {
	token := bytes.Repeat([]byte{0x62}, 32)
	digest := sha256.Sum256(token)
	executed := false
	machine := newGateMachine(noopHydrate, fixedNamespace, func(_ []byte) error {
		executed = true
		return nil
	})
	advanceToArmed(t, machine, digest[:])
	if _, _, err := machine.apply(opRelease, releaseFrame(bytes.Repeat([]byte{0x63}, 32), []byte("jit"))); err == nil {
		t.Fatal("wrong release token accepted")
	}
	if executed {
		t.Fatal("listener executor ran after wrong token")
	}
	if machine.phase != phaseFailed {
		t.Fatalf("phase = %v, want failed", machine.phase)
	}
}

func TestSeedSelectionRequiresCanonicalSortedBoundedIDs(t *testing.T) {
	valid, err := parseSeedSelection([]byte(`["actions-checkout","tool-go"]` + "\n"))
	if err != nil || !slices.Equal(valid, []string{"actions-checkout", "tool-go"}) {
		t.Fatalf("valid seed selection = %q, %v", valid, err)
	}
	for name, payload := range map[string][]byte{
		"unsorted":        []byte(`["tool-go","actions-checkout"]` + "\n"),
		"duplicate":       []byte(`["tool-go","tool-go"]` + "\n"),
		"path":            []byte(`["../tool"]` + "\n"),
		"absolute":        []byte(`["/tool"]` + "\n"),
		"noncanonical":    []byte(`[ "tool-go" ]` + "\n"),
		"trailing object": []byte(`[] {}` + "\n"),
		"too many":        []byte("[" + strings.Repeat(`"x",`, maxSeedCount) + `"x"]` + "\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseSeedSelection(payload); err == nil {
				t.Fatal("parseSeedSelection accepted malformed selection")
			}
		})
	}
}

func TestGateSocketServesExactProtocolAndRemovesOwnedSocket(t *testing.T) {
	root := shortSocketRoot(t)
	socketPath := filepath.Join(root, "gate.sock")
	listener, identity, err := listenGateSocket(socketPath)
	if err != nil {
		t.Fatalf("listenGateSocket: %v", err)
	}
	info, err := os.Lstat(socketPath)
	if err != nil || info.Mode().Type() != os.ModeSocket || info.Mode().Perm() != 0o600 {
		t.Fatalf("socket identity mode=%v err=%v", info.Mode(), err)
	}

	token := bytes.Repeat([]byte{0x75}, 32)
	digest := sha256.Sum256(token)
	terminal := errors.New("test release terminal")
	machine := newGateMachine(noopHydrate, fixedNamespace, func(jit []byte) error {
		if string(jit) != "jit" {
			t.Fatalf("release jit = %q", jit)
		}
		return terminal
	})
	serverDone := make(chan error, 1)
	go func() { serverDone <- serveGateListener(listener, identity, machine, 500*time.Millisecond) }()

	invoke := func(operation gateOperation, payload []byte) []byte {
		t.Helper()
		var output bytes.Buffer
		if err := forwardGate(context.Background(), socketPath, operation, bytes.NewReader(payload), &output, 500*time.Millisecond); err != nil {
			t.Fatalf("forwardGate operation %d: %v", operation, err)
		}
		return output.Bytes()
	}
	if got := invoke(opHydrateSeeds, []byte("[]\n")); string(got) != "OK\n" {
		t.Fatalf("hydrate response = %q", got)
	}
	_ = invoke(opNetNSID, nil)
	if got := invoke(opArm, armFrame(digest[:])); string(got) != "OK\n" {
		t.Fatalf("arm response = %q", got)
	}
	_ = invoke(opNetNSID, nil)
	if got := invoke(opRelease, releaseFrame(token, []byte("jit"))); string(got) != "OK\n" {
		t.Fatalf("release response = %q", got)
	}
	select {
	case err := <-serverDone:
		if err == nil {
			t.Fatal("server returned nil after injected exec failure")
		}
	case <-time.After(time.Second):
		t.Fatal("gate server did not terminate after release")
	}
	if _, err := os.Lstat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("owned gate socket remains after terminal release: %v", err)
	}
}

func TestListenGateSocketRejectsPreexistingPathWithoutUnlink(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("Chmod root: %v", err)
	}
	path := filepath.Join(root, "gate.sock")
	if err := os.WriteFile(path, []byte("sentinel"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, _, err := listenGateSocket(path); err == nil {
		t.Fatal("listenGateSocket accepted preexisting path")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "sentinel" {
		t.Fatalf("preexisting path was altered: %q %v", data, err)
	}
}

func TestGateServerSlowClientIsTerminal(t *testing.T) {
	root := shortSocketRoot(t)
	path := filepath.Join(root, "gate.sock")
	listener, identity, err := listenGateSocket(path)
	if err != nil {
		t.Fatalf("listenGateSocket: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- serveGateListener(listener, identity, newGateMachine(noopHydrate, fixedNamespace, noopRelease), 40*time.Millisecond)
	}()
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("DialUnix: %v", err)
	}
	defer connection.Close()
	if _, err := connection.Write([]byte{byte(opHydrateSeeds)}); err != nil {
		t.Fatalf("write opcode: %v", err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("slow client did not fail the gate")
		}
	case <-time.After(time.Second):
		t.Fatal("slow client did not reach terminal deadline")
	}
}

func TestVerifyListenerRejectsPathModeSizeDigestAndOwnerDrift(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	path := filepath.Join(root, "Runner.Listener")
	contents := []byte("listener-binary")
	if err := os.WriteFile(path, contents, 0o700); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(path, 0o555); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	digest := sha256.Sum256(contents)
	want := listenerIdentity{Path: path, SHA256: hex.EncodeToString(digest[:]), Size: uint64(len(contents)), Mode: 0o555, UID: stat.Uid, GID: stat.Gid}
	file, err := verifyListener(want)
	if err != nil {
		t.Fatalf("verifyListener: %v", err)
	}
	file.Close()

	tests := []struct {
		name   string
		mutate func(listenerIdentity) listenerIdentity
	}{
		{"digest", func(v listenerIdentity) listenerIdentity { v.SHA256 = strings.Repeat("f", 64); return v }},
		{"size", func(v listenerIdentity) listenerIdentity { v.Size++; return v }},
		{"mode", func(v listenerIdentity) listenerIdentity { v.Mode = 0o500; return v }},
		{"uid", func(v listenerIdentity) listenerIdentity { v.UID++; return v }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if file, err := verifyListener(tt.mutate(want)); err == nil {
				file.Close()
				t.Fatal("verifyListener accepted drift")
			}
		})
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	want.Path = alias
	if file, err := verifyListener(want); err == nil {
		file.Close()
		t.Fatal("verifyListener accepted symlink")
	}
}

func TestLoadGateRuntimeLockBindsExactTreeLockListenerEntry(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	runnerRoot := filepath.Join(root, "runner")
	t.Cleanup(func() {
		_ = filepath.WalkDir(runnerRoot, func(path string, entry os.DirEntry, err error) error {
			if err == nil && entry.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	for _, directory := range []string{runnerRoot, filepath.Join(runnerRoot, "bin"), filepath.Join(runnerRoot, "externals")} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatalf("Mkdir %s: %v", directory, err)
		}
	}
	listener := []byte("real-runner-listener")
	target := []byte("tool-target")
	for path, contents := range map[string][]byte{
		filepath.Join(runnerRoot, "bin", "Runner.Listener"): listener,
		filepath.Join(runnerRoot, "externals", "target"):    target,
	} {
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatalf("WriteFile %s: %v", path, err)
		}
		mode := os.FileMode(0o444)
		if strings.HasSuffix(path, "Runner.Listener") {
			mode = 0o555
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatalf("Chmod %s: %v", path, err)
		}
	}
	if err := os.Symlink("target", filepath.Join(runnerRoot, "externals", "tool")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	for _, directory := range []string{filepath.Join(runnerRoot, "bin"), filepath.Join(runnerRoot, "externals")} {
		if err := os.Chmod(directory, 0o555); err != nil {
			t.Fatalf("Chmod %s: %v", directory, err)
		}
	}
	manifest := seedarchive.RunnerTreeManifest{
		SchemaVersion: 1,
		Entries: []seedarchive.RunnerTreeEntry{
			{Path: "bin", Type: seedarchive.RunnerEntryDirectory, Mode: 0o555},
			{Path: "bin/Runner.Listener", Type: seedarchive.RunnerEntryRegular, SHA256: testSHAHex(listener), Size: uint64(len(listener)), Mode: 0o555},
			{Path: "externals", Type: seedarchive.RunnerEntryDirectory, Mode: 0o555},
			{Path: "externals/target", Type: seedarchive.RunnerEntryRegular, SHA256: testSHAHex(target), Size: uint64(len(target)), Mode: 0o444},
			{Path: "externals/tool", Type: seedarchive.RunnerEntrySymlink, SHA256: testSHAHex([]byte("target")), Size: uint64(len("target")), LinkTarget: "target"},
		},
	}
	verified, err := seedarchive.VerifyRunnerDirectory(runnerRoot, manifest, 7)
	if err != nil {
		t.Fatalf("VerifyRunnerDirectory: %v", err)
	}
	lock, err := runtimelock.NewRunnerLock(verified, "bin/Runner.Listener")
	if err != nil {
		t.Fatalf("NewRunnerLock: %v", err)
	}
	encoded, err := runtimelock.Encode(lock)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var treeBuffer bytes.Buffer
	if err := seedarchive.WriteRunnerTreeLock(&treeBuffer, verified); err != nil {
		t.Fatalf("WriteRunnerTreeLock: %v", err)
	}
	tree := treeBuffer.Bytes()
	if !bytes.Contains(tree, []byte("\nL\texternals/tool\t0000\t")) {
		t.Fatalf("runner tree fixture omitted symlink line: %q", tree)
	}
	lockPath := filepath.Join(root, "runtime-lock.json")
	treePath := filepath.Join(root, "runner-tree.lock")
	for path, contents := range map[string][]byte{lockPath: encoded, treePath: tree} {
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if err := os.Chmod(path, 0o444); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
	}
	identity, err := loadGateRuntimeLock(lockPath, treePath)
	if err != nil {
		t.Fatalf("loadGateRuntimeLock: %v", err)
	}
	if identity.Path != lock.Listener.Path || identity.SHA256 != testSHAHex(listener) || identity.Size != uint64(len(listener)) {
		t.Fatalf("identity = %+v", identity)
	}
	if err := os.Chmod(treePath, 0o600); err != nil {
		t.Fatalf("Chmod tree: %v", err)
	}
	if err := os.WriteFile(treePath, append(tree, 'x'), 0o600); err != nil {
		t.Fatalf("mutate tree: %v", err)
	}
	if _, err := loadGateRuntimeLock(lockPath, treePath); err == nil {
		t.Fatal("loadGateRuntimeLock accepted tree-lock drift")
	}
}

func testSHAHex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func TestListenerExecBoundaryAcceptsOnlyTheClosedListenerEnvironment(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	path := filepath.Join(root, "Runner.Listener")
	if err := os.WriteFile(path, []byte("listener"), 0o555); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer file.Close()
	descriptorPath := "/proc/self/fd/" + strconv.FormatUint(uint64(file.Fd()), 10)
	argv := []string{path, "run"}
	environment := runtimeenv.Listener("opaque-jit")
	if err := validateListenerExecBoundary(file, descriptorPath, argv, environment); err != nil {
		t.Fatalf("validateListenerExecBoundary exact environment: %v", err)
	}
	for name, mutation := range map[string][]string{
		"image only": runtimeenv.Image(),
		"extra":      append(runtimeenv.Listener("opaque-jit"), "EXTRA=value"),
		"reordered":  {runtimeenv.Language, runtimeenv.Home, runtimeenv.Path, runtimeenv.JITName + "opaque-jit"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateListenerExecBoundary(file, descriptorPath, argv, mutation); err == nil {
				t.Fatal("validateListenerExecBoundary accepted a noncanonical environment")
			}
		})
	}
}

func TestRunForwardsOnlyTheClosedGateSubcommands(t *testing.T) {
	root := shortSocketRoot(t)
	socketPath := filepath.Join(root, "gate.sock")
	listener, identity, err := listenGateSocket(socketPath)
	if err != nil {
		t.Fatalf("listenGateSocket: %v", err)
	}
	token := bytes.Repeat([]byte{0x73}, 32)
	digest := sha256.Sum256(token)
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- serveGateListener(
			listener,
			identity,
			newGateMachine(noopHydrate, fixedNamespace, noopRelease),
			500*time.Millisecond,
		)
	}()
	runtime := gateRuntime{socketPath: socketPath, ioTimeout: 500 * time.Millisecond}
	for _, call := range []struct {
		name    string
		stdin   []byte
		wantOut string
	}{
		{"hydrate-seeds", []byte("[]\n"), "OK\n"},
		{"netns-id", nil, `{"version":1,"device":11,"inode":22}` + "\n"},
		{"arm", armFrame(digest[:]), "OK\n"},
		{"netns-id", nil, `{"version":1,"device":11,"inode":22}` + "\n"},
		{"release", releaseFrame(token, []byte("jit")), "OK\n"},
	} {
		var stdout, stderr bytes.Buffer
		code := run([]string{call.name}, bytes.NewReader(call.stdin), &stdout, &stderr, runtime)
		if code != 0 || stdout.String() != call.wantOut || stderr.Len() != 0 {
			t.Fatalf("%s code=%d stdout=%q stderr=%q", call.name, code, stdout.String(), stderr.String())
		}
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("gate server: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("gate server did not finish")
	}

	for _, args := range [][]string{
		nil,
		{"unknown"},
		{"arm", "extra"},
		{"netns-id", "extra"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(args, bytes.NewReader(nil), &stdout, &stderr, runtime); code != 2 || stdout.Len() != 0 || stderr.String() != "portable-ghar-runner-gate: unavailable\n" {
			t.Fatalf("run(%q) code=%d stdout=%q stderr=%q", args, code, stdout.String(), stderr.String())
		}
	}
}

func TestRunVerifyImageIsBuildOnlyAndFailClosed(t *testing.T) {
	called := 0
	runtime := gateRuntime{
		verifyImage: func() error {
			called++
			return nil
		},
	}
	var stdout, stderr bytes.Buffer
	if code := run(
		[]string{"verify-image"},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
		runtime,
	); code != 0 || stdout.String() != "2.336.0\n" || stderr.Len() != 0 || called != 1 {
		t.Fatalf("verify-image code/output/called = %d/%q/%q/%d", code, stdout.String(), stderr.String(), called)
	}

	runtime.verifyImage = func() error { return errors.New("invalid image") }
	stdout.Reset()
	stderr.Reset()
	if code := run(
		[]string{"verify-image"},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
		runtime,
	); code != 1 || stdout.Len() != 0 ||
		stderr.String() != "portable-ghar-runner-gate: unavailable\n" {
		t.Fatalf("failed verify-image code/output = %d/%q/%q", code, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run(
		[]string{"verify-image", "extra"},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
		runtime,
	); code != 2 {
		t.Fatalf("verify-image extra args code=%d", code)
	}
}

func TestExecuteVerifiedListenerUsesDescriptorPathAndMinimalJITEnvironment(t *testing.T) {
	t.Setenv("PORTABLE_GHAR_AMBIENT_POISON", "must-not-cross-exec")
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	listenerPath := filepath.Join(root, "Runner.Listener")
	contents := []byte("listener-binary")
	if err := os.WriteFile(listenerPath, contents, 0o555); err != nil {
		t.Fatalf("WriteFile listener: %v", err)
	}
	info, err := os.Lstat(listenerPath)
	if err != nil {
		t.Fatalf("Lstat listener: %v", err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	digest := sha256.Sum256(contents)
	identity := listenerIdentity{
		Path: listenerPath, SHA256: hex.EncodeToString(digest[:]), Size: uint64(len(contents)),
		Mode: 0o555, UID: stat.Uid, GID: stat.Gid,
	}
	jit := []byte("opaque-jit")
	called := false
	err = executeVerifiedListener(identity, jit, func(file *os.File, path string, argv, env []string) error {
		called = true
		if file == nil || path != "/proc/self/fd/"+strconv.FormatUint(uint64(file.Fd()), 10) {
			t.Fatalf("descriptor path=%q file=%v", path, file)
		}
		if !slices.Equal(argv, []string{listenerPath, "run"}) {
			t.Fatalf("argv=%q", argv)
		}
		if !slices.Equal(env, []string{
			"HOME=/runner",
			"LANG=C.UTF-8",
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"ACTIONS_RUNNER_INPUT_JITCONFIG=opaque-jit",
		}) {
			t.Fatalf("env=%q", env)
		}
		if strings.Contains(strings.Join(env, "\x00"), "PORTABLE_GHAR_AMBIENT_POISON") ||
			strings.Contains(strings.Join(env, "\x00"), "must-not-cross-exec") {
			t.Fatal("ambient environment crossed the listener exec boundary")
		}
		if strings.Contains(strings.Join(argv, "\x00"), "opaque-jit") {
			t.Fatal("JIT appeared in argv")
		}
		return errors.New("injected exec failure")
	})
	if err == nil || !called {
		t.Fatalf("executeVerifiedListener=%v called=%v", err, called)
	}
	if !allZero(jit) {
		t.Fatalf("JIT buffer was not destroyed: %x", jit)
	}

	nulJIT := []byte{'a', 0, 'b'}
	if err := executeVerifiedListener(identity, nulJIT, func(*os.File, string, []string, []string) error {
		t.Fatal("executor ran for NUL-bearing JIT")
		return nil
	}); err == nil || !allZero(nulJIT) {
		t.Fatalf("NUL JIT result=%v buffer=%x", err, nulJIT)
	}
}

func advanceToArmed(t *testing.T, machine *gateMachine, digest []byte) {
	t.Helper()
	if _, _, err := machine.apply(opHydrateSeeds, []byte("[]\n")); err != nil {
		t.Fatalf("hydrate: %v", err)
	}
	if _, _, err := machine.apply(opNetNSID, nil); err != nil {
		t.Fatalf("pre netns: %v", err)
	}
	if _, _, err := machine.apply(opArm, armFrame(digest)); err != nil {
		t.Fatalf("arm: %v", err)
	}
	if _, _, err := machine.apply(opNetNSID, nil); err != nil {
		t.Fatalf("final netns: %v", err)
	}
}

func requireGateResponse(t *testing.T, response []byte, action func() error, err error, want []byte, wantAction bool) {
	t.Helper()
	if err != nil {
		t.Fatalf("gate operation: %v", err)
	}
	if !slices.Equal(response, want) {
		t.Fatalf("response = %q, want %q", response, want)
	}
	if (action != nil) != wantAction {
		t.Fatalf("action present = %t, want %t", action != nil, wantAction)
	}
}

func armFrame(digest []byte) []byte {
	frame := make([]byte, 44)
	copy(frame[:8], "PGHARARM")
	frame[8], frame[9] = 1, 1
	binary.BigEndian.PutUint16(frame[10:12], 32)
	copy(frame[12:], digest)
	return frame
}

func releaseFrame(token, jit []byte) []byte {
	frame := make([]byte, 47+len(jit))
	copy(frame[:8], "PGHARREL")
	frame[8] = 1
	binary.BigEndian.PutUint16(frame[9:11], 32)
	binary.BigEndian.PutUint32(frame[11:15], uint32(len(jit)))
	copy(frame[15:47], token)
	copy(frame[47:], jit)
	return frame
}

func mutate(frame []byte, offset int, value byte) []byte {
	result := slices.Clone(frame)
	result[offset] = value
	return result
}

func mutateUint16(frame []byte, offset int, value uint16) []byte {
	result := slices.Clone(frame)
	binary.BigEndian.PutUint16(result[offset:offset+2], value)
	return result
}

func noopHydrate(_ []string) error { return nil }
func noopRelease(_ []byte) error   { return nil }
func fixedNamespace() ([]byte, error) {
	return []byte(`{"version":1,"device":11,"inode":22}` + "\n"), nil
}

func shortSocketRoot(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp("/private/tmp", "pghar-gate-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("Chmod root: %v", err)
	}
	return root
}
