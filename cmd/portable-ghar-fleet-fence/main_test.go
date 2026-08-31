package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/fleetfence"
)

const (
	fenceHelperModeEnv     = "PORTABLE_GHAR_FENCE_TEST_HELPER_MODE"
	fenceHelperStateEnv    = "PORTABLE_GHAR_FENCE_TEST_STATE_DIR"
	fenceHelperMarkerEnv   = "PORTABLE_GHAR_FENCE_TEST_MARKER"
	fenceHelperDurationEnv = "PORTABLE_GHAR_FENCE_TEST_DURATION"
	fenceHelperIgnoreEnv   = "PORTABLE_GHAR_FENCE_TEST_IGNORE_TERM"
	fenceHelperGrandEnv    = "PORTABLE_GHAR_FENCE_TEST_GRANDCHILD_MARKER"
)

type commandIdentityStub struct{}

func (commandIdentityStub) Current(
	context.Context,
	int,
) (fleetfence.ProcessIdentity, error) {
	return fleetfence.ProcessIdentity{
		BootID:         "test-boot",
		ProcessStartID: "test-process",
	}, nil
}

type changingCommandIdentity struct {
	calls atomic.Uint32
}

func (s *changingCommandIdentity) Current(
	context.Context,
	int,
) (fleetfence.ProcessIdentity, error) {
	call := s.calls.Add(1)
	start := "test-process"
	if call > 1 {
		start = "reused-process"
	}
	return fleetfence.ProcessIdentity{
		BootID:         "test-boot",
		ProcessStartID: start,
	}, nil
}

func testDependencies() commandDependencies {
	return commandDependencies{
		identity:         commandIdentityStub{},
		now:              func() time.Time { return time.Date(2026, 7, 29, 3, 0, 0, 0, time.UTC) },
		effectiveUID:     func() int { return 0 },
		lockPollInterval: time.Millisecond,
		operationTimeout: time.Second,
		renewalInterval:  100 * time.Millisecond,
		renewalTimeout:   50 * time.Millisecond,
		terminationGrace: 100 * time.Millisecond,
	}
}

func privateStateDir(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "fleet")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("mkdir state: %v", err)
	}
	return root
}

func TestFenceGuardSubprocess(t *testing.T) {
	if os.Getenv(fenceHelperModeEnv) != "guard" {
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("executable: %v", err)
	}
	if err := os.Setenv(fenceHelperModeEnv, "workload"); err != nil {
		t.Fatalf("set workload mode: %v", err)
	}
	code := runWithDependencies(
		[]string{
			"guard",
			"--state-dir", os.Getenv(fenceHelperStateEnv),
			"--fleet", "portable",
			"--generation", "1",
			"--",
			executable,
			"-test.run=^TestFenceWorkloadSubprocess$",
			"-test.count=1",
		},
		io.Discard,
		io.Discard,
		testDependencies(),
	)
	if code != 0 {
		t.Fatalf("guard helper exit code = %d", code)
	}
}

func TestFenceWorkloadSubprocess(t *testing.T) {
	if os.Getenv(fenceHelperModeEnv) != "workload" {
		return
	}
	if os.Getenv(fenceHelperIgnoreEnv) == "1" {
		signal.Ignore(syscall.SIGTERM)
		defer signal.Reset(syscall.SIGTERM)
	}
	duration, err := time.ParseDuration(os.Getenv(fenceHelperDurationEnv))
	if err != nil || duration <= 0 {
		t.Fatalf("duration invalid: %v", err)
	}
	var grandchild *exec.Cmd
	if marker := os.Getenv(fenceHelperGrandEnv); marker != "" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatalf("grandchild executable: %v", err)
		}
		grandchild = exec.Command(
			executable,
			"-test.run=^TestFenceGrandchildSubprocess$",
			"-test.count=1",
		)
		grandchild.Env = append(
			os.Environ(),
			fenceHelperModeEnv+"=grandchild",
			fenceHelperMarkerEnv+"="+marker,
			fenceHelperDurationEnv+"="+duration.String(),
			fenceHelperIgnoreEnv+"="+
				os.Getenv(fenceHelperIgnoreEnv),
		)
		grandchild.Stdout = io.Discard
		grandchild.Stderr = io.Discard
		if err := grandchild.Start(); err != nil {
			t.Fatalf("start grandchild: %v", err)
		}
		defer grandchild.Wait()
	}
	writeFenceHelperPID(t, os.Getenv(fenceHelperMarkerEnv))
	time.Sleep(duration)
}

func TestFenceGrandchildSubprocess(t *testing.T) {
	if os.Getenv(fenceHelperModeEnv) != "grandchild" {
		return
	}
	if os.Getenv(fenceHelperIgnoreEnv) == "1" {
		signal.Ignore(syscall.SIGTERM)
		defer signal.Reset(syscall.SIGTERM)
	}
	duration, err := time.ParseDuration(os.Getenv(fenceHelperDurationEnv))
	if err != nil || duration <= 0 {
		t.Fatalf("duration invalid: %v", err)
	}
	writeFenceHelperPID(t, os.Getenv(fenceHelperMarkerEnv))
	time.Sleep(duration)
}

func writeFenceHelperPID(t *testing.T, marker string) {
	t.Helper()
	if marker == "" {
		t.Fatal("PID marker path empty")
	}
	temporary := marker + ".tmp"
	if err := os.WriteFile(
		temporary,
		[]byte(strconv.Itoa(os.Getpid())),
		0o600,
	); err != nil {
		t.Fatalf("write PID marker temporary: %v", err)
	}
	if err := os.Rename(temporary, marker); err != nil {
		t.Fatalf("publish PID marker: %v", err)
	}
}

func bootstrapPortableFence(
	t *testing.T,
	root string,
	dependencies commandDependencies,
) {
	t.Helper()
	code, _, _ := invoke(
		t,
		dependencies,
		"handoff",
		"--state-dir", root,
		"--from", "none",
		"--to", "portable",
		"--expected-generation", "0",
		"--json",
	)
	if code != 0 {
		t.Fatal("bootstrap failed")
	}
}

func startFenceGuardHelper(
	t *testing.T,
	root string,
	duration time.Duration,
	ignoreTermination bool,
) (*exec.Cmd, int) {
	command, childPID, _ := startFenceGuardTreeHelper(
		t,
		root,
		duration,
		ignoreTermination,
		false,
	)
	return command, childPID
}

func startFenceGuardTreeHelper(
	t *testing.T,
	root string,
	duration time.Duration,
	ignoreTermination bool,
	spawnGrandchild bool,
) (*exec.Cmd, int, int) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("executable: %v", err)
	}
	marker := filepath.Join(t.TempDir(), "workload-pid")
	grandchildMarker := ""
	if spawnGrandchild {
		grandchildMarker = filepath.Join(t.TempDir(), "grandchild-pid")
	}
	ignore := "0"
	if ignoreTermination {
		ignore = "1"
	}
	command := exec.Command(
		executable,
		"-test.run=^TestFenceGuardSubprocess$",
		"-test.count=1",
	)
	command.Env = append(
		os.Environ(),
		fenceHelperModeEnv+"=guard",
		fenceHelperStateEnv+"="+root,
		fenceHelperMarkerEnv+"="+marker,
		fenceHelperDurationEnv+"="+duration.String(),
		fenceHelperIgnoreEnv+"="+ignore,
		fenceHelperGrandEnv+"="+grandchildMarker,
	)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		t.Fatalf("start guard helper: %v", err)
	}
	childPID := waitForMarkerPID(t, marker, command)
	grandchildPID := 0
	if grandchildMarker != "" {
		grandchildPID = waitForMarkerPID(t, grandchildMarker, command)
	}
	return command, childPID, grandchildPID
}

func waitForMarkerPID(
	t *testing.T,
	marker string,
	command *exec.Cmd,
) int {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		document, readErr := os.ReadFile(marker)
		if readErr == nil {
			pid, parseErr := strconv.Atoi(string(document))
			if parseErr != nil || pid <= 0 {
				_ = command.Process.Kill()
				_ = command.Wait()
				t.Fatalf("workload PID invalid: %q", document)
			}
			return pid
		}
		if !errors.Is(readErr, os.ErrNotExist) || time.Now().After(deadline) {
			_ = command.Process.Kill()
			_ = command.Wait()
			t.Fatalf("wait for workload marker: %v", readErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func waitForProcessExit(t *testing.T, pid int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for processAlive(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("process %d remained alive", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestGuardedChildNeverSignalsAfterReapOrGroupChange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		reaped    bool
		current   int
		wantIs    error
		wantKills int
	}{
		{
			name:      "reaped pid could be reused",
			reaped:    true,
			current:   4100,
			wantIs:    os.ErrProcessDone,
			wantKills: 0,
		},
		{
			name:      "child escaped captured group",
			current:   4200,
			wantKills: 0,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			const pid = 4100
			reaped := make(chan struct{})
			if test.reaped {
				close(reaped)
			}
			kills := 0
			child := &guardedChild{
				command: &exec.Cmd{
					Process: &os.Process{Pid: pid},
				},
				reaped: reaped,
				getpgid: func(int) (int, error) {
					return test.current, nil
				},
				kill: func(int, syscall.Signal) error {
					kills++
					return nil
				},
			}
			child.pgid.Store(pid)
			err := child.signal(syscall.SIGTERM)
			if err == nil ||
				test.wantIs != nil && !errors.Is(err, test.wantIs) ||
				kills != test.wantKills {
				t.Fatalf(
					"signal() error=%v, kills=%d",
					err,
					kills,
				)
			}
		})
	}
}

func invoke(
	t *testing.T,
	dependencies commandDependencies,
	arguments ...string,
) (int, string, string) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runWithDependencies(arguments, &stdout, &stderr, dependencies)
	return code, stdout.String(), stderr.String()
}

func TestGuardChildRetainsFenceIfParentIsKilled(t *testing.T) {
	root := privateStateDir(t)
	dependencies := testDependencies()
	bootstrapPortableFence(t, root, dependencies)
	command, childPID := startFenceGuardHelper(t, root, time.Second, false)
	cleanupNeeded := true
	t.Cleanup(func() {
		if cleanupNeeded {
			_ = command.Process.Kill()
			_ = syscall.Kill(childPID, syscall.SIGKILL)
		}
	})
	if err := command.Process.Kill(); err != nil {
		t.Fatalf("kill guard parent: %v", err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("killed guard parent exited successfully")
	}
	if !processAlive(childPID) {
		t.Fatal("workload did not survive the simulated parent crash")
	}

	bounded := dependencies
	bounded.operationTimeout = 50 * time.Millisecond
	code, _, _ := invoke(
		t,
		bounded,
		"handoff",
		"--state-dir", root,
		"--from", "portable",
		"--to", "legacy",
		"--expected-generation", "1",
		"--json",
	)
	if code != 1 {
		t.Fatalf("handoff crossed live orphaned workload, code = %d", code)
	}

	waitForProcessExit(t, childPID, 3*time.Second)
	code, stdout, stderr := invoke(
		t,
		dependencies,
		"handoff",
		"--state-dir", root,
		"--from", "portable",
		"--to", "legacy",
		"--expected-generation", "1",
		"--json",
	)
	if code != 0 || stderr != "" ||
		stdout != "{\"generation\":2,\"active_fleet\":\"legacy\"}\n" {
		t.Fatalf(
			"post-exit handoff code=%d stdout=%q stderr=%q",
			code,
			stdout,
			stderr,
		)
	}
	cleanupNeeded = false
}

func TestGuardEscalatesForwardedTerminationAndReapsChild(t *testing.T) {
	root := privateStateDir(t)
	dependencies := testDependencies()
	bootstrapPortableFence(t, root, dependencies)
	command, childPID := startFenceGuardHelper(t, root, 5*time.Second, true)
	cleanupNeeded := true
	t.Cleanup(func() {
		if cleanupNeeded {
			_ = command.Process.Kill()
			_ = syscall.Kill(childPID, syscall.SIGKILL)
		}
	})
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal guard parent: %v", err)
	}
	waitResult := make(chan error, 1)
	go func() { waitResult <- command.Wait() }()
	select {
	case err := <-waitResult:
		if err == nil {
			t.Fatal("terminated guard parent exited successfully")
		}
	case <-time.After(time.Second):
		t.Fatal("guard did not escalate ignored termination")
	}
	waitForProcessExit(t, childPID, time.Second)

	code, stdout, stderr := invoke(
		t,
		dependencies,
		"inspect",
		"--state-dir", root,
		"--json",
	)
	if code != 0 || stderr != "" ||
		!strings.Contains(stdout, "\"holders\":[]") {
		t.Fatalf(
			"post-termination inspect code=%d stdout=%q stderr=%q",
			code,
			stdout,
			stderr,
		)
	}
	cleanupNeeded = false
}

func TestGuardTerminatesTheDedicatedChildProcessGroup(t *testing.T) {
	root := privateStateDir(t)
	dependencies := testDependencies()
	bootstrapPortableFence(t, root, dependencies)
	command, childPID, grandchildPID := startFenceGuardTreeHelper(
		t,
		root,
		5*time.Second,
		true,
		true,
	)
	cleanupNeeded := true
	t.Cleanup(func() {
		if cleanupNeeded {
			_ = command.Process.Kill()
			_ = syscall.Kill(childPID, syscall.SIGKILL)
			_ = syscall.Kill(grandchildPID, syscall.SIGKILL)
		}
	})
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal guard parent: %v", err)
	}
	waitResult := make(chan error, 1)
	go func() { waitResult <- command.Wait() }()
	select {
	case err := <-waitResult:
		if err == nil {
			t.Fatal("terminated guard parent exited successfully")
		}
	case <-time.After(time.Second):
		t.Fatal("guard did not terminate its dedicated process group")
	}
	waitForProcessExit(t, childPID, time.Second)
	waitForProcessExit(t, grandchildPID, time.Second)
	cleanupNeeded = false
}

func TestHandoffInspectAndGuardUseOneCanonicalFence(t *testing.T) {
	t.Parallel()

	root := privateStateDir(t)
	dependencies := testDependencies()
	code, stdout, stderr := invoke(
		t,
		dependencies,
		"handoff",
		"--state-dir", root,
		"--from", "none",
		"--to", "portable",
		"--expected-generation", "0",
		"--json",
	)
	if code != 0 || stderr != "" ||
		stdout != "{\"generation\":1,\"active_fleet\":\"portable\"}\n" {
		t.Fatalf("handoff code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}

	code, stdout, stderr = invoke(
		t,
		dependencies,
		"inspect",
		"--state-dir", root,
		"--json",
	)
	if code != 0 || stderr != "" ||
		stdout != "{\"generation\":1,\"active_fleet\":\"portable\",\"holders\":[]}\n" {
		t.Fatalf("inspect code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}

	code, stdout, stderr = invoke(
		t,
		dependencies,
		"guard",
		"--state-dir", root,
		"--fleet", "portable",
		"--generation", "1",
		"--",
		"/usr/bin/true",
	)
	if code != 0 || stdout != "" || stderr != "" {
		t.Fatalf("guard code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = invoke(
		t,
		dependencies,
		"inspect",
		"--state-dir", root,
		"--json",
	)
	if code != 0 || !strings.Contains(stdout, "\"holders\":[]") || stderr != "" {
		t.Fatalf("post-guard inspect code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestGuardNeverStartsChildWithoutExactAuthority(t *testing.T) {
	t.Parallel()

	root := privateStateDir(t)
	dependencies := testDependencies()
	code, _, _ := invoke(
		t,
		dependencies,
		"handoff",
		"--state-dir", root,
		"--from", "none",
		"--to", "portable",
		"--expected-generation", "0",
		"--json",
	)
	if code != 0 {
		t.Fatal("bootstrap failed")
	}
	marker := filepath.Join(t.TempDir(), "child-started")
	code, _, _ = invoke(
		t,
		dependencies,
		"guard",
		"--state-dir", root,
		"--fleet", "portable",
		"--generation", "2",
		"--",
		"/usr/bin/touch", marker,
	)
	if code == 0 {
		t.Fatal("stale guard succeeded")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("child started without authority: %v", err)
	}
}

func TestGuardRenewalFailureTerminatesAndReapsChild(t *testing.T) {
	t.Parallel()

	root := privateStateDir(t)
	dependencies := testDependencies()
	code, _, _ := invoke(
		t,
		dependencies,
		"handoff",
		"--state-dir", root,
		"--from", "none",
		"--to", "portable",
		"--expected-generation", "0",
		"--json",
	)
	if code != 0 {
		t.Fatal("bootstrap failed")
	}
	dependencies.identity = &changingCommandIdentity{}
	dependencies.renewalInterval = 5 * time.Millisecond
	dependencies.renewalTimeout = 20 * time.Millisecond
	dependencies.terminationGrace = 20 * time.Millisecond
	started := time.Now()
	code, _, _ = invoke(
		t,
		dependencies,
		"guard",
		"--state-dir", root,
		"--fleet", "portable",
		"--generation", "1",
		"--",
		"/bin/sleep", "5",
	)
	if code != 1 {
		t.Fatalf("renewal failure code = %d", code)
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("child was not terminated promptly: %s", elapsed)
	}
}

func TestFenceCommandGrammarIsExactAndClosed(t *testing.T) {
	t.Parallel()

	root := privateStateDir(t)
	dependencies := testDependencies()
	tests := [][]string{
		nil,
		{"unknown"},
		{"inspect", "--json", "--state-dir", root},
		{"inspect", "--state-dir", root, "--json", "--json"},
		{"handoff", "--state-dir", root, "--from", "none", "--to", "portable", "--expected-generation", "00", "--json"},
		{"handoff", "--state-dir", root, "--from", "portable", "--to", "portable", "--expected-generation", "1", "--json"},
		{"guard", "--state-dir", root, "--generation", "1", "--fleet", "portable", "--", "/usr/bin/true"},
		{"guard", "--state-dir", root, "--fleet", "portable", "--generation", "1"},
		{"guard", "--state-dir", root, "--fleet", "portable", "--generation", "1", "--", "--state-dir", root},
		{"guard", "--state-dir", root + string(os.PathSeparator) + ".", "--fleet", "portable", "--generation", "1", "--", "/usr/bin/true"},
	}
	for _, arguments := range tests {
		arguments := arguments
		t.Run(strings.Join(arguments, "_"), func(t *testing.T) {
			t.Parallel()
			code, stdout, stderr := invoke(t, dependencies, arguments...)
			if code != 2 || stdout != "" ||
				stderr != "portable-ghar-fleet-fence: unavailable\n" {
				t.Fatalf(
					"args=%q code=%d stdout=%q stderr=%q",
					arguments,
					code,
					stdout,
					stderr,
				)
			}
		})
	}
}

func TestFenceMutationsRequirePrivilegeButInspectDoesNot(t *testing.T) {
	t.Parallel()

	root := privateStateDir(t)
	privileged := testDependencies()
	code, _, _ := invoke(
		t,
		privileged,
		"handoff",
		"--state-dir", root,
		"--from", "none",
		"--to", "portable",
		"--expected-generation", "0",
		"--json",
	)
	if code != 0 {
		t.Fatal("privileged bootstrap failed")
	}
	unprivileged := testDependencies()
	unprivileged.effectiveUID = func() int { return 501 }
	code, _, _ = invoke(
		t,
		unprivileged,
		"handoff",
		"--state-dir", root,
		"--from", "portable",
		"--to", "legacy",
		"--expected-generation", "1",
		"--json",
	)
	if code != 1 {
		t.Fatalf("unprivileged handoff code = %d", code)
	}
	code, stdout, stderr := invoke(
		t,
		unprivileged,
		"inspect",
		"--state-dir", root,
		"--json",
	)
	if code != 0 || !strings.Contains(stdout, "\"generation\":1") || stderr != "" {
		t.Fatalf("unprivileged inspect code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestHandoffSupportsExplicitInactiveFleetGenerations(t *testing.T) {
	t.Parallel()

	root := privateStateDir(t)
	dependencies := testDependencies()
	steps := []struct {
		from       string
		to         string
		expected   string
		generation string
		active     string
	}{
		{from: "none", to: "portable", expected: "0", generation: "1", active: "portable"},
		{from: "portable", to: "none", expected: "1", generation: "2", active: "none"},
		{from: "none", to: "legacy", expected: "2", generation: "3", active: "legacy"},
	}
	for _, step := range steps {
		code, stdout, stderr := invoke(
			t,
			dependencies,
			"handoff",
			"--state-dir", root,
			"--from", step.from,
			"--to", step.to,
			"--expected-generation", step.expected,
			"--json",
		)
		want := "{\"generation\":" + step.generation +
			",\"active_fleet\":\"" + step.active + "\"}\n"
		if code != 0 || stdout != want || stderr != "" {
			t.Fatalf(
				"%s->%s code=%d stdout=%q stderr=%q",
				step.from,
				step.to,
				code,
				stdout,
				stderr,
			)
		}
	}
}
