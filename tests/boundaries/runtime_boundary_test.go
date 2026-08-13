// SPDX-License-Identifier: MPL-2.0

package boundaries_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	maxBoundaryFileBytes = 32 << 20
	gateRelativePath     = "scripts/test-controller-runtime.sh"
)

var requiredQTSScripts = []string{
	"deploy/qts/install-controller.sh",
	"deploy/qts/install-watchdog.sh",
	"deploy/qts/resume-controller.sh",
	"deploy/qts/rollback-controller.sh",
	"deploy/qts/run-legacy-fenced.sh",
	"deploy/qts/suspend-controller.sh",
	"deploy/qts/uninstall-controller.sh",
	"deploy/qts/uninstall-watchdog.sh",
	"deploy/qts/verify-controller.sh",
	"deploy/qts/lib/host-runtime.sh",
	"deploy/qts/lib/operation-journal.sh",
	"deploy/qts/lib/runtime-manifest.sh",
}

var publicNetworkSurfaceFiles = map[string]struct{}{
	"cmd/portable-ghar-controller/local_client.go":               {},
	"cmd/portable-ghar-network-adapter/control.go":               {},
	"cmd/portable-ghar-network-adapter/relay.go":                 {},
	"cmd/portable-ghar-network-verifier/closed_denials_linux.go": {},
	"cmd/portable-ghar-network-verifier/flood.go":                {},
	"cmd/portable-ghar-network-verifier/probe.go":                {},
	"cmd/portable-ghar-runner-gate/socket.go":                    {},
	"cmd/portable-ghar-task11-listener/proxy.go":                 {},
	"internal/githubscale/client.go":                             {},
	"internal/networkjail/broker_parser.go":                      {},
	"internal/networkjail/doh.go":                                {},
	"internal/networkjail/literal_dialer.go":                     {},
	"internal/networkjail/permit_unix.go":                        {},
	"internal/upgrade/runner_release.go":                         {},
}

type parsedGoFile struct {
	relative string
	source   []byte
	file     *ast.File
	fileset  *token.FileSet
	imports  map[string]string
}

type gateStage struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

type gateSummary struct {
	SchemaVersion int         `json:"schema_version"`
	Gate          string      `json:"gate"`
	Mode          string      `json:"mode"`
	Status        string      `json:"status"`
	FailedStage   *string     `json:"failed_stage"`
	LinuxDocker   string      `json:"linux_docker"`
	Stages        []gateStage `json:"stages"`
}

func TestRuntimeBoundary(t *testing.T) {
	root := repositoryRoot(t)
	tracked := trackedFiles(t, root)
	production := productionGoFiles(t, root)

	t.Run("module_and_lifecycle", func(t *testing.T) {
		checkModuleAndLifecycle(t, root, tracked)
	})
	t.Run("imports_and_authority", func(t *testing.T) {
		checkImportsAndAuthority(t, production)
	})
	t.Run("container_isolation", func(t *testing.T) {
		checkContainerIsolation(t, production)
	})
	t.Run("network_and_permit", func(t *testing.T) {
		checkNetworkAndPermit(t, production)
	})
	t.Run("secret_and_bounded_readers", func(t *testing.T) {
		checkSecretsAndReaders(t, production)
	})
	t.Run("pins_sizing_upgrade_and_fence", func(t *testing.T) {
		checkPinsSizingUpgradeAndFence(t, root, production)
	})
	t.Run("tracked_artifacts_and_fixtures", func(t *testing.T) {
		checkTrackedArtifactsAndFixtures(t, root, tracked)
	})
	t.Run("runtime_gate_source", func(t *testing.T) {
		checkGateSource(t, root)
	})
}

func TestBoundaryScannerRejectsSyntheticRegressions(t *testing.T) {
	t.Run("arc_import", func(t *testing.T) {
		source := []byte("package p\nimport _ \"sigs.k8s.io/actions-runner-controller/pkg\"\n")
		if len(importPolicyIssues("internal/example/p.go", source)) == 0 {
			t.Fatal("ARC import was accepted")
		}
	})
	t.Run("scaleset_escape", func(t *testing.T) {
		source := []byte("package p\nimport _ \"github.com/actions/scaleset\"\n")
		if len(importPolicyIssues("internal/example/p.go", source)) == 0 {
			t.Fatal("scale-set import outside adapter was accepted")
		}
	})
	t.Run("unbounded_read_all", func(t *testing.T) {
		source := []byte("package p\nimport \"io\"\nfunc f(r io.Reader) { _, _ = io.ReadAll(r) }\n")
		parsed, err := parseGo("internal/example/p.go", source)
		if err != nil {
			t.Fatal(err)
		}
		if len(unboundedReadAllIssues(parsed)) == 0 {
			t.Fatal("unbounded io.ReadAll was accepted")
		}
	})
	t.Run("parallel_prepermit_dial", func(t *testing.T) {
		source := []byte(`package p
func (d *BrokerDialer) DialFrame() {
	go d.literals.DialLiteral()
	d.permits.Request()
}`)
		parsed, err := parseGo("internal/networkjail/dialer.go", source)
		if err != nil {
			t.Fatal(err)
		}
		if len(brokerDialIssues(parsed)) == 0 {
			t.Fatal("parallel pre-permit dial was accepted")
		}
	})
	t.Run("comment_only_prepermit", func(t *testing.T) {
		source := []byte(`package p
func (d *BrokerDialer) DialFrame() {
	// d.permits.Request()
	d.literals.DialLiteral()
	d.permits.Request()
}`)
		parsed, err := parseGo("internal/networkjail/dialer.go", source)
		if err != nil {
			t.Fatal(err)
		}
		if len(brokerDialIssues(parsed)) == 0 {
			t.Fatal("comment-only pre-permit ordering was accepted")
		}
	})
	t.Run("doh_submission_after_dial", func(t *testing.T) {
		source := []byte(`package p
func (d *dohConnector) DialTLSContext() {
	d.literals.DialLiteral()
	d.sequencer.request()
}
func (s *PermitSequencer) request() {
	request.Sequence = s.sequence
	client.Request()
}`)
		parsed, err := parseGo("internal/networkjail/doh.go", source)
		if err != nil {
			t.Fatal(err)
		}
		if len(dohDialIssues(parsed)) == 0 {
			t.Fatal("post-dial DoH permit submission was accepted")
		}
	})
	t.Run("doh_helper_without_permit_submission", func(t *testing.T) {
		source := []byte(`package p
func (d *dohConnector) DialTLSContext() {
	d.sequencer.request()
	d.literals.DialLiteral()
}
func (s *PermitSequencer) request() {
	request.Sequence = s.sequence
}`)
		parsed, err := parseGo("internal/networkjail/doh.go", source)
		if err != nil {
			t.Fatal(err)
		}
		if len(dohDialIssues(parsed)) == 0 {
			t.Fatal("DoH helper without permit submission was accepted")
		}
	})
	t.Run("runner_docker_surface", func(t *testing.T) {
		tokens := []string{
			"--network",
			"container:",
			"--mount",
			"/var/run/docker.sock",
			"--device",
		}
		if len(runnerArgvIssues(tokens)) == 0 {
			t.Fatal("runner Docker socket/device/mount surface was accepted")
		}
	})
	t.Run("comment_only_runner_contract", func(t *testing.T) {
		source := []byte(`package p
func runnerCreateArgv() []string {
	// "--network", "container:"
	// "--cap-drop", "ALL"
	// "--read-only"
	// "no-new-privileges=true"
	// "--restart", "no"
	// "--memory"
	// "--memory-swap"
	// "--pids-limit"
	// "--ulimit"
	// "--log-driver", "local"
	// "--tmpfs" "--tmpfs" "--tmpfs"
	return []string{}
}`)
		parsed, err := parseGo("internal/hostruntime/dockercli.go", source)
		if err != nil {
			t.Fatal(err)
		}
		tokens, ok := returnedStringArgv(parsed, "runnerCreateArgv")
		if !ok || len(runnerArgvIssues(tokens)) == 0 {
			t.Fatal("comment-only runner contract was accepted")
		}
	})
	t.Run("upstream_archive", func(t *testing.T) {
		if trackedPathIssue("fixtures/actions-runner-linux-x64.tar.gz") == "" {
			t.Fatal("upstream archive was accepted")
		}
	})
	t.Run("private_fixture_identity", func(t *testing.T) {
		email := strings.Join([]string{"operator", "private.test"}, "@")
		if fixtureContentIssue([]byte(`{"email":"`+email+`"}`)) == "" {
			t.Fatal("non-synthetic fixture identity was accepted")
		}
	})
	t.Run("missing_lifecycle_script", func(t *testing.T) {
		tracked := map[string]bool{}
		modes := map[string]fs.FileMode{}
		for _, name := range requiredQTSScripts[1:] {
			tracked[name] = true
			modes[name] = 0o755
		}
		if len(requiredScriptIssues(tracked, modes)) == 0 {
			t.Fatal("missing lifecycle script was accepted")
		}
	})
}

func TestRuntimeGateRejectsInvalidArguments(t *testing.T) {
	root := repositoryRoot(t)
	script := filepath.Join(root, gateRelativePath)
	requireExecutable(t, script)

	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "missing"},
		{name: "unknown", args: []string{"--other"}},
		{name: "extra", args: []string{"--unit", "--full"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := exec.Command(script, test.args...)
			command.Dir = root
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			command.Stdout = &stdout
			command.Stderr = &stderr
			if err := command.Run(); err == nil {
				t.Fatal("invalid arguments returned success")
			}
			if stdout.Len() != 0 {
				t.Fatalf("invalid arguments emitted stdout: %q", stdout.String())
			}
			if stderr.String() != "arguments\n" {
				t.Fatalf("invalid arguments stderr = %q", stderr.String())
			}
		})
	}
}

func TestRuntimeGateContainsToolFailureAndCleansPrivateLogs(t *testing.T) {
	root := repositoryRoot(t)
	script := filepath.Join(root, gateRelativePath)
	requireExecutable(t, script)

	parent := t.TempDir()
	fakeBin := filepath.Join(parent, "bin")
	if err := os.Mkdir(fakeBin, 0o700); err != nil {
		t.Fatal(err)
	}
	fakeGofmt := filepath.Join(fakeBin, "gofmt")
	if err := os.WriteFile(
		fakeGofmt,
		[]byte("#!/bin/sh\nprintf '%s\\n' FAKE_GOFMT_PRIVATE_OUTPUT >&2\nexit 1\n"),
		0o700,
	); err != nil {
		t.Fatal(err)
	}
	tmpRoot := filepath.Join(parent, "tmp")
	if err := os.Mkdir(tmpRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	command := exec.Command(script, "--unit")
	command.Dir = root
	command.Env = append(
		os.Environ(),
		"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"TMPDIR="+tmpRoot,
	)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err == nil {
		t.Fatal("failing gofmt returned success")
	}
	if strings.Contains(stdout.String(), "FAKE_GOFMT") ||
		strings.Contains(stderr.String(), "FAKE_GOFMT") {
		t.Fatal("subordinate output crossed the gate boundary")
	}
	summary := decodeSummary(t, stdout.Bytes())
	if summary.Mode != "unit" || summary.Status != "fail" ||
		summary.FailedStage == nil || *summary.FailedStage != "gofmt" ||
		summary.LinuxDocker != "not_run" {
		t.Fatalf("unexpected failure summary: %#v", summary)
	}
	if stderr.String() != "gofmt\n" {
		t.Fatalf("stderr = %q", stderr.String())
	}
	entries, err := os.ReadDir(tmpRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("gate log directory leaked: %v", entries)
	}
}

func TestRuntimeGateNormalizesGoTestFixtureUmask(t *testing.T) {
	root := repositoryRoot(t)
	script := filepath.Join(root, gateRelativePath)
	requireExecutable(t, script)

	parent := t.TempDir()
	fakeBin := filepath.Join(parent, "bin")
	if err := os.Mkdir(fakeBin, 0o700); err != nil {
		t.Fatal(err)
	}
	capturedUmask := filepath.Join(parent, "go-test.umask")
	fakeGo := filepath.Join(fakeBin, "go")
	if err := os.WriteFile(
		fakeGo,
		[]byte(`#!/bin/sh
case "$1" in
vet)
  exit 0
  ;;
test)
  umask >"$PGHAR_CAPTURE_UMASK"
  exit 1
  ;;
*)
  exit 1
  ;;
esac
`),
		0o700,
	); err != nil {
		t.Fatal(err)
	}
	tmpRoot := filepath.Join(parent, "tmp")
	if err := os.Mkdir(tmpRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	command := exec.Command(script, "--unit")
	command.Dir = root
	command.Env = append(
		os.Environ(),
		"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"PGHAR_CAPTURE_UMASK="+capturedUmask,
		"TMPDIR="+tmpRoot,
	)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err == nil {
		t.Fatal("fake unit failure returned success")
	}
	summary := decodeSummary(t, stdout.Bytes())
	if summary.FailedStage == nil || *summary.FailedStage != "unit" {
		t.Fatalf("unexpected failure summary: %#v", summary)
	}
	raw, err := os.ReadFile(capturedUmask)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(raw)); got != "0022" {
		t.Fatalf("go test fixture umask = %q, want 0022", got)
	}
	entries, err := os.ReadDir(tmpRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("gate log directory leaked: %v", entries)
	}
}

func TestRuntimeGateContainsStaticcheckCache(t *testing.T) {
	root := repositoryRoot(t)
	script := filepath.Join(root, gateRelativePath)
	requireExecutable(t, script)

	parent := t.TempDir()
	fakeBin := filepath.Join(parent, "bin")
	if err := os.Mkdir(fakeBin, 0o700); err != nil {
		t.Fatal(err)
	}
	capturedCache := filepath.Join(parent, "staticcheck-cache.path")
	fakeGo := filepath.Join(fakeBin, "go")
	if err := os.WriteFile(
		fakeGo,
		[]byte(`#!/bin/sh
if [ "$1" = tool ] && [ "$2" = staticcheck ]; then
  printf '%s\n' "${STATICCHECK_CACHE:-unset}" >"$PGHAR_CAPTURE_STATICCHECK_CACHE"
  exit 1
fi
if [ "$1" = test ]; then
  printf '%s\n' \
    '--- PASS: TestBrokerDialerRevalidatesThenPermitsEveryLiteralAttempt (0.00s)' \
    '--- PASS: TestBrokerDialerLiteralSkipsResolverAndRequiresPermit (0.00s)' \
    '--- PASS: TestBrokerDialerPermitFailurePreventsKernelDial (0.00s)' \
    '--- PASS: TestDoHResolverUsesOnePermittedLockedPersistentConnection (0.00s)' \
    '--- PASS: TestPollPermitFailureAbortsBeforeAcquireAndLeavesServiceReady (0.00s)' \
    '--- PASS: TestServiceTransitionCancelsAndJoinsOldOperationBeforeOpen (0.00s)' \
    '--- PASS: TestServiceDisabledTransitionRequiresListenerQuiescence (0.00s)' \
    '--- PASS: TestServiceTransitionJoinTimeoutPersistsFatalBeforeTermination (0.00s)' \
    '--- PASS: TestReplayHostedExplicitRouteFailureIsDurableAndNeverAcknowledged (0.00s)' \
    '--- PASS: TestReplayHostedEmptyOwnershipProofIsDurableFailure (0.00s)'
  printf 'ok\tfake/package\t0.001s\n'
fi
exit 0
`),
		0o700,
	); err != nil {
		t.Fatal(err)
	}
	tmpRoot := filepath.Join(parent, "tmp")
	if err := os.Mkdir(tmpRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	command := exec.Command(script, "--unit")
	command.Dir = root
	command.Env = append(
		os.Environ(),
		"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"PGHAR_CAPTURE_STATICCHECK_CACHE="+capturedCache,
		"TMPDIR="+tmpRoot,
	)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err == nil {
		t.Fatal("fake staticcheck failure returned success")
	}
	summary := decodeSummary(t, stdout.Bytes())
	if summary.FailedStage == nil || *summary.FailedStage != "staticcheck" {
		t.Fatalf("unexpected failure summary: %#v", summary)
	}
	raw, err := os.ReadFile(capturedCache)
	if err != nil {
		t.Fatal(err)
	}
	cachePath := strings.TrimSpace(string(raw))
	relative, err := filepath.Rel(tmpRoot, cachePath)
	if err != nil || relative == "." || strings.HasPrefix(relative, "..") ||
		filepath.Base(cachePath) != "staticcheck-cache" {
		t.Fatalf("staticcheck cache escaped private root: %q", cachePath)
	}
	entries, err := os.ReadDir(tmpRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("gate log/cache directory leaked: %v", entries)
	}
}

func TestRuntimeGateFullModeStopsBeforeDockerOnUnsupportedHost(t *testing.T) {
	root := repositoryRoot(t)
	script := filepath.Join(root, gateRelativePath)
	requireExecutable(t, script)

	parent := t.TempDir()
	fakeBin := filepath.Join(parent, "bin")
	if err := os.Mkdir(fakeBin, 0o700); err != nil {
		t.Fatal(err)
	}
	dockerSentinel := filepath.Join(parent, "docker.invoked")
	fakes := map[string]string{
		"bats":       "#!/bin/sh\nexit 0\n",
		"gofmt":      "#!/bin/sh\nexit 0\n",
		"python3":    "#!/bin/sh\nexit 0\n",
		"shellcheck": "#!/bin/sh\nexit 0\n",
		"uname":      "#!/bin/sh\nprintf '%s\\n' Darwin\n",
		"go": `#!/bin/sh
if [ "$1" = test ]; then
  printf '%s\n' \
    '--- PASS: TestBrokerDialerRevalidatesThenPermitsEveryLiteralAttempt (0.00s)' \
    '--- PASS: TestBrokerDialerLiteralSkipsResolverAndRequiresPermit (0.00s)' \
    '--- PASS: TestBrokerDialerPermitFailurePreventsKernelDial (0.00s)' \
    '--- PASS: TestDoHResolverUsesOnePermittedLockedPersistentConnection (0.00s)' \
    '--- PASS: TestPollPermitFailureAbortsBeforeAcquireAndLeavesServiceReady (0.00s)' \
    '--- PASS: TestServiceTransitionCancelsAndJoinsOldOperationBeforeOpen (0.00s)' \
    '--- PASS: TestServiceDisabledTransitionRequiresListenerQuiescence (0.00s)' \
    '--- PASS: TestServiceTransitionJoinTimeoutPersistsFatalBeforeTermination (0.00s)' \
    '--- PASS: TestReplayHostedExplicitRouteFailureIsDurableAndNeverAcknowledged (0.00s)' \
    '--- PASS: TestReplayHostedEmptyOwnershipProofIsDurableFailure (0.00s)' \
    '--- PASS: TestChaosSourceOptInBoundary (0.00s)'
  printf 'ok\tfake/package\t0.001s\n'
fi
exit 0
`,
		"docker": `#!/bin/sh
: >"$PGHAR_DOCKER_SENTINEL"
exit 0
`,
	}
	for name, source := range fakes {
		if err := os.WriteFile(
			filepath.Join(fakeBin, name),
			[]byte(source),
			0o700,
		); err != nil {
			t.Fatal(err)
		}
	}
	tmpRoot := filepath.Join(parent, "tmp")
	if err := os.Mkdir(tmpRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	command := exec.Command(script, "--full")
	command.Dir = root
	command.Env = append(
		os.Environ(),
		"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"PGHAR_INTEGRATION_DOCKER=1",
		"PGHAR_CHAOS_DOCKER=1",
		"PGHAR_DOCKER_SENTINEL="+dockerSentinel,
		"TMPDIR="+tmpRoot,
	)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err == nil {
		t.Fatal("unsupported full-mode host returned success")
	}
	summary := decodeSummary(t, stdout.Bytes())
	if summary.Status != "fail" || summary.LinuxDocker != "failed" ||
		summary.FailedStage == nil ||
		*summary.FailedStage != "linux-docker-preflight" {
		t.Fatalf("unexpected full-mode summary: %#v", summary)
	}
	if _, err := os.Stat(dockerSentinel); !os.IsNotExist(err) {
		t.Fatalf("Docker was invoked before host rejection: %v", err)
	}
	entries, err := os.ReadDir(tmpRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("gate log directory leaked: %v", entries)
	}
}

func TestRuntimeGateRejectsMissingFocusedTestEvidence(t *testing.T) {
	tests := []struct {
		name        string
		mode        string
		failedStage string
	}{
		{
			name:        "network authority",
			mode:        "missing-network",
			failedStage: "network-authority",
		},
		{
			name:        "chaos source",
			mode:        "missing-chaos-source",
			failedStage: "chaos-source",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			summary, stderr, err := runSyntheticGate(t, "--unit", test.mode)
			if err == nil {
				t.Fatal("missing focused evidence returned success")
			}
			if summary.Status != "fail" || summary.FailedStage == nil ||
				*summary.FailedStage != test.failedStage {
				t.Fatalf("unexpected summary: %#v", summary)
			}
			if stderr != test.failedStage+"\n" {
				t.Fatalf("stderr = %q", stderr)
			}
		})
	}
}

func TestRuntimeGateRejectsTaggedSkipOrEmptyRunEvidence(t *testing.T) {
	for _, mode := range []string{"tagged-skip", "tagged-empty"} {
		t.Run(mode, func(t *testing.T) {
			summary, stderr, err := runSyntheticGate(t, "--full", mode)
			if err == nil {
				t.Fatal("invalid tagged evidence returned success")
			}
			if summary.Status != "fail" || summary.LinuxDocker != "ready" ||
				summary.FailedStage == nil ||
				*summary.FailedStage != "integration-authority" {
				t.Fatalf("unexpected summary: %#v", summary)
			}
			if stderr != "integration-authority\n" {
				t.Fatalf("stderr = %q", stderr)
			}
		})
	}
}

func runSyntheticGate(
	t *testing.T,
	gateMode string,
	fakeGoMode string,
) (gateSummary, string, error) {
	t.Helper()
	root := repositoryRoot(t)
	script := filepath.Join(root, gateRelativePath)
	requireExecutable(t, script)

	parent := t.TempDir()
	fakeBin := filepath.Join(parent, "bin")
	if err := os.Mkdir(fakeBin, 0o700); err != nil {
		t.Fatal(err)
	}
	fakes := map[string]string{
		"bats":       "#!/bin/sh\nexit 0\n",
		"gofmt":      "#!/bin/sh\nexit 0\n",
		"python3":    "#!/bin/sh\nexit 0\n",
		"shellcheck": "#!/bin/sh\nexit 0\n",
		"uname":      "#!/bin/sh\nprintf '%s\\n' Linux\n",
		"docker":     "#!/bin/sh\nexit 0\n",
		"go": `#!/bin/sh
arguments=" $* "
case "${PGHAR_FAKE_GO_MODE:-}" in
missing-network)
  case "$arguments" in
  *" test ./internal/networkjail -run "*)
    printf 'ok\tfake/networkjail\t0.001s [no tests to run]\n'
    exit 0
    ;;
  esac
  ;;
missing-chaos-source)
  case "$arguments" in
  *" test -tags=chaos ./tests/chaos -run ^TestChaosSourceOptInBoundary$ "*)
    printf 'ok\tfake/chaos\t0.001s [no tests to run]\n'
    exit 0
    ;;
  esac
  ;;
tagged-skip)
  case "$arguments" in
  *" test -tags=integration ./internal/networkjail "*)
    printf '%s\n' '=== RUN   TestSynthetic' '--- SKIP: TestSynthetic (0.00s)'
    printf 'ok\tfake/networkjail\t0.001s\n'
    exit 0
    ;;
  esac
  ;;
tagged-empty)
  case "$arguments" in
  *" test -tags=integration ./internal/networkjail "*)
    printf 'ok\tfake/networkjail\t0.001s [no tests to run]\n'
    exit 0
    ;;
  esac
  ;;
esac
if [ "$1" = "test" ]; then
  case "$arguments" in
  *" ./tests/integration ./tests/conformance "*)
    printf '%s\n' \
      '--- PASS: TestPortableGHARConformance (0.00s)' \
      '--- PASS: TestPublicEvidenceTypesExposeNoCompositeAuthority (0.00s)'
    printf 'ok\tfake/integration\t0.001s\n'
    printf 'ok\tfake/conformance\t0.001s\n'
    exit 0
    ;;
  esac
  printf '%s\n' \
    '--- PASS: TestBrokerDialerRevalidatesThenPermitsEveryLiteralAttempt (0.00s)' \
    '--- PASS: TestBrokerDialerLiteralSkipsResolverAndRequiresPermit (0.00s)' \
    '--- PASS: TestBrokerDialerPermitFailurePreventsKernelDial (0.00s)' \
    '--- PASS: TestDoHResolverUsesOnePermittedLockedPersistentConnection (0.00s)' \
    '--- PASS: TestPollPermitFailureAbortsBeforeAcquireAndLeavesServiceReady (0.00s)' \
    '--- PASS: TestServiceTransitionCancelsAndJoinsOldOperationBeforeOpen (0.00s)' \
    '--- PASS: TestServiceDisabledTransitionRequiresListenerQuiescence (0.00s)' \
    '--- PASS: TestServiceTransitionJoinTimeoutPersistsFatalBeforeTermination (0.00s)' \
    '--- PASS: TestReplayHostedExplicitRouteFailureIsDurableAndNeverAcknowledged (0.00s)' \
    '--- PASS: TestReplayHostedEmptyOwnershipProofIsDurableFailure (0.00s)' \
    '--- PASS: TestChaosSourceOptInBoundary (0.00s)' \
    '--- PASS: TestChaosOperationalGate (0.00s)' \
    '--- PASS: TestShutdownIntegrationAuthorityStopsOnlyExactTuple (0.00s)'
  printf 'ok\tfake/package\t0.001s\n'
fi
exit 0
`,
	}
	for name, source := range fakes {
		if err := os.WriteFile(
			filepath.Join(fakeBin, name),
			[]byte(source),
			0o700,
		); err != nil {
			t.Fatal(err)
		}
	}
	tmpRoot := filepath.Join(parent, "tmp")
	if err := os.Mkdir(tmpRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	emptyManifest := filepath.Join(parent, "empty-images.json")
	if err := os.WriteFile(
		emptyManifest,
		[]byte("{\"version\":1,\"images\":[]}\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	command := exec.Command(script, gateMode)
	command.Dir = root
	command.Env = append(
		os.Environ(),
		"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"IMAGES_MANIFEST="+emptyManifest,
		"PGHAR_CHAOS_DOCKER=1",
		"PGHAR_FAKE_GO_MODE="+fakeGoMode,
		"PGHAR_INTEGRATION_DOCKER=1",
		"TMPDIR="+tmpRoot,
	)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	summary := decodeSummary(t, stdout.Bytes())
	entries, readErr := os.ReadDir(tmpRoot)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("gate log directory leaked: %v", entries)
	}
	return summary, stderr.String(), err
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("boundary: source location unavailable")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(current), "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("boundary: repository root unavailable: %v", err)
	}
	return root
}

func trackedFiles(t *testing.T, root string) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "git", "ls-files", "-z")
	command.Dir = root
	raw, err := command.Output()
	if err != nil || ctx.Err() != nil {
		t.Fatalf("boundary: tracked-file inventory unavailable: %v", err)
	}
	parts := bytes.Split(raw, []byte{0})
	files := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		name := filepath.ToSlash(string(part))
		if filepath.Clean(name) != filepath.FromSlash(name) ||
			strings.HasPrefix(name, "../") || filepath.IsAbs(name) {
			t.Fatalf("boundary: invalid tracked path %q", name)
		}
		files = append(files, name)
	}
	sort.Strings(files)
	return files
}

func productionGoFiles(t *testing.T, root string) []parsedGoFile {
	t.Helper()
	var parsed []parsedGoFile
	for _, top := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(
			filepath.Join(root, top),
			func(path string, entry fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if entry.IsDir() {
					return nil
				}
				if !strings.HasSuffix(entry.Name(), ".go") ||
					strings.HasSuffix(entry.Name(), "_test.go") {
					return nil
				}
				relative, err := filepath.Rel(root, path)
				if err != nil {
					return err
				}
				source, err := readBounded(path)
				if err != nil {
					return err
				}
				file, err := parseGo(filepath.ToSlash(relative), source)
				if err != nil {
					return err
				}
				parsed = append(parsed, file)
				return nil
			},
		)
		if err != nil {
			t.Fatalf("boundary: parse production source: %v", err)
		}
	}
	sort.Slice(parsed, func(i, j int) bool {
		return parsed[i].relative < parsed[j].relative
	})
	return parsed
}

func parseGo(relative string, source []byte) (parsedGoFile, error) {
	fileset := token.NewFileSet()
	file, err := parser.ParseFile(fileset, relative, source, parser.AllErrors)
	if err != nil {
		return parsedGoFile{}, fmt.Errorf("%s: %w", relative, err)
	}
	imports := make(map[string]string)
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return parsedGoFile{}, fmt.Errorf("%s: import: %w", relative, err)
		}
		name := filepath.Base(path)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		imports[name] = path
	}
	return parsedGoFile{
		relative: relative,
		source:   source,
		file:     file,
		fileset:  fileset,
		imports:  imports,
	}, nil
}

func readBounded(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 ||
		info.Size() > maxBoundaryFileBytes {
		return nil, fmt.Errorf("boundary: file shape invalid: %s", path)
	}
	return os.ReadFile(path)
}

func checkModuleAndLifecycle(t *testing.T, root string, tracked []string) {
	t.Helper()
	module := string(mustRead(t, filepath.Join(root, "go.mod")))
	for _, exact := range []string{
		"module github.com/sumitake/portable-ghar\n",
		"\ngo 1.26.0\n",
		"\ntoolchain go1.26.6\n",
		"github.com/actions/scaleset v0.4.0",
	} {
		if !strings.Contains(module, exact) {
			t.Errorf("go.mod missing exact anchor %q", exact)
		}
	}
	for _, directive := range []string{"\nreplace ", "\nexclude ", "\nretract "} {
		if strings.Contains(module, directive) {
			t.Errorf("go.mod contains prohibited directive %q", strings.TrimSpace(directive))
		}
	}

	trackedSet := make(map[string]bool, len(tracked))
	modes := make(map[string]fs.FileMode, len(requiredQTSScripts))
	for _, name := range tracked {
		trackedSet[name] = true
	}
	for _, name := range requiredQTSScripts {
		info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(name)))
		if err == nil {
			modes[name] = info.Mode()
		}
	}
	for _, issue := range requiredScriptIssues(trackedSet, modes) {
		t.Error(issue)
	}
	requireExecutable(t, filepath.Join(root, gateRelativePath))
}

func requiredScriptIssues(
	tracked map[string]bool,
	modes map[string]fs.FileMode,
) []string {
	var issues []string
	for _, name := range requiredQTSScripts {
		if !tracked[name] {
			issues = append(issues, name+": missing or untracked")
			continue
		}
		mode, ok := modes[name]
		if !ok || !mode.IsRegular() || mode&0o111 == 0 {
			issues = append(issues, name+": not a regular executable")
		}
	}
	return issues
}

func requireExecutable(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("boundary: required executable unavailable: %s: %v", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
		t.Fatalf("boundary: required executable mode invalid: %s: %s", path, info.Mode())
	}
}

func checkImportsAndAuthority(t *testing.T, production []parsedGoFile) {
	t.Helper()
	for _, file := range production {
		for _, issue := range importPolicyIssues(file.relative, file.source) {
			t.Error(issue)
		}
		if isControllerOrWatchdog(file.relative) {
			for _, literal := range stringLiterals(file.file) {
				switch literal {
				case "PORTABLE_GHAR_ROUTE",
					"PORTABLE_GHAR_SCALE_SET",
					"PORTABLE_GHAR_LEGACY_LABEL":
					t.Errorf("%s: routing variable escaped into controller/watchdog", file.relative)
				}
			}
		}
		for _, issue := range defaultNetworkAssignmentIssues(file) {
			t.Error(issue)
		}
	}

	acquisition := findParsed(t, production, "internal/controller/acquisition.go")
	if countTypeDeclarations(acquisition.file, "AcquisitionTransitioner") != 1 {
		t.Error("controller.AcquisitionTransitioner is not one exact interface declaration")
	}
	for _, method := range []string{"Snapshot", "Transition"} {
		if !interfaceHasMethod(acquisition.file, "AcquisitionTransitioner", method) {
			t.Errorf("AcquisitionTransitioner missing %s", method)
		}
	}
}

func importPolicyIssues(relative string, source []byte) []string {
	parsed, err := parseGo(relative, source)
	if err != nil {
		return []string{err.Error()}
	}
	var issues []string
	for _, spec := range parsed.file.Imports {
		path, _ := strconv.Unquote(spec.Path.Value)
		if spec.Name != nil && spec.Name.Name == "." {
			issues = append(issues, relative+": dot import")
		}
		lower := strings.ToLower(path)
		if strings.HasPrefix(lower, "k8s.io/") ||
			strings.HasPrefix(lower, "sigs.k8s.io/") ||
			strings.Contains(lower, "actions-runner-controller") ||
			strings.Contains(lower, "container-hook") {
			issues = append(issues, relative+": prohibited orchestration import "+path)
		}
		if path == "github.com/actions/scaleset" &&
			!strings.HasPrefix(relative, "internal/githubscale/") {
			blankPin := relative == "internal/buildinfo/pins.go" &&
				spec.Name != nil && spec.Name.Name == "_"
			if !blankPin {
				issues = append(issues, relative+": scale-set import escaped adapter")
			}
		}
		if isControllerOrWatchdog(relative) &&
			(strings.Contains(lower, "cloudflare") ||
				strings.Contains(lower, "go-github")) {
			issues = append(issues, relative+": concrete routing writer import "+path)
		}
	}
	return issues
}

func isControllerOrWatchdog(relative string) bool {
	return strings.HasPrefix(relative, "internal/controller/") ||
		strings.HasPrefix(relative, "cmd/portable-ghar-controller/") ||
		strings.HasPrefix(relative, "cmd/portable-ghar-watchdog/")
}

func defaultNetworkAssignmentIssues(file parsedGoFile) []string {
	protected := map[string]map[string]bool{
		"net/http": {
			"DefaultClient":    true,
			"DefaultTransport": true,
		},
		"net": {
			"DefaultResolver": true,
		},
	}
	var issues []string
	ast.Inspect(file.file, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, left := range assignment.Lhs {
			selector, ok := left.(*ast.SelectorExpr)
			if !ok {
				continue
			}
			identifier, ok := selector.X.(*ast.Ident)
			if !ok {
				continue
			}
			importPath := file.imports[identifier.Name]
			if protected[importPath][selector.Sel.Name] {
				issues = append(
					issues,
					fmt.Sprintf(
						"%s:%d: assignment to process-global %s.%s",
						file.relative,
						file.fileset.Position(left.Pos()).Line,
						identifier.Name,
						selector.Sel.Name,
					),
				)
			}
		}
		return true
	})
	return issues
}

func checkContainerIsolation(t *testing.T, production []parsedGoFile) {
	t.Helper()
	docker := findParsed(t, production, "internal/hostruntime/dockercli.go")
	runner, ok := returnedStringArgv(docker, "runnerCreateArgv")
	if !ok {
		t.Fatal("runnerCreateArgv unavailable")
	}
	for _, issue := range runnerArgvIssues(runner) {
		t.Error(issue)
	}
	adapter, ok := returnedStringArgv(docker, "adapterCreateArgv")
	if !ok {
		t.Fatal("adapterCreateArgv unavailable")
	}
	for _, required := range [][2]string{
		{"--network", "none"},
		{"--cap-drop", "ALL"},
	} {
		if !adjacentStaticArgv(adapter, required[0], required[1]) {
			t.Errorf("adapter argv missing %q %q", required[0], required[1])
		}
	}
	for _, required := range []string{
		"--read-only",
		"no-new-privileges=true",
	} {
		if !containsStaticArgv(adapter, required) {
			t.Errorf("adapter argv missing %q", required)
		}
	}
	if !containsStaticArgvFragment(adapter, ",readonly") {
		t.Error("adapter argv bind is not statically read-only")
	}
	if countStaticArgv(adapter, "--mount") != 1 {
		t.Error("adapter argv does not have exactly one mount")
	}

	hostruntimeSource := joinedSource(production, "internal/hostruntime/")
	if strings.Count(hostruntimeSource, `"--cap-add"`) != 1 ||
		strings.Count(hostruntimeSource, `"NET_ADMIN"`) < 1 {
		t.Error("helper capability surface is not exactly one NET_ADMIN add")
	}
	for _, prohibited := range []string{
		`"--privileged"`,
		`"/var/run/docker.sock"`,
		`"--device"`,
	} {
		if strings.Contains(hostruntimeSource, prohibited) {
			t.Errorf("host runtime contains prohibited Docker surface %s", prohibited)
		}
	}
	for _, auditAnchor := range []string{
		"len(host.Binds) != 0",
		"len(host.Devices) != 0",
		"host.Privileged",
		"len(host.CapAdd) != 0",
		"host.ReadonlyRootfs",
		"host.SecurityOpt",
		"host.MemorySwap",
		"host.PidsLimit",
	} {
		if !strings.Contains(hostruntimeSource, auditAnchor) {
			t.Errorf("runtime read-back missing %s", auditAnchor)
		}
	}

	seccompPath := filepath.Join(repositoryRoot(t), "config/seccomp/portable-ghar-capless-v1.json")
	var document struct {
		Syscalls []struct {
			Names  []string `json:"names"`
			Action string   `json:"action"`
			Args   []any    `json:"args"`
		} `json:"syscalls"`
	}
	if err := json.Unmarshal(mustRead(t, seccompPath), &document); err != nil {
		t.Fatalf("seccomp JSON: %v", err)
	}
	denied := make(map[string]bool)
	socketRules := 0
	cloneRules := 0
	for _, rule := range document.Syscalls {
		if rule.Action != "SCMP_ACT_ERRNO" {
			continue
		}
		for _, name := range rule.Names {
			denied[name] = true
			if name == "socket" {
				socketRules++
			}
			if name == "clone" {
				cloneRules++
			}
		}
	}
	for _, name := range []string{"bpf", "clone3", "setns", "unshare"} {
		if !denied[name] {
			t.Errorf("seccomp does not deny %s", name)
		}
	}
	if socketRules < 2 || cloneRules < 6 {
		t.Errorf("seccomp closed socket/namespace rules incomplete: socket=%d clone=%d", socketRules, cloneRules)
	}
}

func runnerArgvIssues(tokens []string) []string {
	var issues []string
	for _, required := range [][2]string{
		{"--cap-drop", "ALL"},
		{"--restart", "no"},
		{"--log-driver", "local"},
	} {
		if !adjacentStaticArgv(tokens, required[0], required[1]) {
			issues = append(
				issues,
				fmt.Sprintf("runner argv missing %q %q", required[0], required[1]),
			)
		}
	}
	if !adjacentStaticArgvPrefix(tokens, "--network", "container:") {
		issues = append(issues, "runner argv missing container network")
	}
	for _, required := range []string{
		"--read-only",
		"no-new-privileges=true",
		"--memory",
		"--memory-swap",
		"--pids-limit",
		"--ulimit",
	} {
		if !containsStaticArgv(tokens, required) {
			issues = append(issues, "runner argv missing "+required)
		}
	}
	if countStaticArgv(tokens, "--tmpfs") != 3 {
		issues = append(issues, "runner argv must have exactly three tmpfs mounts")
	}
	for _, prohibited := range []string{
		"--mount",
		"--volume",
		"--device",
		"--privileged",
		"/var/run/docker.sock",
	} {
		if containsStaticArgvFragment(tokens, prohibited) {
			issues = append(issues, "runner argv contains prohibited "+prohibited)
		}
	}
	for _, token := range tokens {
		if token == "host" || token == "--network=host" {
			issues = append(issues, "runner argv contains prohibited host network")
		}
	}
	return issues
}

func checkNetworkAndPermit(t *testing.T, production []parsedGoFile) {
	t.Helper()
	for _, file := range production {
		sites := networkSurfaceSites(file)
		if len(sites) == 0 {
			continue
		}
		if _, ok := publicNetworkSurfaceFiles[file.relative]; !ok {
			t.Errorf("%s: unreviewed network surface: %s", file.relative, strings.Join(sites, ","))
		}
	}
	for relative := range publicNetworkSurfaceFiles {
		if !containsParsed(production, relative) {
			t.Errorf("reviewed network surface disappeared: %s", relative)
		}
	}

	dialer := findParsed(t, production, "internal/networkjail/dialer.go")
	if _, ok := functionDeclaration(dialer, "DialFrame"); !ok {
		t.Fatal("BrokerDialer.DialFrame unavailable")
	}
	for _, issue := range brokerDialIssues(dialer) {
		t.Error(issue)
	}

	literal := findParsed(t, production, "internal/networkjail/literal_dialer.go")
	literalBody, ok := functionBody(literal, "DialLiteral")
	if !ok || !strings.Contains(literalBody, "address.String()") ||
		!strings.Contains(literalBody, "normalizeEmbedded(address) != address") {
		t.Error("literal dialer lost canonical netip address validation")
	}
	if !functionParameterUsesType(literal, "DialLiteral", "netip", "Addr") {
		t.Error("LiteralNetDialer.DialLiteral no longer accepts netip.Addr")
	}

	doh := findParsed(t, production, "internal/networkjail/doh.go")
	for _, issue := range dohDialIssues(doh) {
		t.Error(issue)
	}

	for _, name := range []string{
		"TestBrokerDialerRevalidatesThenPermitsEveryLiteralAttempt",
		"TestBrokerDialerLiteralSkipsResolverAndRequiresPermit",
		"TestBrokerDialerPermitFailurePreventsKernelDial",
		"TestDoHResolverUsesOnePermittedLockedPersistentConnection",
	} {
		if !testFunctionExists(t, name, "internal/networkjail") {
			t.Errorf("network authority test missing: %s", name)
		}
	}

	parserSource := string(mustRead(
		t,
		filepath.Join(repositoryRoot(t), "internal/networkjail/connect_parser.go"),
	))
	for _, anchor := range []string{
		`requestParts[0] != "CONNECT"`,
		`data[1] != 1`,
		`len(data) !=`,
		`NormalizeDestination`,
	} {
		if !strings.Contains(parserSource, anchor) {
			t.Errorf("CONNECT parser missing closed anchor %q", anchor)
		}
	}
}

func networkSurfaceSites(file parsedGoFile) []string {
	var sites []string
	ast.Inspect(file.file, func(node ast.Node) bool {
		switch current := node.(type) {
		case *ast.CallExpr:
			selector, ok := current.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch selector.Sel.Name {
			case "Dial", "DialContext", "DialTLSContext":
				sites = append(sites, selector.Sel.Name)
			}
		case *ast.CompositeLit:
			selector, ok := current.Type.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			identifier, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			importPath := file.imports[identifier.Name]
			if (importPath == "net" && selector.Sel.Name == "Dialer") ||
				(importPath == "net/http" &&
					(selector.Sel.Name == "Client" || selector.Sel.Name == "Transport")) {
				sites = append(sites, identifier.Name+"."+selector.Sel.Name)
			}
		case *ast.SelectorExpr:
			switch current.Sel.Name {
			case "DialContext", "DialTLSContext":
				if _, isCall := current.X.(*ast.CallExpr); !isCall {
					sites = append(sites, current.Sel.Name+"-value")
				}
			}
		}
		return true
	})
	sort.Strings(sites)
	return sites
}

func brokerDialIssues(file parsedGoFile) []string {
	var issues []string
	permits := selectorCallPositions(file, "DialFrame", "Request")
	permits = append(
		permits,
		nestedSelectorCallPositions(
			file,
			"DialFrame",
			"dialer",
			"sequencer",
			"request",
		)...,
	)
	dials := selectorCallPositions(file, "DialFrame", "DialLiteral")
	if len(permits) != 1 || len(dials) != 1 || permits[0] > dials[0] {
		issues = append(issues, "literal dial is not ordered after permit")
	}
	if functionContainsGoStatement(file, "DialFrame") {
		issues = append(issues, "parallel dial path")
	}
	function, ok := functionDeclaration(file, "DialFrame")
	if !ok {
		return append(issues, "BrokerDialer.DialFrame unavailable")
	}
	ast.Inspect(function.Body, func(node ast.Node) bool {
		switch current := node.(type) {
		case *ast.CallExpr:
			selector, ok := current.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			identifier, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			importPath := file.imports[identifier.Name]
			if (importPath == "net" && selector.Sel.Name == "Dial") ||
				(importPath == "syscall" && selector.Sel.Name == "Connect") {
				issues = append(
					issues,
					"direct kernel dial in broker: "+importPath+"."+selector.Sel.Name,
				)
			}
		case *ast.CompositeLit:
			selector, ok := current.Type.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "Dialer" {
				return true
			}
			identifier, ok := selector.X.(*ast.Ident)
			if ok && file.imports[identifier.Name] == "net" {
				issues = append(issues, "direct kernel dialer in broker")
			}
		}
		return true
	})
	return issues
}

func dohDialIssues(file parsedGoFile) []string {
	var issues []string
	submissions := selectorCallPositions(file, "DialTLSContext", "request")
	dials := selectorCallPositions(file, "DialTLSContext", "DialLiteral")
	if len(submissions) != 1 || len(dials) != 1 || submissions[0] > dials[0] {
		issues = append(issues, "DoH kernel dial is not ordered after permit submission")
	}
	if functionContainsGoStatement(file, "DialTLSContext") {
		issues = append(issues, "DoH permit/dial path contains parallel fallback")
	}

	permitRequests := selectorCallPositions(file, "request", "Request")
	sequenceAssignments := selectorAssignmentPositions(file, "request", "Sequence")
	if len(permitRequests) != 1 || len(sequenceAssignments) != 1 ||
		sequenceAssignments[0] > permitRequests[0] {
		issues = append(issues, "DoH sequencer does not assign then submit one permit")
	}
	if functionContainsGoStatement(file, "request") {
		issues = append(issues, "DoH permit submission helper contains parallel work")
	}
	return issues
}

func checkSecretsAndReaders(t *testing.T, production []parsedGoFile) {
	t.Helper()
	secret := findParsed(t, production, "internal/redaction/secret.go")
	got := exportedReceiverMethods(secret.file, "Secret")
	want := []string{"Destroy", "MarshalJSON", "String", "Use"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("redaction.Secret exported methods = %v, want %v", got, want)
	}
	for _, file := range production {
		for _, issue := range unboundedReadAllIssues(file) {
			t.Error(issue)
		}
	}
}

func unboundedReadAllIssues(file parsedGoFile) []string {
	ioAliases := make(map[string]bool)
	for alias, path := range file.imports {
		if path == "io" {
			ioAliases[alias] = true
		}
	}
	if len(ioAliases) == 0 {
		return nil
	}
	var issues []string
	for _, declaration := range file.file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		assignments := make(map[string][]ast.Expr)
		positions := make(map[string][]token.Pos)
		ast.Inspect(function.Body, func(node ast.Node) bool {
			assignment, ok := node.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for index, left := range assignment.Lhs {
				identifier, ok := left.(*ast.Ident)
				if !ok || index >= len(assignment.Rhs) {
					continue
				}
				assignments[identifier.Name] = append(assignments[identifier.Name], assignment.Rhs[index])
				positions[identifier.Name] = append(positions[identifier.Name], assignment.Pos())
			}
			return true
		})
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || !isPackageCall(call, ioAliases, "ReadAll") ||
				len(call.Args) != 1 {
				return true
			}
			if nested, ok := call.Args[0].(*ast.CallExpr); ok &&
				isPackageCall(nested, ioAliases, "LimitReader") {
				return true
			}
			identifier, ok := call.Args[0].(*ast.Ident)
			if ok {
				values := assignments[identifier.Name]
				where := positions[identifier.Name]
				if len(values) == 1 && len(where) == 1 && where[0] < call.Pos() {
					if limit, ok := values[0].(*ast.CallExpr); ok &&
						isPackageCall(limit, ioAliases, "LimitReader") {
						return true
					}
				}
			}
			issues = append(
				issues,
				fmt.Sprintf(
					"%s:%d: unbounded or ambiguous io.ReadAll",
					file.relative,
					file.fileset.Position(call.Pos()).Line,
				),
			)
			return true
		})
	}
	return issues
}

func isPackageCall(call *ast.CallExpr, aliases map[string]bool, method string) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != method {
		return false
	}
	identifier, ok := selector.X.(*ast.Ident)
	return ok && aliases[identifier.Name]
}

func checkPinsSizingUpgradeAndFence(
	t *testing.T,
	root string,
	production []parsedGoFile,
) {
	t.Helper()
	pins := string(mustRead(t, filepath.Join(root, "internal/buildinfo/pins.go")))
	for _, anchor := range []string{
		`Version:               "v2.336.0"`,
		`LinuxX64SHA256:        "04cf0be1aff4c3ec3554466c39124ca250e3effd8873bb7e8d68535aa9505d5d"`,
		`SourceCommit:          "98aabcd429c4e8402406c56ce2d26387fed3b9ce"`,
		`RunnerBaseImage: "debian:bookworm-slim@sha256:`,
		`AdapterImage:    "scratch"`,
		`BrokerImage:     "scratch"`,
		`HelperImage:     "scratch"`,
		`VerifierImage:   "scratch"`,
	} {
		if !strings.Contains(pins, anchor) {
			t.Errorf("build pins missing %q", anchor)
		}
	}

	githubScale := joinedSource(production, "internal/githubscale/")
	for _, anchor := range []string{
		"RunnerSetting.DisableUpdate",
		"SingleNameLabel",
		"withOperationDeadline",
	} {
		if !strings.Contains(githubScale, anchor) {
			t.Errorf("scale-set compatibility/deadline anchor missing %s", anchor)
		}
	}

	profile := string(mustRead(t, filepath.Join(root, "internal/hostruntime/profile.go")))
	for _, anchor := range []string{
		"func ValidateRunnerSizing",
		"!value.OperatorApproved",
		"!value.SwapLimitConfigured",
		"value.ReclamationObservationCadence <= 0",
		"checkedMul(value.MaxActiveConcurrency, value.RunnerMemoryBytes)",
		"hostTotal > value.UsableHostMemoryBytes",
	} {
		if !strings.Contains(profile, anchor) {
			t.Errorf("runner sizing proof missing %q", anchor)
		}
	}
	overlay := string(mustRead(t, filepath.Join(root, "internal/hostruntime/private_overlay.go")))
	if !strings.Contains(overlay, "RunnerSizingOverlay") ||
		!strings.Contains(overlay, "ValidateRunnerSizing(runner)") {
		t.Error("private overlay does not carry and validate the complete runner sizing tuple")
	}

	for _, name := range []string{
		"TestPollPermitFailureAbortsBeforeAcquireAndLeavesServiceReady",
		"TestServiceTransitionCancelsAndJoinsOldOperationBeforeOpen",
		"TestServiceDisabledTransitionRequiresListenerQuiescence",
		"TestServiceTransitionJoinTimeoutPersistsFatalBeforeTermination",
		"TestReplayHostedExplicitRouteFailureIsDurableAndNeverAcknowledged",
		"TestReplayHostedEmptyOwnershipProofIsDurableFailure",
	} {
		if !testFunctionExists(t, name, "internal/controller") {
			t.Errorf("authority regression test missing: %s", name)
		}
	}
	if !testFunctionExists(
		t,
		"TestChaosSourceOptInBoundary",
		"tests/chaos",
	) {
		t.Error("chaos source authority test missing")
	}

	for _, file := range production {
		for _, declaration := range file.file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			name := strings.ToLower(function.Name.Name)
			if !strings.Contains(name, "sweep") &&
				!strings.Contains(name, "purge") &&
				!strings.Contains(name, "clean") {
				continue
			}
			body, _ := functionBody(file, function.Name.Name)
			if strings.Contains(body, `"_work"`) ||
				strings.Contains(body, `"_update"`) ||
				strings.Contains(body, `"externals"`) {
				t.Errorf("%s: serving runner file sweeper %s", file.relative, function.Name.Name)
			}
		}
	}

	all := joinedSource(production, "")
	for _, anchor := range []string{
		"fleetfence",
		"RemoveRunner",
		"removeRunnerID",
		"AcquisitionDefault",
	} {
		if !strings.Contains(all, anchor) {
			t.Errorf("lifecycle/fence anchor missing %s", anchor)
		}
	}
}

func checkTrackedArtifactsAndFixtures(
	t *testing.T,
	root string,
	tracked []string,
) {
	t.Helper()
	for _, relative := range tracked {
		if issue := trackedPathIssue(relative); issue != "" {
			t.Error(issue)
		}
		path := filepath.Join(root, filepath.FromSlash(relative))
		info, err := os.Lstat(path)
		if err != nil {
			t.Errorf("%s: lstat: %v", relative, err)
			continue
		}
		if !info.Mode().IsRegular() || info.Size() == 0 {
			continue
		}
		file, err := os.Open(path)
		if err != nil {
			t.Errorf("%s: open: %v", relative, err)
			continue
		}
		header := make([]byte, 8)
		count, readErr := file.Read(header)
		_ = file.Close()
		if readErr != nil && count == 0 {
			t.Errorf("%s: read magic: %v", relative, readErr)
			continue
		}
		header = header[:count]
		if binaryMagic(header) {
			t.Errorf("%s: tracked binary/archive magic", relative)
		}
		if isPublicFixture(relative) {
			content, err := readBounded(path)
			if err != nil {
				t.Errorf("%s: fixture read: %v", relative, err)
				continue
			}
			if issue := fixtureContentIssue(content); issue != "" {
				t.Errorf("%s: %s", relative, issue)
			}
		}
	}
}

func trackedPathIssue(relative string) string {
	lower := strings.ToLower(filepath.ToSlash(relative))
	extension := strings.ToLower(filepath.Ext(lower))
	switch extension {
	case ".zip", ".gz", ".tgz", ".tar", ".xz", ".bz2", ".7z",
		".deb", ".rpm", ".apk", ".exe", ".dll", ".so", ".dylib",
		".a", ".o", ".bin":
		return relative + ": prohibited archive/binary extension"
	}
	base := strings.ToLower(filepath.Base(lower))
	if strings.Contains(base, "actions-runner") ||
		strings.Contains(base, "runner.listener") {
		return relative + ": upstream runner payload name"
	}
	for _, segment := range strings.Split(lower, "/") {
		switch segment {
		case "_work", "_update", "externals", "runner-cache", "runtime-cache":
			return relative + ": mutable runner/cache path"
		}
	}
	return ""
}

func binaryMagic(header []byte) bool {
	magics := [][]byte{
		{0x7f, 'E', 'L', 'F'},
		{0xcf, 0xfa, 0xed, 0xfe},
		{0xce, 0xfa, 0xed, 0xfe},
		{0xca, 0xfe, 0xba, 0xbe},
		{'M', 'Z'},
		{'P', 'K', 0x03, 0x04},
		{0x1f, 0x8b},
	}
	for _, magic := range magics {
		if bytes.HasPrefix(header, magic) {
			return true
		}
	}
	return false
}

func isPublicFixture(relative string) bool {
	return strings.HasPrefix(relative, "config/examples/") ||
		(strings.Contains(relative, "/fixtures/") &&
			!strings.HasPrefix(relative, "tests/sanitization/fixtures/"))
}

var emailPattern = regexp.MustCompile(
	`[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})`,
)

func fixtureContentIssue(content []byte) string {
	text := string(content)
	if strings.Contains(text, "/Users/") ||
		strings.Contains(text, "/home/") ||
		regexp.MustCompile(`(?i)\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.local\b`).MatchString(text) {
		return "private path or local hostname"
	}
	for _, match := range emailPattern.FindAllStringSubmatch(text, -1) {
		domain := strings.ToLower(strings.TrimSuffix(match[1], "."))
		allowed := false
		for _, suffix := range []string{
			"example.com",
			"example.org",
			"example.net",
			"example.invalid",
			"example.edu",
		} {
			if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
				allowed = true
				break
			}
		}
		if !allowed {
			return "non-synthetic email identity"
		}
	}
	return ""
}

func checkGateSource(t *testing.T, root string) {
	t.Helper()
	path := filepath.Join(root, gateRelativePath)
	requireExecutable(t, path)
	source := string(mustRead(t, path))
	if !strings.HasPrefix(source, "#!/usr/bin/env bash\n# SPDX-License-Identifier: MPL-2.0\n") {
		t.Error("runtime gate shebang/SPDX header invalid")
	}
	for _, anchor := range []string{
		"set -euo pipefail",
		"umask 077",
		"run_verified_go_test_stage",
		"git ls-files -z",
		`"${files[@]}"`,
		"--- SKIP:",
		`\[no tests to run\]`,
		"--unit",
		"--full",
		"mktemp -d",
		"source-integrity-entry",
		"gofmt",
		"vet",
		"unit",
		"race",
		"network-authority",
		"acquisition-authority",
		"routing-authority",
		"boundary",
		"staticcheck",
		"module",
		"shellcheck",
		"shfmt",
		"bats",
		"python-contract",
		"workflow-policy",
		"repository-metadata",
		"public-sanitizer",
		"chaos-source",
		"linux-docker-preflight",
		"image-reproducibility",
		"integration-authority",
		"conformance",
		"chaos",
		"docker-state-exit",
		"source-integrity-full-exit",
		`"schema_version":1`,
		`"portable-ghar-controller-runtime"`,
	} {
		if !strings.Contains(source, anchor) {
			t.Errorf("runtime gate source missing %q", anchor)
		}
	}
	for _, prohibited := range []string{
		"eval ",
		"curl ",
		"wget ",
		"git add",
		"git checkout",
		"git reset",
		"docker pull",
		"docker system prune",
		"docker network create",
		"docker volume create",
		"prepare-task",
		"shellcheck $files",
		"bats $files",
	} {
		if strings.Contains(source, prohibited) {
			t.Errorf("runtime gate contains prohibited command %q", prohibited)
		}
	}
	if regexp.MustCompile(`(?m)^[ \t]*(source|\.)[ \t]+`).MatchString(source) {
		t.Error("runtime gate sources an external shell document")
	}
	if strings.Count(source, "emit_summary") != 2 {
		t.Errorf("runtime gate must define and invoke one summary emitter, references=%d", strings.Count(source, "emit_summary"))
	}
}

func decodeSummary(t *testing.T, raw []byte) gateSummary {
	t.Helper()
	if len(raw) == 0 || bytes.Count(raw, []byte{'\n'}) != 1 ||
		raw[len(raw)-1] != '\n' {
		t.Fatalf("gate stdout is not exactly one line: %q", raw)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var summary gateSummary
	if err := decoder.Decode(&summary); err != nil {
		t.Fatalf("gate summary decode: %v", err)
	}
	if decoder.More() {
		t.Fatal("gate summary contains a second JSON value")
	}
	if summary.SchemaVersion != 1 ||
		summary.Gate != "portable-ghar-controller-runtime" ||
		(summary.Mode != "unit" && summary.Mode != "full") ||
		(summary.Status != "pass" && summary.Status != "fail") ||
		(summary.LinuxDocker != "not_run" &&
			summary.LinuxDocker != "ready" &&
			summary.LinuxDocker != "failed") ||
		len(summary.Stages) == 0 {
		t.Fatalf("gate summary closed fields invalid: %#v", summary)
	}
	seen := make(map[string]bool)
	for _, stage := range summary.Stages {
		if stage.ID == "" || (stage.Status != "pass" && stage.Status != "fail") ||
			seen[stage.ID] {
			t.Fatalf("gate stage invalid: %#v", stage)
		}
		seen[stage.ID] = true
	}
	return summary
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	content, err := readBounded(path)
	if err != nil {
		t.Fatalf("boundary: read %s: %v", path, err)
	}
	return content
}

func findParsed(
	t *testing.T,
	files []parsedGoFile,
	relative string,
) parsedGoFile {
	t.Helper()
	for _, file := range files {
		if file.relative == relative {
			return file
		}
	}
	t.Fatalf("boundary: production file unavailable: %s", relative)
	return parsedGoFile{}
}

func containsParsed(files []parsedGoFile, relative string) bool {
	for _, file := range files {
		if file.relative == relative {
			return true
		}
	}
	return false
}

func joinedSource(files []parsedGoFile, prefix string) string {
	var document strings.Builder
	for _, file := range files {
		if strings.HasPrefix(file.relative, prefix) {
			document.Write(file.source)
			document.WriteByte('\n')
		}
	}
	return document.String()
}

func functionDeclaration(
	file parsedGoFile,
	name string,
) (*ast.FuncDecl, bool) {
	for _, declaration := range file.file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == name && function.Body != nil {
			return function, true
		}
	}
	return nil, false
}

func functionBody(file parsedGoFile, name string) (string, bool) {
	function, ok := functionDeclaration(file, name)
	if !ok {
		return "", false
	}
	start := file.fileset.Position(function.Body.Pos()).Offset
	end := file.fileset.Position(function.Body.End()).Offset
	if start < 0 || end < start || end > len(file.source) {
		return "", false
	}
	return string(file.source[start:end]), true
}

func selectorCallPositions(
	file parsedGoFile,
	functionName string,
	selectorName string,
) []token.Pos {
	function, ok := functionDeclaration(file, functionName)
	if !ok {
		return nil
	}
	var positions []token.Pos
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if ok && selector.Sel.Name == selectorName {
			positions = append(positions, call.Pos())
		}
		return true
	})
	return positions
}

func nestedSelectorCallPositions(
	file parsedGoFile,
	functionName,
	receiverName,
	fieldName,
	selectorName string,
) []token.Pos {
	function, ok := functionDeclaration(file, functionName)
	if !ok {
		return nil
	}
	var positions []token.Pos
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != selectorName {
			return true
		}
		field, ok := selector.X.(*ast.SelectorExpr)
		if !ok || field.Sel.Name != fieldName {
			return true
		}
		receiver, ok := field.X.(*ast.Ident)
		if ok && receiver.Name == receiverName {
			positions = append(positions, call.Pos())
		}
		return true
	})
	return positions
}

func selectorAssignmentPositions(
	file parsedGoFile,
	functionName string,
	selectorName string,
) []token.Pos {
	function, ok := functionDeclaration(file, functionName)
	if !ok {
		return nil
	}
	var positions []token.Pos
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		assignment, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, expression := range assignment.Lhs {
			selector, ok := expression.(*ast.SelectorExpr)
			if ok && selector.Sel.Name == selectorName {
				positions = append(positions, expression.Pos())
			}
		}
		return true
	})
	return positions
}

func functionContainsGoStatement(
	file parsedGoFile,
	functionName string,
) bool {
	function, ok := functionDeclaration(file, functionName)
	if !ok {
		return false
	}
	found := false
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		if _, ok := node.(*ast.GoStmt); ok {
			found = true
			return false
		}
		return !found
	})
	return found
}

func returnedStringArgv(
	file parsedGoFile,
	name string,
) ([]string, bool) {
	function, ok := functionDeclaration(file, name)
	if !ok {
		return nil, false
	}
	var result *ast.CompositeLit
	for _, statement := range function.Body.List {
		returned, ok := statement.(*ast.ReturnStmt)
		if !ok {
			continue
		}
		if result != nil || len(returned.Results) != 1 {
			return nil, false
		}
		composite, ok := returned.Results[0].(*ast.CompositeLit)
		if !ok || !isStringSliceType(composite.Type) {
			return nil, false
		}
		result = composite
	}
	if result == nil {
		return nil, false
	}
	tokens := make([]string, 0, len(result.Elts))
	for _, element := range result.Elts {
		var fragments []string
		ast.Inspect(element, func(node ast.Node) bool {
			literal, ok := node.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(literal.Value)
			if err != nil {
				fragments = nil
				return false
			}
			fragments = append(fragments, value)
			return true
		})
		tokens = append(tokens, strings.Join(fragments, ""))
	}
	return tokens, true
}

func isStringSliceType(expression ast.Expr) bool {
	array, ok := expression.(*ast.ArrayType)
	if !ok || array.Len != nil {
		return false
	}
	identifier, ok := array.Elt.(*ast.Ident)
	return ok && identifier.Name == "string"
}

func containsStaticArgv(tokens []string, expected string) bool {
	for _, current := range tokens {
		if current == expected {
			return true
		}
	}
	return false
}

func containsStaticArgvFragment(tokens []string, expected string) bool {
	for _, current := range tokens {
		if strings.Contains(current, expected) {
			return true
		}
	}
	return false
}

func countStaticArgv(tokens []string, expected string) int {
	count := 0
	for _, current := range tokens {
		if current == expected {
			count++
		}
	}
	return count
}

func adjacentStaticArgv(tokens []string, key string, value string) bool {
	for index := 0; index+1 < len(tokens); index++ {
		if tokens[index] == key && tokens[index+1] == value {
			return true
		}
	}
	return false
}

func adjacentStaticArgvPrefix(
	tokens []string,
	key string,
	prefix string,
) bool {
	for index := 0; index+1 < len(tokens); index++ {
		if tokens[index] == key && strings.HasPrefix(tokens[index+1], prefix) {
			return true
		}
	}
	return false
}

func functionParameterUsesType(
	file parsedGoFile,
	name string,
	alias string,
	typeName string,
) bool {
	for _, declaration := range file.file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != name || function.Type.Params == nil {
			continue
		}
		for _, field := range function.Type.Params.List {
			selector, ok := field.Type.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != typeName {
				continue
			}
			identifier, ok := selector.X.(*ast.Ident)
			if ok && identifier.Name == alias &&
				file.imports[alias] == "net/netip" {
				return true
			}
		}
	}
	return false
}

func stringLiterals(file *ast.File) []string {
	var literals []string
	ast.Inspect(file, func(node ast.Node) bool {
		literal, ok := node.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return true
		}
		value, err := strconv.Unquote(literal.Value)
		if err == nil {
			literals = append(literals, value)
		}
		return true
	})
	return literals
}

func exportedReceiverMethods(file *ast.File, receiver string) []string {
	var methods []string
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Recv == nil || !function.Name.IsExported() ||
			len(function.Recv.List) != 1 {
			continue
		}
		current := function.Recv.List[0].Type
		if pointer, ok := current.(*ast.StarExpr); ok {
			current = pointer.X
		}
		identifier, ok := current.(*ast.Ident)
		if ok && identifier.Name == receiver {
			methods = append(methods, function.Name.Name)
		}
	}
	sort.Strings(methods)
	return methods
}

func countTypeDeclarations(file *ast.File, name string) int {
	count := 0
	for _, declaration := range file.Decls {
		generic, ok := declaration.(*ast.GenDecl)
		if !ok || generic.Tok != token.TYPE {
			continue
		}
		for _, spec := range generic.Specs {
			current, ok := spec.(*ast.TypeSpec)
			if ok && current.Name.Name == name {
				count++
			}
		}
	}
	return count
}

func interfaceHasMethod(file *ast.File, name string, method string) bool {
	for _, declaration := range file.Decls {
		generic, ok := declaration.(*ast.GenDecl)
		if !ok || generic.Tok != token.TYPE {
			continue
		}
		for _, spec := range generic.Specs {
			current, ok := spec.(*ast.TypeSpec)
			if !ok || current.Name.Name != name {
				continue
			}
			interfaceType, ok := current.Type.(*ast.InterfaceType)
			if !ok {
				return false
			}
			for _, field := range interfaceType.Methods.List {
				for _, fieldName := range field.Names {
					if fieldName.Name == method {
						return true
					}
				}
			}
		}
	}
	return false
}

func testFunctionExists(t *testing.T, name string, relativeDirectory string) bool {
	t.Helper()
	root := repositoryRoot(t)
	found := false
	err := filepath.WalkDir(
		filepath.Join(root, filepath.FromSlash(relativeDirectory)),
		func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
				return nil
			}
			source, err := readBounded(path)
			if err != nil {
				return err
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, source, parser.AllErrors)
			if err != nil {
				return err
			}
			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if ok && function.Recv == nil && function.Name.Name == name {
					found = true
					return fs.SkipAll
				}
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("boundary: scan test authority: %v", err)
	}
	return found
}
