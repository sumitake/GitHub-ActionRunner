package testenv

import (
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"testing"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

const (
	oneShotTestDocker  = "/usr/bin/docker"
	oneShotTestAdapter = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	oneShotTestBroker  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	oneShotTestRunner  = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	oneShotTestBuild   = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	oneShotTestImage   = "example/verifier@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	oneShotTestHelper  = "example/helper@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
)

type oneShotRecorderRunner struct {
	next   hostruntime.Result
	err    error
	argv   [][]string
	stdin  [][]byte
	called int
}

func (r *oneShotRecorderRunner) Run(
	_ context.Context,
	argv []string,
	_ []*os.File,
	stdin io.Reader,
) (hostruntime.Result, error) {
	r.called++
	r.argv = append(r.argv, append([]string(nil), argv...))
	var input []byte
	if stdin != nil {
		input, _ = io.ReadAll(stdin)
	}
	r.stdin = append(r.stdin, input)
	return r.next, r.err
}

func TestTask11OneShotRecorderCapturesExactBoundSequenceOnce(
	t *testing.T,
) {
	t.Parallel()

	base := &oneShotRecorderRunner{}
	recorder, err := newTask11OneShotRecorder(
		base,
		oneShotTestRecorderBinding(),
	)
	if err != nil {
		t.Fatalf("newTask11OneShotRecorder: %v", err)
	}
	adapterStem := "11111111111111111111111111111111"
	brokerStem := "22222222222222222222222222222222"
	helperName := "pghar-broker-test-policy"
	document := []byte(`{"status":"ok","version":1}` + "\n")

	commands := []struct {
		argv   []string
		stdout []byte
	}{
		{
			argv: task11VerifierArgvForTest(
				"pghar-verifier-"+adapterStem+"-empty",
				oneShotTestAdapter,
				"namespace-empty",
			),
			stdout: document,
		},
		{
			argv: task11AbsenceArgvForTest(
				"pghar-verifier-" + adapterStem + "-empty",
			),
		},
		{
			argv:   task11HelperArgvForTest(helperName),
			stdout: document,
		},
		{
			argv:   task11AbsenceArgvForTest(helperName),
			stdout: nil,
		},
		{
			argv: []string{
				oneShotTestDocker,
				"exec",
				oneShotTestBroker,
				"/usr/local/bin/portable-ghar-network-broker-dialer",
				"authority-id",
			},
			stdout: document,
		},
		{
			argv: []string{
				oneShotTestDocker,
				"exec",
				oneShotTestBroker,
				"/usr/local/bin/portable-ghar-network-broker-dialer",
				"socket-audit",
			},
			stdout: document,
		},
		{
			argv: []string{
				oneShotTestDocker,
				"exec",
				"-i",
				oneShotTestBroker,
				"/usr/local/bin/portable-ghar-network-broker-dialer",
				"release",
			},
			stdout: document,
		},
		{
			argv: []string{
				oneShotTestDocker,
				"exec",
				oneShotTestBroker,
				"/usr/local/bin/portable-ghar-network-broker-dialer",
				"audit",
			},
			stdout: document,
		},
		{
			argv: []string{
				oneShotTestDocker,
				"exec",
				"-i",
				oneShotTestAdapter,
				"/usr/local/bin/portable-ghar-network-adapter",
				"bind-peer",
			},
			stdout: []byte("OK\n"),
		},
		{
			argv: task11VerifierArgvForTest(
				"pghar-verifier-"+adapterStem+"-probe",
				oneShotTestAdapter,
				"probe",
			),
			stdout: document,
		},
		{
			argv: task11AbsenceArgvForTest(
				"pghar-verifier-" + adapterStem + "-probe",
			),
		},
		{
			argv: task11VerifierArgvForTest(
				"pghar-verifier-"+brokerStem+"-identity",
				oneShotTestBroker,
				"namespace-id",
			),
			stdout: document,
		},
		{
			argv: task11AbsenceArgvForTest(
				"pghar-verifier-" + brokerStem + "-identity",
			),
		},
		{
			argv: []string{
				oneShotTestDocker,
				"exec",
				oneShotTestRunner,
				"/usr/local/bin/portable-ghar-runner-gate",
				"netns-id",
			},
			stdout: document,
		},
		{
			// The production final audit repeats the already-validated
			// released-broker document after the pre-arm namespace proof.
			argv: []string{
				oneShotTestDocker,
				"exec",
				oneShotTestBroker,
				"/usr/local/bin/portable-ghar-network-broker-dialer",
				"audit",
			},
			stdout: document,
		},
		{
			argv: []string{
				oneShotTestDocker,
				"exec",
				oneShotTestRunner,
				"/usr/local/bin/portable-ghar-runner-gate",
				"netns-id",
			},
			stdout: document,
		},
		{
			argv: task11VerifierArgvForTest(
				"pghar-verifier-"+adapterStem+"-flood",
				oneShotTestAdapter,
				"loopback-flood",
			),
			stdout: document,
		},
		{
			argv: task11AbsenceArgvForTest(
				"pghar-verifier-" + adapterStem + "-flood",
			),
		},
	}
	unrelated := []string{
		oneShotTestDocker,
		"inspect",
		"--type",
		"container",
		oneShotTestAdapter,
	}
	base.next = hostruntime.Result{
		ExitCode: 0,
		Stdout:   []byte(`[{"Id":"ignored"}]`),
	}
	if _, err := recorder.Run(
		context.Background(),
		unrelated,
		nil,
		nil,
	); err != nil {
		t.Fatalf("unrelated Run: %v", err)
	}

	for index, command := range commands {
		base.next = hostruntime.Result{
			ExitCode: 0,
			Stdout:   append([]byte(nil), command.stdout...),
		}
		result, err := recorder.Run(
			context.Background(),
			command.argv,
			nil,
			nil,
		)
		if err != nil {
			t.Fatalf("Run command %d: %v", index, err)
		}
		if !reflect.DeepEqual(result.Stdout, command.stdout) {
			t.Fatalf(
				"Run command %d stdout = %q, want %q",
				index,
				result.Stdout,
				command.stdout,
			)
		}
	}
	capture, err := recorder.Take()
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if !validOneShotTranscriptCapture(capture) ||
		len(capture.surfaces) != len(oneShotRuntimeSurfaceOrder()) ||
		!isLowerHex(capture.commandDigest, 64) ||
		!isLowerHex(capture.mountAbsenceDigest, 64) ||
		capture.commandDigest == capture.mountAbsenceDigest {
		t.Fatalf("capture = %+v", capture)
	}
	if got := oneShotSurfaceIDsForTest(capture.surfaces); !reflect.DeepEqual(
		got,
		oneShotRuntimeSurfaceOrder(),
	) {
		t.Fatalf("surface order = %v", got)
	}
	if _, err := recorder.Take(); !errors.Is(
		err,
		ErrClosedCommand,
	) {
		t.Fatalf("second Take error = %v", err)
	}
}

func TestTask11OneShotRecorderRejectsReorderedOrUnboundEvidence(
	t *testing.T,
) {
	t.Parallel()

	validEmpty := task11VerifierArgvForTest(
		"pghar-verifier-11111111111111111111111111111111-empty",
		oneShotTestAdapter,
		"namespace-empty",
	)
	tests := map[string]struct {
		argv   []string
		result hostruntime.Result
		err    error
	}{
		"future phase": {
			argv: task11HelperArgvForTest(
				"pghar-broker-test-policy",
			),
			result: hostruntime.Result{
				ExitCode: 0,
				Stdout:   []byte(`{"version":1}` + "\n"),
			},
		},
		"malformed verifier argv": {
			argv: append(
				append([]string(nil), validEmpty...),
				"--volume",
				"/host:/guest",
			),
			result: hostruntime.Result{
				ExitCode: 0,
				Stdout:   []byte(`{"version":1}` + "\n"),
			},
		},
		"nonzero": {
			argv: validEmpty,
			result: hostruntime.Result{
				ExitCode: 7,
				Stdout:   []byte(`{"version":1}` + "\n"),
			},
		},
		"stderr": {
			argv: validEmpty,
			result: hostruntime.Result{
				ExitCode: 0,
				Stdout:   []byte(`{"version":1}` + "\n"),
				Stderr:   []byte("unexpected"),
			},
		},
		"truncated": {
			argv: validEmpty,
			result: hostruntime.Result{
				ExitCode:        0,
				Stdout:          []byte(`{"version":1}` + "\n"),
				StdoutTruncated: true,
			},
		},
		"runner error": {
			argv:   validEmpty,
			result: hostruntime.Result{ExitCode: 0},
			err:    errors.New("injected"),
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			base := &oneShotRecorderRunner{
				next: test.result,
				err:  test.err,
			}
			recorder, err := newTask11OneShotRecorder(
				base,
				oneShotTestRecorderBinding(),
			)
			if err != nil {
				t.Fatalf(
					"newTask11OneShotRecorder: %v",
					err,
				)
			}
			if _, err := recorder.Run(
				context.Background(),
				test.argv,
				nil,
				nil,
			); err == nil {
				t.Fatal("accepted invalid transcript command")
			}
			if _, err := recorder.Take(); err == nil {
				t.Fatal("accepted poisoned transcript")
			}
		})
	}
}

func oneShotTestRecorderBinding() task11OneShotRecorderBinding {
	return task11OneShotRecorderBinding{
		DockerPath: oneShotTestDocker,
		BrokerName: "pghar-broker-test",
		Helper: task11OneShotCommandBinding{
			Image:           oneShotTestHelper,
			BuildID:         oneShotTestBuild,
			FleetGeneration: 29,
			SlotIdentity:    "slot-test",
			User:            "0:0",
			SeccompPath:     "/private/tmp/seccomp.json",
			Limits: hostruntime.OneShotLimits{
				MilliCPU:        250,
				MemoryBytes:     131072,
				MemorySwapBytes: 196608,
				PIDs:            8,
				FileDescriptors: 32,
			},
		},
		Verifier: task11OneShotCommandBinding{
			Image:           oneShotTestImage,
			BuildID:         oneShotTestBuild,
			FleetGeneration: 29,
			SlotIdentity:    "slot-test",
			User:            "1001:1001",
			SeccompPath:     "/private/tmp/seccomp.json",
			Limits: hostruntime.OneShotLimits{
				MilliCPU:        125,
				MemoryBytes:     262144,
				MemorySwapBytes: 327680,
				PIDs:            9,
				FileDescriptors: 40,
			},
		},
	}
}

func task11HelperArgvForTest(name string) []string {
	return []string{
		oneShotTestDocker, "run", "--rm",
		"--name", name,
		"--network", "container:" + oneShotTestBroker,
		"--cap-drop", "ALL",
		"--cap-add", "NET_ADMIN",
		"--read-only",
		"--security-opt", "no-new-privileges=true",
		"--security-opt", "seccomp=/private/tmp/seccomp.json",
		"--user", "0:0",
		"--cpus", "0.25",
		"--memory", "131072",
		"--memory-swap", "196608",
		"--pids-limit", "8",
		"--ulimit", "nofile=32:32",
		"--tmpfs",
		"/run:rw,noexec,nosuid,nodev,size=65536,uid=0,gid=0,mode=0700",
		"--log-driver", "none",
		"--env", "XTABLES_LOCKFILE=/run/xtables.lock",
		"--label", "io.portable-ghar.managed=true",
		"--label", "io.portable-ghar.kind=network-policy-helper",
		"--label", "io.portable-ghar.build-id=" + oneShotTestBuild,
		"--label", "io.portable-ghar.fleet-generation=29",
		"--label", "io.portable-ghar.slot=slot-test",
		"--entrypoint",
		"/usr/local/bin/portable-ghar-network-helper",
		oneShotTestHelper,
		"apply",
	}
}

func task11VerifierArgvForTest(
	name string,
	namespaceID string,
	operation string,
) []string {
	return []string{
		oneShotTestDocker, "run", "--rm",
		"--name", name,
		"--network", "container:" + namespaceID,
		"--cap-drop", "ALL",
		"--read-only",
		"--security-opt", "no-new-privileges=true",
		"--security-opt", "seccomp=/private/tmp/seccomp.json",
		"--user", "1001:1001",
		"--cpus", "0.125",
		"--memory", "262144",
		"--memory-swap", "327680",
		"--pids-limit", "9",
		"--ulimit", "nofile=40:40",
		"--log-driver", "none",
		"--label", "io.portable-ghar.managed=true",
		"--label", "io.portable-ghar.kind=network-verifier",
		"--label", "io.portable-ghar.build-id=" + oneShotTestBuild,
		"--label", "io.portable-ghar.fleet-generation=29",
		"--label", "io.portable-ghar.slot=slot-test",
		"--entrypoint",
		"/usr/local/bin/portable-ghar-network-verifier",
		oneShotTestImage,
		operation,
	}
}

func task11AbsenceArgvForTest(name string) []string {
	return []string{
		oneShotTestDocker,
		"ps",
		"-a",
		"--filter",
		"name=^/" + name + "$",
		"--format",
		"{{.ID}}",
	}
}

func oneShotSurfaceIDsForTest(
	surfaces []closedRuntimeSurface,
) []closedRuntimeSurfaceID {
	ids := make([]closedRuntimeSurfaceID, len(surfaces))
	for index, surface := range surfaces {
		ids[index] = surface.ID
	}
	return ids
}
