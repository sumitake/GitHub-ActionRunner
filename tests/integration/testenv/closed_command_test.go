package testenv

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
)

type scriptedClosedRunner struct {
	argv   [][]string
	result hostruntime.Result
	err    error
}

func (r *scriptedClosedRunner) Run(
	_ context.Context,
	argv []string,
	_ []*os.File,
	_ io.Reader,
) (hostruntime.Result, error) {
	r.argv = append(r.argv, append([]string(nil), argv...))
	return r.result, r.err
}

type orderedClosedResult struct {
	result hostruntime.Result
	err    error
}

type orderedClosedRunner struct {
	argv    [][]string
	stdin   [][]byte
	results []orderedClosedResult
	events  *[]string
}

func (r *orderedClosedRunner) Run(
	_ context.Context,
	argv []string,
	_ []*os.File,
	stdin io.Reader,
) (hostruntime.Result, error) {
	if r.events != nil {
		*r.events = append(*r.events, "command")
	}
	r.argv = append(r.argv, append([]string(nil), argv...))
	var document []byte
	if stdin != nil {
		document, _ = io.ReadAll(stdin)
	}
	r.stdin = append(r.stdin, document)
	if len(r.results) == 0 {
		return hostruntime.Result{}, fmt.Errorf("unexpected command")
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result.result, result.err
}

type fakeClosedLeaseAuthority struct {
	events      *[]string
	registered  map[cleanupHandle]string
	retired     map[cleanupHandle]bool
	registerErr error
	retireErr   error
}

func (a *fakeClosedLeaseAuthority) Register(
	handle cleanupHandle,
	name string,
) error {
	if a.events != nil {
		*a.events = append(*a.events, "register")
	}
	if a.registerErr != nil {
		return a.registerErr
	}
	if a.registered == nil {
		a.registered = make(map[cleanupHandle]string)
	}
	if _, exists := a.registered[handle]; exists {
		return fmt.Errorf("duplicate handle")
	}
	for _, existing := range a.registered {
		if existing == name {
			return fmt.Errorf("duplicate name")
		}
	}
	a.registered[handle] = name
	return nil
}

func (a *fakeClosedLeaseAuthority) Retire(
	handle cleanupHandle,
) error {
	if a.events != nil {
		*a.events = append(*a.events, "retire")
	}
	if a.retireErr != nil {
		return a.retireErr
	}
	if _, exists := a.registered[handle]; !exists {
		return fmt.Errorf("unknown handle")
	}
	if a.retired == nil {
		a.retired = make(map[cleanupHandle]bool)
	}
	if a.retired[handle] {
		return fmt.Errorf("already retired")
	}
	a.retired[handle] = true
	return nil
}

func TestClosedCommandSurfaceUsesExactEnumArgvAndClearsRawOutput(t *testing.T) {
	t.Parallel()

	raw := []byte(`{"ServerVersion":"1.2.3"}`)
	runner := &scriptedClosedRunner{
		result: hostruntime.Result{Stdout: raw},
	}
	preflight, err := newPreflightSession(closedCommandConfig{
		DockerPath:   "/usr/bin/docker",
		FixtureRoot:  "/private/tmp/portable-ghar-fixture",
		MaximumBytes: 1024,
	}, runner)
	if err != nil {
		t.Fatalf("newPreflightSession: %v", err)
	}
	observation, err := preflight.Run(
		context.Background(),
		ClosedDockerServerVersion,
	)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if observation.Digest == "" ||
		observation.Bytes != uint64(len(`{"ServerVersion":"1.2.3"}`)) {
		t.Fatalf("observation = %+v", observation)
	}
	want := []string{
		"/usr/bin/docker",
		"version",
		"--format",
		"{{json .Server}}",
	}
	if len(runner.argv) != 1 || !reflect.DeepEqual(runner.argv[0], want) {
		t.Fatalf("argv = %v, want %v", runner.argv, want)
	}
	for index, value := range raw {
		if value != 0 {
			t.Fatalf("raw output byte %d not cleared: %d", index, value)
		}
	}
}

func TestPreflightImageInspectionBindsExactReferencesAndTypedUsers(
	t *testing.T,
) {
	t.Parallel()

	references := []staticImageBinding{
		{
			ID: "runner",
			Reference: "example/runner@sha256:" +
				inputDigestA,
		},
		{
			ID: "adapter",
			Reference: "example/adapter@sha256:" +
				inputDigestB,
		},
	}
	raw := []byte(
		fmt.Sprintf(
			`{"id":"sha256:%s","repo_digests":["%s"],"operating_system":"linux","architecture":"amd64","user":"0:0"}`+"\n"+
				`{"id":"sha256:%s","repo_digests":["%s"],"operating_system":"linux","architecture":"amd64","user":"1001:1001"}`+"\n",
			inputDigestC,
			references[0].Reference,
			inputDigestD,
			references[1].Reference,
		),
	)
	runner := &scriptedClosedRunner{
		result: hostruntime.Result{Stdout: raw},
	}
	preflight, err := newPreflightSession(closedCommandConfig{
		DockerPath:   "/usr/bin/docker",
		FixtureRoot:  "/private/tmp/portable-ghar-fixture",
		MaximumBytes: 4096,
		Images:       references,
	}, runner)
	if err != nil {
		t.Fatalf("newPreflightSession: %v", err)
	}
	observations, err := preflight.InspectImages(context.Background())
	if err != nil {
		t.Fatalf("InspectImages: %v", err)
	}
	if len(observations) != 2 ||
		observations[0].ID != "runner" ||
		observations[0].User != "0:0" ||
		observations[1].ID != "adapter" ||
		observations[1].User != "1001:1001" {
		t.Fatalf("image observations = %+v", observations)
	}
	want := []string{
		"/usr/bin/docker",
		"image",
		"inspect",
		"--format",
		`{"id":{{json .Id}},"repo_digests":{{json .RepoDigests}},"operating_system":{{json .Os}},"architecture":{{json .Architecture}},"user":{{json .Config.User}}}`,
		references[0].Reference,
		references[1].Reference,
	}
	if len(runner.argv) != 1 || !reflect.DeepEqual(runner.argv[0], want) {
		t.Fatalf("argv = %v, want %v", runner.argv, want)
	}
	for index, value := range raw {
		if value != 0 {
			t.Fatalf("raw image output byte %d not cleared: %d", index, value)
		}
	}
}

func TestPreflightImageInspectionRejectsMissingDuplicateOrWrongReference(
	t *testing.T,
) {
	t.Parallel()

	reference := "example/runner@sha256:" + inputDigestA
	config := closedCommandConfig{
		DockerPath:   "/usr/bin/docker",
		FixtureRoot:  "/private/tmp/portable-ghar-fixture",
		MaximumBytes: 4096,
		Images: []staticImageBinding{{
			ID: "runner", Reference: reference,
		}},
	}
	tests := map[string][]byte{
		"missing line": nil,
		"wrong reference": []byte(
			fmt.Sprintf(
				`{"id":"sha256:%s","repo_digests":["example/other@sha256:%s"],"operating_system":"linux","architecture":"amd64","user":"0:0"}`+"\n",
				inputDigestB,
				inputDigestA,
			),
		),
		"duplicate reference": []byte(
			fmt.Sprintf(
				`{"id":"sha256:%s","repo_digests":["%s","%s"],"operating_system":"linux","architecture":"amd64","user":"0:0"}`+"\n",
				inputDigestB,
				reference,
				reference,
			),
		),
		"named user": []byte(
			fmt.Sprintf(
				`{"id":"sha256:%s","repo_digests":["%s"],"operating_system":"linux","architecture":"amd64","user":"runner"}`+"\n",
				inputDigestB,
				reference,
			),
		),
	}
	for name, output := range tests {
		t.Run(name, func(t *testing.T) {
			runner := &scriptedClosedRunner{
				result: hostruntime.Result{Stdout: output},
			}
			preflight, err := newPreflightSession(config, runner)
			if err != nil {
				t.Fatalf("newPreflightSession: %v", err)
			}
			if _, err := preflight.InspectImages(
				context.Background(),
			); err == nil {
				t.Fatal("accepted invalid image observation")
			}
		})
	}
}

func TestPreflightDockerInfoUsesClosedTypedProjection(t *testing.T) {
	t.Parallel()

	raw := []byte(
		`{"server_version":"28.0.1","operating_system":"Example Linux","architecture":"x86_64","kernel_version":"6.12.1","cgroup_version":"2","memory_limit":true,"cpu_cfs":true,"pids_limit":true}` + "\n",
	)
	runner := &scriptedClosedRunner{
		result: hostruntime.Result{Stdout: raw},
	}
	preflight, err := newPreflightSession(closedCommandConfig{
		DockerPath:   "/usr/bin/docker",
		FixtureRoot:  "/private/tmp/portable-ghar-fixture",
		MaximumBytes: 4096,
	}, runner)
	if err != nil {
		t.Fatalf("newPreflightSession: %v", err)
	}
	observation, err := preflight.InspectDockerInfo(
		context.Background(),
	)
	if err != nil {
		t.Fatalf("InspectDockerInfo: %v", err)
	}
	if observation.ServerVersion != "28.0.1" ||
		observation.Architecture != "x86_64" ||
		!observation.MemoryLimit ||
		!observation.CPUCFS ||
		!observation.PIDsLimit {
		t.Fatalf("Docker info = %+v", observation)
	}
	want := []string{
		"/usr/bin/docker",
		"info",
		"--format",
		`{"server_version":{{json .ServerVersion}},"operating_system":{{json .OperatingSystem}},"architecture":{{json .Architecture}},"kernel_version":{{json .KernelVersion}},"cgroup_version":{{json .CgroupVersion}},"memory_limit":{{json .MemoryLimit}},"cpu_cfs":{{json .CPUCfs}},"pids_limit":{{json .PidsLimit}}}`,
	}
	if len(runner.argv) != 1 || !reflect.DeepEqual(runner.argv[0], want) {
		t.Fatalf("argv = %v, want %v", runner.argv, want)
	}
	for index, value := range raw {
		if value != 0 {
			t.Fatalf("raw Docker-info byte %d not cleared: %d", index, value)
		}
	}
}

func TestClosedCommandSurfaceRejectsUnknownOrUnboundedResult(t *testing.T) {
	t.Parallel()

	tests := map[string]hostruntime.Result{
		"nonzero":   {ExitCode: 2, Stderr: []byte("discarded")},
		"signaled":  {Signaled: true, Signal: "KILL"},
		"truncated": {StdoutTruncated: true},
		"oversize":  {Stdout: make([]byte, 33)},
	}
	for name, result := range tests {
		t.Run(name, func(t *testing.T) {
			runner := &scriptedClosedRunner{result: result}
			preflight, err := newPreflightSession(closedCommandConfig{
				DockerPath:   "/usr/bin/docker",
				FixtureRoot:  "/private/tmp/portable-ghar-fixture",
				MaximumBytes: 32,
			}, runner)
			if err != nil {
				t.Fatalf("newPreflightSession: %v", err)
			}
			if _, err := preflight.Run(
				context.Background(),
				ClosedDockerInfo,
			); err == nil {
				t.Fatalf("accepted %s result", name)
			}
			for _, buffer := range [][]byte{
				runner.result.Stdout,
				runner.result.Stderr,
			} {
				for _, value := range buffer {
					if value != 0 {
						t.Fatalf("%s raw result was not cleared", name)
					}
				}
			}
		})
	}

	runner := &scriptedClosedRunner{}
	preflight, err := newPreflightSession(closedCommandConfig{
		DockerPath:   "/usr/bin/docker",
		FixtureRoot:  "/private/tmp/portable-ghar-fixture",
		MaximumBytes: 32,
	}, runner)
	if err != nil {
		t.Fatalf("newPreflightSession: %v", err)
	}
	if _, err := preflight.Run(
		context.Background(),
		ClosedOperation(255),
	); err == nil {
		t.Fatal("accepted unknown operation")
	}
	if len(runner.argv) != 0 {
		t.Fatalf("unknown operation reached runner: %v", runner.argv)
	}
}

func TestClosedCommandSessionsRejectCrossPhaseOperationsBeforeExecution(
	t *testing.T,
) {
	t.Parallel()

	runner := &scriptedClosedRunner{
		result: hostruntime.Result{Stdout: []byte(`{}`)},
	}
	preflight, err := newPreflightSession(closedCommandConfig{
		DockerPath:   "/usr/bin/docker",
		FixtureRoot:  "/private/tmp/portable-ghar-fixture",
		MaximumBytes: 1024,
	}, runner)
	if err != nil {
		t.Fatalf("newPreflightSession: %v", err)
	}
	networkBinding := validClosedNetworkSessionBinding(t)
	networkBinding.Adapter = cleanupHandle{
		kind: CleanupAdapter,
		id:   inputDigestA,
	}
	networkBinding.Broker = cleanupHandle{
		kind: CleanupBroker,
		id:   inputDigestB,
	}
	network, err := newNetworkSession(
		preflight.surface,
		networkBinding,
		&fakeClosedLeaseAuthority{},
	)
	if err != nil {
		t.Fatalf("newNetworkSession: %v", err)
	}
	runnerSession, err := newRunnerSession(
		preflight.surface,
		runnerSessionBinding{
			Runner: cleanupHandle{
				kind: CleanupRunner,
				id:   inputDigestC,
			},
			User: "1001:1001",
		},
	)
	if err != nil {
		t.Fatalf("newRunnerSession: %v", err)
	}

	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "preflight cannot run namespace operation",
			run: func() error {
				_, err := preflight.Run(
					context.Background(),
					ClosedNamespaceRoutes,
				)
				return err
			},
		},
		{
			name: "network cannot run static operation",
			run: func() error {
				_, err := network.Run(
					context.Background(),
					ClosedDockerInfo,
				)
				return err
			},
		},
		{
			name: "network cannot run runner operation",
			run: func() error {
				_, err := network.Run(
					context.Background(),
					ClosedContainerSeccomp,
				)
				return err
			},
		},
		{
			name: "runner cannot run broker operation",
			run: func() error {
				_, err := runnerSession.Run(
					context.Background(),
					ClosedBrokerHTTPS,
				)
				return err
			},
		},
		{
			name: "runner cannot run static operation",
			run: func() error {
				_, err := runnerSession.Run(
					context.Background(),
					ClosedImageInspect,
				)
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := len(runner.argv)
			if err := test.run(); err == nil {
				t.Fatal("cross-phase operation was accepted")
			}
			if len(runner.argv) != before {
				t.Fatal("cross-phase operation reached command runner")
			}
		})
	}
}

func TestClosedCommandSessionsRejectCallerSynthesizedHandles(t *testing.T) {
	t.Parallel()

	surface, err := newClosedCommandSurface(closedCommandConfig{
		DockerPath:   "/usr/bin/docker",
		FixtureRoot:  "/private/tmp/portable-ghar-fixture",
		MaximumBytes: 1024,
	}, &scriptedClosedRunner{})
	if err != nil {
		t.Fatalf("newClosedCommandSurface: %v", err)
	}
	if _, err := newNetworkSession(
		surface,
		networkSessionBinding{
			Adapter: cleanupHandle{
				kind: CleanupRunner,
				id:   inputDigestA,
			},
			Broker: cleanupHandle{
				kind: CleanupBroker,
				id:   inputDigestB,
			},
		},
		&fakeClosedLeaseAuthority{},
	); err == nil {
		t.Fatal("network session accepted non-adapter handle")
	}
	if _, err := newRunnerSession(
		surface,
		runnerSessionBinding{
			Runner: cleanupHandle{
				kind: CleanupRunner,
				id:   "container-name",
			},
			User: "1001:1001",
		},
	); err == nil {
		t.Fatal("runner session accepted non-engine identity")
	}
}

func TestRunnerSessionObservesExactHeldGateSequenceAndNumericUser(
	t *testing.T,
) {
	t.Parallel()

	inventory := []byte(
		"417 /usr/local/bin/portable-ghar-runner-gate hold\n",
	)
	conformance := []byte(
		`{"version":1,"euid":1001,"egid":1001,"capabilities":{"effective":"0000000000000000","permitted":"0000000000000000","inheritable":"0000000000000000","bounding":"0000000000000000","ambient":"0000000000000000"},"raw_socket_denied":true,"bpf_denied":true,"unshare_denied":true,"setns_denied":true,"clone3_denied":true,"namespace_denied":true,"proc_sys_read_only":true,"proc_masks_present":true,"controller_database_absent":true,"docker_authority_absent":true,"host_control_absent":true,"secret_environment_absent":true,"jit_environment_absent":true,"synthetic_token_absent":true}` + "\n",
	)
	verifyVersion := []byte("2.336.0\n")
	listenerVersion := []byte("2.336.0\n")
	commandRunner := &orderedClosedRunner{
		results: []orderedClosedResult{
			{result: hostruntime.Result{Stdout: inventory}},
			{result: hostruntime.Result{Stdout: conformance}},
			{result: hostruntime.Result{
				Stdout: append([]byte(nil), inventory...),
			}},
			{result: hostruntime.Result{Stdout: verifyVersion}},
			{result: hostruntime.Result{Stdout: listenerVersion}},
			{result: hostruntime.Result{
				Stdout: append([]byte(nil), inventory...),
			}},
		},
	}
	surface, err := newClosedCommandSurface(closedCommandConfig{
		DockerPath:   "/usr/bin/docker",
		FixtureRoot:  "/private/tmp/portable-ghar-fixture",
		MaximumBytes: 4096,
	}, commandRunner)
	if err != nil {
		t.Fatalf("newClosedCommandSurface: %v", err)
	}
	session, err := newRunnerSession(
		surface,
		runnerSessionBinding{
			Runner: cleanupHandle{
				kind: CleanupRunner,
				id:   inputDigestA,
			},
			User: "1001:1001",
		},
	)
	if err != nil {
		t.Fatalf("newRunnerSession: %v", err)
	}
	observation, err := session.Observe(context.Background())
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if observation.Version != "2.336.0" ||
		observation.Conformance.EUID != 1001 ||
		observation.Conformance.EGID != 1001 ||
		observation.InventoryDigest == "" ||
		observation.ConformanceDigest == "" {
		t.Fatalf("runner observation = %+v", observation)
	}
	want := [][]string{
		{
			"/usr/bin/docker",
			"top",
			inputDigestA,
			"-eo",
			"pid=,args=",
		},
		{
			"/usr/bin/docker",
			"exec",
			"--user",
			"1001:1001",
			inputDigestA,
			"/usr/local/bin/portable-ghar-runner-gate",
			"conformance-observe",
		},
		{
			"/usr/bin/docker",
			"top",
			inputDigestA,
			"-eo",
			"pid=,args=",
		},
		{
			"/usr/bin/docker",
			"exec",
			"--user",
			"1001:1001",
			inputDigestA,
			"/usr/local/bin/portable-ghar-runner-gate",
			"verify-image",
		},
		{
			"/usr/bin/docker",
			"exec",
			"--user",
			"1001:1001",
			inputDigestA,
			"/opt/actions-runner/bin/Runner.Listener",
			"--version",
		},
		{
			"/usr/bin/docker",
			"top",
			inputDigestA,
			"-eo",
			"pid=,args=",
		},
	}
	if !reflect.DeepEqual(commandRunner.argv, want) {
		t.Fatalf("argv = %#v, want %#v", commandRunner.argv, want)
	}
	for index, input := range commandRunner.stdin {
		if len(input) != 0 {
			t.Fatalf("stdin %d = %q, want empty", index, input)
		}
	}
	if len(commandRunner.results) != 0 {
		t.Fatalf("unused scripted results = %d", len(commandRunner.results))
	}
	before := len(commandRunner.argv)
	if _, err := session.Observe(context.Background()); err == nil {
		t.Fatal("runner session allowed a second observation")
	}
	if len(commandRunner.argv) != before {
		t.Fatal("second observation reached the command runner")
	}
}

func TestRunnerSessionFailsClosedOnSequenceOrEvidenceDrift(
	t *testing.T,
) {
	t.Parallel()

	validInventory := []byte(
		"417 /usr/local/bin/portable-ghar-runner-gate hold\n",
	)
	validConformance := []byte(
		`{"version":1,"euid":1001,"egid":1001,"capabilities":{"effective":"0000000000000000","permitted":"0000000000000000","inheritable":"0000000000000000","bounding":"0000000000000000","ambient":"0000000000000000"},"raw_socket_denied":true,"bpf_denied":true,"unshare_denied":true,"setns_denied":true,"clone3_denied":true,"namespace_denied":true,"proc_sys_read_only":true,"proc_masks_present":true,"controller_database_absent":true,"docker_authority_absent":true,"host_control_absent":true,"secret_environment_absent":true,"jit_environment_absent":true,"synthetic_token_absent":true}` + "\n",
	)
	validResults := func() []orderedClosedResult {
		return []orderedClosedResult{
			{result: hostruntime.Result{
				Stdout: append([]byte(nil), validInventory...),
			}},
			{result: hostruntime.Result{
				Stdout: append([]byte(nil), validConformance...),
			}},
			{result: hostruntime.Result{
				Stdout: append([]byte(nil), validInventory...),
			}},
			{result: hostruntime.Result{Stdout: []byte("2.336.0\n")}},
			{result: hostruntime.Result{Stdout: []byte("2.336.0\n")}},
			{result: hostruntime.Result{
				Stdout: append([]byte(nil), validInventory...),
			}},
		}
	}
	tests := map[string]func([]orderedClosedResult) []orderedClosedResult{
		"extra process": func(results []orderedClosedResult) []orderedClosedResult {
			results[0].result.Stdout = []byte(
				"417 /usr/local/bin/portable-ghar-runner-gate hold\n" +
					"418 /bin/sh -c sleep 1\n",
			)
			return results
		},
		"inventory changed": func(results []orderedClosedResult) []orderedClosedResult {
			results[2].result.Stdout = []byte(
				"419 /usr/local/bin/portable-ghar-runner-gate hold\n",
			)
			return results
		},
		"identity changed": func(results []orderedClosedResult) []orderedClosedResult {
			results[1].result.Stdout = []byte(
				strings.Replace(
					string(results[1].result.Stdout),
					`"euid":1001`,
					`"euid":0`,
					1,
				),
			)
			return results
		},
		"stderr present": func(results []orderedClosedResult) []orderedClosedResult {
			results[1].result.Stderr = []byte("forbidden")
			return results
		},
		"verify version drift": func(results []orderedClosedResult) []orderedClosedResult {
			results[3].result.Stdout = []byte("2.335.1\n")
			return results
		},
		"listener version drift": func(results []orderedClosedResult) []orderedClosedResult {
			results[4].result.Stdout = []byte("2.335.1\n")
			return results
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			commandRunner := &orderedClosedRunner{
				results: mutate(validResults()),
			}
			surface, err := newClosedCommandSurface(
				closedCommandConfig{
					DockerPath: "/usr/bin/docker",
					FixtureRoot: "/private/tmp/" +
						"portable-ghar-fixture",
					MaximumBytes: 4096,
				},
				commandRunner,
			)
			if err != nil {
				t.Fatalf("newClosedCommandSurface: %v", err)
			}
			session, err := newRunnerSession(
				surface,
				runnerSessionBinding{
					Runner: cleanupHandle{
						kind: CleanupRunner,
						id:   inputDigestA,
					},
					User: "1001:1001",
				},
			)
			if err != nil {
				t.Fatalf("newRunnerSession: %v", err)
			}
			if _, err := session.Observe(
				context.Background(),
			); err == nil {
				t.Fatal("accepted drifted runner evidence")
			}
		})
	}
}

func TestRunnerSessionRejectsNoncanonicalNumericUser(t *testing.T) {
	t.Parallel()

	surface, err := newClosedCommandSurface(closedCommandConfig{
		DockerPath:   "/usr/bin/docker",
		FixtureRoot:  "/private/tmp/portable-ghar-fixture",
		MaximumBytes: 1024,
	}, &scriptedClosedRunner{})
	if err != nil {
		t.Fatalf("newClosedCommandSurface: %v", err)
	}
	for _, user := range []string{"runner", "1001", "01001:1001"} {
		if _, err := newRunnerSession(
			surface,
			runnerSessionBinding{
				Runner: cleanupHandle{
					kind: CleanupRunner,
					id:   inputDigestA,
				},
				User: user,
			},
		); err == nil {
			t.Fatalf("accepted user %q", user)
		}
	}
}

func TestNetworkSessionRunsOneExactClosedDenialsVerifier(
	t *testing.T,
) {
	t.Parallel()

	binding := validClosedNetworkSessionBinding(t)
	expectedName, expectedHandle := closedNetworkIdentityForTest(binding)
	graphDocument, err := networkjail.EncodeDecisionGraph(binding.Graph)
	if err != nil {
		t.Fatalf("EncodeDecisionGraph: %v", err)
	}
	defer zeroClosedBytes(graphDocument)
	report := closedDenialsDocumentForTest(binding.Graph)
	events := make([]string, 0, 4)
	commandRunner := &orderedClosedRunner{
		events: &events,
		results: []orderedClosedResult{
			{result: hostruntime.Result{Stdout: report}},
			{result: hostruntime.Result{
				ExitCode: 1,
				Stderr: []byte(
					"Error: No such object: " +
						expectedName + "\n",
				),
			}},
		},
	}
	surface, err := newClosedCommandSurface(closedCommandConfig{
		DockerPath:   "/usr/bin/docker",
		FixtureRoot:  "/private/tmp/portable-ghar-fixture",
		MaximumBytes: 64 << 10,
	}, commandRunner)
	if err != nil {
		t.Fatalf("newClosedCommandSurface: %v", err)
	}
	leases := &fakeClosedLeaseAuthority{events: &events}
	session, err := newNetworkSession(surface, binding, leases)
	if err != nil {
		t.Fatalf("newNetworkSession: %v", err)
	}
	observation, err := session.ObserveClosedDenials(
		context.Background(),
	)
	if err != nil {
		t.Fatalf("ObserveClosedDenials: %v", err)
	}
	if observation.Name != expectedName ||
		observation.Cleanup != expectedHandle ||
		observation.PolicyDigest != binding.Graph.Digest().String() ||
		observation.IPFamily != binding.Graph.IPFamily() ||
		observation.BrokerIPv6Posture !=
			binding.Graph.BrokerIPv6Posture() ||
		!isLowerHex(observation.BeforeDigest, sha256.Size*2) ||
		!isLowerHex(observation.DirectAfterDigest, sha256.Size*2) ||
		!isLowerHex(observation.ParserAfterDigest, sha256.Size*2) ||
		observation.Digest == "" ||
		!observation.Completed {
		t.Fatalf("closed-denials observation = %+v", observation)
	}
	wantArgv := [][]string{
		{
			"/usr/bin/docker", "run", "--rm",
			"--name", expectedName,
			"--network", "container:" + binding.Adapter.id,
			"--cap-drop", "ALL",
			"--read-only",
			"--security-opt", "no-new-privileges=true",
			"--security-opt",
			"seccomp=" + binding.VerifierSeccomp.Path,
			"--user", binding.VerifierUser,
			"--cpus", "0.5",
			"--memory", "131072",
			"--memory-swap", "262144",
			"--pids-limit", "8",
			"--ulimit", "nofile=16:16",
			"--log-driver", "none",
			"--label", "io.portable-ghar.managed=true",
			"--label",
			"io.portable-ghar.kind=network-verifier",
			"--label",
			"io.portable-ghar.build-id=" + binding.BuildID,
			"--label",
			"io.portable-ghar.fleet-generation=7",
			"--label",
			"io.portable-ghar.slot=" + binding.SlotIdentity,
			"--entrypoint",
			"/usr/local/bin/portable-ghar-network-verifier",
			binding.VerifierImage,
			"closed-denials",
		},
		{
			"/usr/bin/docker",
			"inspect",
			"--type",
			"container",
			expectedName,
		},
	}
	if !reflect.DeepEqual(commandRunner.argv, wantArgv) {
		t.Fatalf("argv = %#v, want %#v", commandRunner.argv, wantArgv)
	}
	if len(commandRunner.stdin) != 2 ||
		!reflect.DeepEqual(commandRunner.stdin[0], graphDocument) ||
		len(commandRunner.stdin[1]) != 0 {
		t.Fatalf("stdin = %#v", commandRunner.stdin)
	}
	if !reflect.DeepEqual(
		events,
		[]string{"register", "command", "command", "retire"},
	) {
		t.Fatalf("events = %v", events)
	}
	if leases.registered[expectedHandle] != expectedName ||
		!leases.retired[expectedHandle] {
		t.Fatalf(
			"lease state registered=%v retired=%v",
			leases.registered,
			leases.retired,
		)
	}
	for index, value := range report {
		if value != 0 {
			t.Fatalf(
				"raw closed-denials byte %d not cleared: %d",
				index,
				value,
			)
		}
	}
	before := len(commandRunner.argv)
	if _, err := session.ObserveClosedDenials(
		context.Background(),
	); err == nil {
		t.Fatal("network session allowed a second verifier")
	}
	if len(commandRunner.argv) != before {
		t.Fatal("second verifier reached the command runner")
	}
}

func TestNetworkSessionLeavesExactLeaseActiveOnEveryAmbiguousResult(
	t *testing.T,
) {
	t.Parallel()

	tests := map[string]func(
		networkSessionBinding,
		string,
	) ([]orderedClosedResult, error){
		"run nonzero": func(
			_ networkSessionBinding,
			name string,
		) ([]orderedClosedResult, error) {
			return []orderedClosedResult{
				{result: hostruntime.Result{
					ExitCode: 2,
					Stderr:   []byte("discarded"),
				}},
				{result: closedAbsentResultForTest(name)},
			}, nil
		},
		"malformed output": func(
			_ networkSessionBinding,
			name string,
		) ([]orderedClosedResult, error) {
			return []orderedClosedResult{
				{result: hostruntime.Result{
					Stdout: []byte("{}\n"),
				}},
				{result: closedAbsentResultForTest(name)},
			}, nil
		},
		"wrong absence identity": func(
			binding networkSessionBinding,
			_ string,
		) ([]orderedClosedResult, error) {
			return []orderedClosedResult{
				{result: hostruntime.Result{
					Stdout: closedDenialsDocumentForTest(
						binding.Graph,
					),
				}},
				{result: hostruntime.Result{
					ExitCode: 1,
					Stderr: []byte(
						"Error: No such object: " +
							"pghar-task11-verifier-" +
							"00000000000000000000000000000000" +
							"-denials\n",
					),
				}},
			}, nil
		},
		"absence success exit": func(
			binding networkSessionBinding,
			name string,
		) ([]orderedClosedResult, error) {
			return []orderedClosedResult{
				{result: hostruntime.Result{
					Stdout: closedDenialsDocumentForTest(
						binding.Graph,
					),
				}},
				{result: hostruntime.Result{
					Stdout: []byte(name),
				}},
			}, nil
		},
	}
	for name, resultsFor := range tests {
		t.Run(name, func(t *testing.T) {
			binding := validClosedNetworkSessionBinding(t)
			expectedName, expectedHandle :=
				closedNetworkIdentityForTest(binding)
			results, err := resultsFor(binding, expectedName)
			if err != nil {
				t.Fatalf("resultsFor: %v", err)
			}
			commandRunner := &orderedClosedRunner{
				results: results,
			}
			surface, err := newClosedCommandSurface(
				closedCommandConfig{
					DockerPath: "/usr/bin/docker",
					FixtureRoot: "/private/tmp/" +
						"portable-ghar-fixture",
					MaximumBytes: 64 << 10,
				},
				commandRunner,
			)
			if err != nil {
				t.Fatalf("newClosedCommandSurface: %v", err)
			}
			leases := &fakeClosedLeaseAuthority{}
			session, err := newNetworkSession(
				surface,
				binding,
				leases,
			)
			if err != nil {
				t.Fatalf("newNetworkSession: %v", err)
			}
			if _, err := session.ObserveClosedDenials(
				context.Background(),
			); err == nil {
				t.Fatal("accepted ambiguous verifier result")
			}
			if leases.registered[expectedHandle] != expectedName {
				t.Fatalf(
					"registered leases = %v",
					leases.registered,
				)
			}
			if leases.retired[expectedHandle] {
				t.Fatal("ambiguous verifier lease was retired")
			}
		})
	}
}

func TestNetworkSessionRejectsCleanupCollisionBeforeDockerRun(
	t *testing.T,
) {
	t.Parallel()

	binding := validClosedNetworkSessionBinding(t)
	expectedName, expectedHandle := closedNetworkIdentityForTest(binding)
	leases := &fakeClosedLeaseAuthority{
		registered: map[cleanupHandle]string{
			expectedHandle: expectedName,
		},
	}
	commandRunner := &orderedClosedRunner{}
	surface, err := newClosedCommandSurface(closedCommandConfig{
		DockerPath:   "/usr/bin/docker",
		FixtureRoot:  "/private/tmp/portable-ghar-fixture",
		MaximumBytes: 64 << 10,
	}, commandRunner)
	if err != nil {
		t.Fatalf("newClosedCommandSurface: %v", err)
	}
	session, err := newNetworkSession(surface, binding, leases)
	if err != nil {
		t.Fatalf("newNetworkSession: %v", err)
	}
	if _, err := session.ObserveClosedDenials(
		context.Background(),
	); err == nil {
		t.Fatal("accepted cleanup identity collision")
	}
	if len(commandRunner.argv) != 0 {
		t.Fatalf("collision reached Docker: %v", commandRunner.argv)
	}
}

func TestNetworkSessionRejectsChangedPreparedBinding(t *testing.T) {
	t.Parallel()

	surface, err := newClosedCommandSurface(closedCommandConfig{
		DockerPath:   "/usr/bin/docker",
		FixtureRoot:  "/private/tmp/portable-ghar-fixture",
		MaximumBytes: 64 << 10,
	}, &scriptedClosedRunner{})
	if err != nil {
		t.Fatalf("newClosedCommandSurface: %v", err)
	}
	tests := map[string]func(*networkSessionBinding){
		"broker kind": func(binding *networkSessionBinding) {
			binding.Broker.kind = CleanupRunner
		},
		"adapter id": func(binding *networkSessionBinding) {
			binding.Adapter.id = "container-name"
		},
		"build": func(binding *networkSessionBinding) {
			binding.BuildID = inputDigestA[:63]
		},
		"fleet": func(binding *networkSessionBinding) {
			binding.FleetGeneration = 0
		},
		"user": func(binding *networkSessionBinding) {
			binding.VerifierUser = "0:0"
		},
		"image": func(binding *networkSessionBinding) {
			binding.VerifierImage = "example/verifier:latest"
		},
		"seccomp": func(binding *networkSessionBinding) {
			binding.VerifierSeccomp.Path = "relative.json"
		},
		"limits": func(binding *networkSessionBinding) {
			binding.VerifierLimits.MemorySwapBytes =
				binding.VerifierLimits.MemoryBytes - 1
		},
		"spec digest": func(binding *networkSessionBinding) {
			binding.VerifierSpecDigest = inputDigestB[:63]
		},
		"graph": func(binding *networkSessionBinding) {
			binding.Graph = networkjail.DecisionGraph{}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			binding := validClosedNetworkSessionBinding(t)
			mutate(&binding)
			if _, err := newNetworkSession(
				surface,
				binding,
				&fakeClosedLeaseAuthority{},
			); err == nil {
				t.Fatal("accepted changed prepared binding")
			}
		})
	}
}

func TestScannerSessionCapturesExactRoleOrderAndReusesRunnerInventory(
	t *testing.T,
) {
	t.Parallel()

	inventory := []byte(
		"417 /usr/local/bin/portable-ghar-runner-gate hold\n",
	)
	conformance := []byte(
		`{"version":1,"euid":1001,"egid":1001,"capabilities":{"effective":"0000000000000000","permitted":"0000000000000000","inheritable":"0000000000000000","bounding":"0000000000000000","ambient":"0000000000000000"},"raw_socket_denied":true,"bpf_denied":true,"unshare_denied":true,"setns_denied":true,"clone3_denied":true,"namespace_denied":true,"proc_sys_read_only":true,"proc_masks_present":true,"controller_database_absent":true,"docker_authority_absent":true,"host_control_absent":true,"secret_environment_absent":true,"jit_environment_absent":true,"synthetic_token_absent":true}` + "\n",
	)
	inspect := func(role string) []byte {
		return []byte(fmt.Sprintf(
			`{"version":1,"env":["PATH=/usr/bin"],"entrypoint":["/usr/local/bin/%s"],"cmd":["hold"],"labels":{"io.portable-ghar.kind":"%s"},"mounts":[],"binds":[],"devices":[],"security_options":["no-new-privileges=true"]}`+"\n",
			role,
			role,
		))
	}
	commandRunner := &orderedClosedRunner{
		results: []orderedClosedResult{
			{result: hostruntime.Result{Stdout: inventory}},
			{result: hostruntime.Result{Stdout: conformance}},
			{result: hostruntime.Result{
				Stdout: append([]byte(nil), inventory...),
			}},
			{result: hostruntime.Result{Stdout: []byte("2.336.0\n")}},
			{result: hostruntime.Result{Stdout: []byte("2.336.0\n")}},
			{result: hostruntime.Result{
				Stdout: append([]byte(nil), inventory...),
			}},
			{result: hostruntime.Result{
				Stdout: inspect("adapter"),
			}},
			{result: hostruntime.Result{
				Stdout: []byte("501 adapter-hold\n"),
			}},
			{result: hostruntime.Result{
				Stdout: []byte("adapter-out\n"),
				Stderr: []byte("adapter-err\n"),
			}},
			{result: hostruntime.Result{
				Stdout: inspect("broker"),
			}},
			{result: hostruntime.Result{
				Stdout: []byte("601 broker-hold\n"),
			}},
			{result: hostruntime.Result{
				Stdout: []byte("broker-out\n"),
				Stderr: []byte("broker-err\n"),
			}},
			{result: hostruntime.Result{
				Stdout: inspect("runner"),
			}},
			{result: hostruntime.Result{
				Stdout: []byte("runner-out\n"),
				Stderr: []byte("runner-err\n"),
			}},
		},
	}
	surface, err := newClosedCommandSurface(closedCommandConfig{
		DockerPath:   "/usr/bin/docker",
		FixtureRoot:  "/private/tmp/portable-ghar-fixture",
		MaximumBytes: 64 << 10,
	}, commandRunner)
	if err != nil {
		t.Fatalf("newClosedCommandSurface: %v", err)
	}
	runner, err := newRunnerSession(
		surface,
		runnerSessionBinding{
			Runner: cleanupHandle{
				kind: CleanupRunner,
				id:   inputDigestC,
			},
			User: "1001:1001",
		},
	)
	if err != nil {
		t.Fatalf("newRunnerSession: %v", err)
	}
	if _, err := runner.Observe(context.Background()); err != nil {
		t.Fatalf("runner Observe: %v", err)
	}
	scanner, err := newScannerSession(
		surface,
		scannerSessionBinding{
			Adapter: cleanupHandle{
				kind: CleanupAdapter,
				id:   inputDigestA,
			},
			Broker: cleanupHandle{
				kind: CleanupBroker,
				id:   inputDigestB,
			},
			Runner: cleanupHandle{
				kind: CleanupRunner,
				id:   inputDigestC,
			},
		},
		runner,
	)
	if err != nil {
		t.Fatalf("newScannerSession: %v", err)
	}
	capture, err := scanner.Capture(context.Background())
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	defer destroyScannerCapture(&capture)
	wantIDs := []closedRuntimeSurfaceID{
		surfaceAdapterInspect,
		surfaceAdapterTop,
		surfaceAdapterLogsStdout,
		surfaceAdapterLogsStderr,
		surfaceBrokerInspect,
		surfaceBrokerTop,
		surfaceBrokerLogsStdout,
		surfaceBrokerLogsStderr,
		surfaceRunnerInspect,
		surfaceRunnerFinalInventory,
		surfaceRunnerLogsStdout,
		surfaceRunnerLogsStderr,
		surfaceRunnerConformance,
		surfaceRunnerVerifyImage,
		surfaceRunnerListenerVersion,
	}
	gotIDs := make([]closedRuntimeSurfaceID, len(capture.Surfaces))
	for index, surface := range capture.Surfaces {
		gotIDs[index] = surface.ID
	}
	if !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Fatalf("surface IDs = %v, want %v", gotIDs, wantIDs)
	}
	if !reflect.DeepEqual(
		capture.Surfaces[9].Document,
		[]byte(
			"417 /usr/local/bin/portable-ghar-runner-gate hold\n",
		),
	) {
		t.Fatalf(
			"runner inventory = %q",
			capture.Surfaces[9].Document,
		)
	}
	scannerArgv := commandRunner.argv[6:]
	wantScannerArgv := [][]string{
		scannerInspectArgvForTest(inputDigestA),
		{"/usr/bin/docker", "top", inputDigestA, "-eo", "pid=,args="},
		{"/usr/bin/docker", "logs", inputDigestA},
		scannerInspectArgvForTest(inputDigestB),
		{"/usr/bin/docker", "top", inputDigestB, "-eo", "pid=,args="},
		{"/usr/bin/docker", "logs", inputDigestB},
		scannerInspectArgvForTest(inputDigestC),
		{"/usr/bin/docker", "logs", inputDigestC},
	}
	if !reflect.DeepEqual(scannerArgv, wantScannerArgv) {
		t.Fatalf(
			"scanner argv = %#v, want %#v",
			scannerArgv,
			wantScannerArgv,
		)
	}
	before := len(commandRunner.argv)
	if _, err := scanner.Capture(context.Background()); err == nil {
		t.Fatal("scanner session allowed a second capture")
	}
	if len(commandRunner.argv) != before {
		t.Fatal("second capture reached the command runner")
	}
}

func validClosedNetworkSessionBinding(
	t *testing.T,
) networkSessionBinding {
	t.Helper()
	graph, _, err := networkjail.Compile(
		validCompositionPolicyManifest(),
	)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return networkSessionBinding{
		Adapter: cleanupHandle{
			kind: CleanupAdapter,
			id:   inputDigestA,
		},
		Broker: cleanupHandle{
			kind: CleanupBroker,
			id:   inputDigestB,
		},
		RunDigest:       inputDigestC,
		BuildID:         inputDigestD,
		FleetGeneration: 7,
		SlotIdentity:    "slot-1",
		VerifierImage: "example/verifier@sha256:" +
			inputDigestC,
		VerifierUser: "65532:65532",
		VerifierSeccomp: hostruntime.SeccompBinding{
			Path:   "/opt/portable-ghar/seccomp.json",
			SHA256: inputDigestB,
		},
		VerifierLimits: hostruntime.OneShotLimits{
			MilliCPU:        500,
			MemoryBytes:     131072,
			MemorySwapBytes: 262144,
			PIDs:            8,
			FileDescriptors: 16,
		},
		VerifierSpecDigest: inputDigestD,
		Graph:              graph,
	}
}

func closedNetworkIdentityForTest(
	binding networkSessionBinding,
) (string, cleanupHandle) {
	hash := sha256.New()
	_, _ = hash.Write(
		[]byte("portable-ghar.task11.closed-denials-name.v1\x00"),
	)
	for _, field := range []string{
		binding.Adapter.id,
		binding.RunDigest,
		binding.BuildID,
		strconv.FormatUint(binding.FleetGeneration, 10),
		binding.VerifierImage,
		binding.VerifierSpecDigest,
	} {
		_, _ = io.WriteString(hash, field)
	}
	full := hash.Sum(nil)
	return "pghar-task11-verifier-" +
			hex.EncodeToString(full[:16]) +
			"-denials",
		cleanupHandle{
			kind: CleanupVerifier,
			id:   hex.EncodeToString(full),
		}
}

func closedDenialsDocumentForTest(
	graph networkjail.DecisionGraph,
) []byte {
	return []byte(fmt.Sprintf(
		`{"version":1,"capabilities":{"effective":"0000000000000000","permitted":"0000000000000000","inheritable":"0000000000000000","bounding":"0000000000000000","ambient":"0000000000000000"},"policy_digest":"%s","ip_family":"%s","broker_ipv6_posture":"%s","before":{"identity":{"device":1,"inode":2},"loopback_only":true,"tables_empty":true,"conntrack_empty":true},"direct_after":{"identity":{"device":1,"inode":2},"loopback_only":true,"tables_empty":true,"conntrack_empty":true},"parser_after":{"identity":{"device":1,"inode":2},"loopback_only":true,"tables_empty":true,"conntrack":"unmeasured"},"ipv4_tcp":"ipv4_tcp_no_route","ipv4_udp":"ipv4_udp_no_route","ipv6_tcp":"ipv6_tcp_no_route","ipv6_udp":"ipv6_udp_family_unavailable","dns_udp":"dns_udp_no_route","raw_icmp":"raw_icmp_permission_denied","plaintext_http":"plaintext_http_parser_rejected","unsupported_connect_port":"unsupported_connect_port_parser_rejected","socks_bind":"socks_bind_parser_rejected","socks_udp_associate":"socks_udp_associate_parser_rejected","completed":true}`+"\n",
		graph.Digest().String(),
		graph.IPFamily(),
		graph.BrokerIPv6Posture(),
	))
}

func closedAbsentResultForTest(name string) hostruntime.Result {
	return hostruntime.Result{
		ExitCode: 1,
		Stderr: []byte(
			"Error: No such object: " + name + "\n",
		),
	}
}

func scannerInspectArgvForTest(id string) []string {
	return []string{
		"/usr/bin/docker",
		"inspect",
		"--type",
		"container",
		"--format",
		`{"version":1,"env":{{json .Config.Env}},"entrypoint":{{json .Config.Entrypoint}},"cmd":{{json .Config.Cmd}},"labels":{{json .Config.Labels}},"mounts":{{json .Mounts}},"binds":{{json .HostConfig.Binds}},"devices":{{json .HostConfig.Devices}},"security_options":{{json .HostConfig.SecurityOpt}}}`,
		id,
	}
}
