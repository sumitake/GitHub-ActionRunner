package testenv

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

const (
	task11HelperEntrypoint   = "/usr/local/bin/portable-ghar-network-helper"
	task11VerifierEntrypoint = "/usr/local/bin/portable-ghar-network-verifier"
	task11BrokerEntrypoint   = "/usr/local/bin/portable-ghar-network-broker-dialer"
	task11AdapterEntrypoint  = "/usr/local/bin/portable-ghar-network-adapter"
	task11RunnerEntrypoint   = "/usr/local/bin/portable-ghar-runner-gate"

	maxTask11OneShotTranscriptBytes = 16 << 10
)

var task11VerifierNamePattern = regexp.MustCompile(
	`^pghar-verifier-([0-9a-f]{32})-(empty|probe|identity|flood)$`,
)

type task11OneShotCommandBinding struct {
	Image           string
	BuildID         string
	FleetGeneration uint64
	SlotIdentity    string
	User            string
	SeccompPath     string
	Limits          hostruntime.OneShotLimits
}

type task11OneShotRecorderBinding struct {
	DockerPath string
	BrokerName string
	Helper     task11OneShotCommandBinding
	Verifier   task11OneShotCommandBinding
}

type task11OneShotRecorder struct {
	base    hostruntime.CommandRunner
	binding task11OneShotRecorderBinding

	mu sync.Mutex

	step                int
	pendingAbsence      string
	adapterID           string
	brokerID            string
	runnerID            string
	adapterVerifierStem string
	brokerVerifierStem  string
	repeatedBrokerAudit bool
	brokerAuditDocument []byte
	surfaces            []closedRuntimeSurface
	failed              bool
	taken               bool
}

func newTask11OneShotRecorder(
	base hostruntime.CommandRunner,
	binding task11OneShotRecorderBinding,
) (*task11OneShotRecorder, error) {
	if base == nil || !validTask11OneShotRecorderBinding(binding) {
		return nil, ErrFixtureStart
	}
	return &task11OneShotRecorder{
		base:     base,
		binding:  binding,
		surfaces: make([]closedRuntimeSurface, 0, len(oneShotRuntimeSurfaceOrder())),
	}, nil
}

func validTask11OneShotRecorderBinding(
	binding task11OneShotRecorderBinding,
) bool {
	return filepath.IsAbs(binding.DockerPath) &&
		validTask11ContainerName(binding.BrokerName) &&
		validTask11ContainerName(binding.BrokerName+"-policy") &&
		validTask11OneShotCommandBinding(binding.Helper) &&
		validTask11OneShotCommandBinding(binding.Verifier) &&
		binding.Helper.User == "0:0" &&
		binding.Helper.BuildID == binding.Verifier.BuildID &&
		binding.Helper.FleetGeneration ==
			binding.Verifier.FleetGeneration &&
		binding.Helper.SlotIdentity ==
			binding.Verifier.SlotIdentity &&
		binding.Helper.SeccompPath ==
			binding.Verifier.SeccompPath
}

func validTask11OneShotCommandBinding(
	binding task11OneShotCommandBinding,
) bool {
	uid, _, userOK := parseStaticNumericUser(binding.User)
	return binding.Image != "" &&
		isLowerHex(binding.BuildID, 64) &&
		binding.FleetGeneration != 0 &&
		binding.SlotIdentity != "" &&
		userOK &&
		(binding.User == "0:0" || uid != 0) &&
		filepath.IsAbs(binding.SeccompPath) &&
		binding.Limits.MilliCPU != 0 &&
		binding.Limits.MemoryBytes != 0 &&
		binding.Limits.MemorySwapBytes >=
			binding.Limits.MemoryBytes &&
		binding.Limits.PIDs != 0 &&
		binding.Limits.FileDescriptors != 0
}

func validTask11ContainerName(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, char := range value {
		if (char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			(index > 0 &&
				(char == '_' || char == '.' || char == '-')) {
			continue
		}
		return false
	}
	return true
}

// Run forwards the exact production command unchanged and records only the
// closed Task 11 transcript surfaces. The existing hostruntime parser remains
// semantic authority for each structured output; this recorder proves that
// the scanner later consumes the byte-identical bounded transport.
func (r *task11OneShotRecorder) Run(
	ctx context.Context,
	argv []string,
	extraFiles []*os.File,
	stdin io.Reader,
) (hostruntime.Result, error) {
	if r == nil || r.base == nil {
		return hostruntime.Result{}, ErrFixtureStart
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	result, runErr := r.base.Run(ctx, argv, extraFiles, stdin)
	if r.failed || r.taken {
		return result, runErr
	}

	if r.step == 14 && r.matchBrokerAudit(argv) {
		if r.repeatedBrokerAudit ||
			!validTask11TranscriptResult(
				result,
				runErr,
				closedRuntimeSurfaceStructuredJSON,
				surfaceBrokerAudit,
			) ||
			!bytes.Equal(result.Stdout, r.brokerAuditDocument) {
			r.fail()
			if runErr != nil {
				return result, runErr
			}
			return result, ErrClosedCommand
		}
		r.repeatedBrokerAudit = true
		return result, nil
	}

	id, encoding, matched := r.matchExpected(argv)
	if !matched {
		if r.looksRelevant(argv) {
			r.fail()
			if runErr != nil {
				return result, runErr
			}
			return result, ErrClosedCommand
		}
		return result, runErr
	}
	if !validTask11TranscriptResult(
		result,
		runErr,
		encoding,
		id,
	) {
		r.fail()
		if runErr != nil {
			return result, runErr
		}
		return result, ErrClosedCommand
	}

	document := append([]byte(nil), result.Stdout...)
	r.surfaces = append(r.surfaces, closedRuntimeSurface{
		ID:       id,
		Encoding: encoding,
		Document: document,
	})
	if id == surfaceBrokerAudit {
		r.brokerAuditDocument = append(
			r.brokerAuditDocument[:0],
			document...,
		)
	}
	r.step++
	return result, nil
}

func (r *task11OneShotRecorder) Take() (
	oneShotTranscriptCapture,
	error,
) {
	if r == nil {
		return oneShotTranscriptCapture{}, ErrClosedCommand
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failed ||
		r.taken ||
		r.step != len(oneShotRuntimeSurfaceOrder()) ||
		!r.repeatedBrokerAudit {
		r.fail()
		return oneShotTranscriptCapture{}, ErrClosedCommand
	}
	commandDigest, mountAbsenceDigest, err :=
		r.transcriptDigests()
	if err != nil {
		r.fail()
		return oneShotTranscriptCapture{}, ErrClosedCommand
	}
	capture := oneShotTranscriptCapture{
		surfaces:           takeClosedRuntimeSurfaces(&r.surfaces),
		commandDigest:      commandDigest,
		mountAbsenceDigest: mountAbsenceDigest,
		valid:              true,
	}
	if !validOneShotTranscriptCapture(capture) {
		destroyClosedRuntimeSurfaces(capture.surfaces)
		r.fail()
		return oneShotTranscriptCapture{}, ErrClosedCommand
	}
	r.taken = true
	zeroClosedBytes(r.brokerAuditDocument)
	r.brokerAuditDocument = nil
	return capture, nil
}

func (r *task11OneShotRecorder) transcriptDigests() (
	string,
	string,
	error,
) {
	if r == nil ||
		!validTask11OneShotRecorderBinding(r.binding) ||
		!isLowerHex(r.adapterID, 64) ||
		!isLowerHex(r.brokerID, 64) ||
		!isLowerHex(r.runnerID, 64) ||
		!isLowerHex(r.adapterVerifierStem, 32) ||
		!isLowerHex(r.brokerVerifierStem, 32) ||
		len(r.surfaces) != len(oneShotRuntimeSurfaceOrder()) {
		return "", "", ErrClosedCommand
	}
	type surfaceWire struct {
		ID       closedRuntimeSurfaceID       `json:"id"`
		Encoding closedRuntimeSurfaceEncoding `json:"encoding"`
		Document []byte                       `json:"document"`
	}
	surfaces := make([]surfaceWire, 0, len(r.surfaces))
	for _, surface := range r.surfaces {
		surfaces = append(surfaces, surfaceWire(surface))
	}
	commandDigest, err := recordingCanonicalDigest(
		"portable-ghar.task11.one-shot-transcript.v1\x00",
		struct {
			SchemaVersion       uint8                        `json:"schema_version"`
			Binding             task11OneShotRecorderBinding `json:"binding"`
			AdapterID           string                       `json:"adapter_id"`
			BrokerID            string                       `json:"broker_id"`
			RunnerID            string                       `json:"runner_id"`
			AdapterVerifierStem string                       `json:"adapter_verifier_stem"`
			BrokerVerifierStem  string                       `json:"broker_verifier_stem"`
			Surfaces            []surfaceWire                `json:"surfaces"`
		}{
			SchemaVersion:       1,
			Binding:             r.binding,
			AdapterID:           r.adapterID,
			BrokerID:            r.brokerID,
			RunnerID:            r.runnerID,
			AdapterVerifierStem: r.adapterVerifierStem,
			BrokerVerifierStem:  r.brokerVerifierStem,
			Surfaces:            surfaces,
		},
	)
	if err != nil {
		return "", "", ErrClosedCommand
	}
	absenceDigest, err := recordingCanonicalDigest(
		"portable-ghar.task11.one-shot-mount-absence.v1\x00",
		struct {
			SchemaVersion uint8    `json:"schema_version"`
			DockerPath    string   `json:"docker_path"`
			Names         []string `json:"names"`
		}{
			SchemaVersion: 1,
			DockerPath:    r.binding.DockerPath,
			Names: []string{
				"pghar-verifier-" +
					r.adapterVerifierStem +
					"-empty",
				r.binding.BrokerName + "-policy",
				"pghar-verifier-" +
					r.adapterVerifierStem +
					"-probe",
				"pghar-verifier-" +
					r.brokerVerifierStem +
					"-identity",
				"pghar-verifier-" +
					r.adapterVerifierStem +
					"-flood",
			},
		},
	)
	if err != nil || commandDigest == absenceDigest {
		return "", "", ErrClosedCommand
	}
	return commandDigest, absenceDigest, nil
}

func (r *task11OneShotRecorder) fail() {
	r.failed = true
	destroyClosedRuntimeSurfaces(r.surfaces)
	r.surfaces = nil
	zeroClosedBytes(r.brokerAuditDocument)
	r.brokerAuditDocument = nil
	r.pendingAbsence = ""
	r.adapterID = ""
	r.brokerID = ""
	r.runnerID = ""
	r.adapterVerifierStem = ""
	r.brokerVerifierStem = ""
}

func (r *task11OneShotRecorder) matchExpected(
	argv []string,
) (closedRuntimeSurfaceID, closedRuntimeSurfaceEncoding, bool) {
	switch r.step {
	case 0:
		name, namespaceID, stem, ok := r.matchVerifierRun(
			argv,
			"namespace-empty",
			"empty",
		)
		if !ok {
			return "", 0, false
		}
		r.adapterID = namespaceID
		r.adapterVerifierStem = stem
		r.pendingAbsence = name
		return surfaceAdapterEmptinessVerifier,
			closedRuntimeSurfaceStructuredJSON,
			true
	case 1:
		if !r.matchAbsence(argv, r.pendingAbsence) {
			return "", 0, false
		}
		r.pendingAbsence = ""
		return surfaceAdapterEmptinessAbsence,
			closedRuntimeSurfaceRaw,
			true
	case 2:
		brokerID, ok := r.matchHelperRun(argv)
		if !ok {
			return "", 0, false
		}
		r.brokerID = brokerID
		r.pendingAbsence = r.binding.BrokerName + "-policy"
		return surfacePolicyHelperApplication,
			closedRuntimeSurfaceStructuredJSON,
			true
	case 3:
		if !r.matchAbsence(argv, r.pendingAbsence) {
			return "", 0, false
		}
		r.pendingAbsence = ""
		return surfacePolicyHelperAbsence,
			closedRuntimeSurfaceRaw,
			true
	case 4:
		return surfaceAuthorityFilesystem,
			closedRuntimeSurfaceStructuredJSON,
			r.matchBrokerExec(argv, false, "authority-id")
	case 5:
		return surfaceHeldSocketAudit,
			closedRuntimeSurfaceStructuredJSON,
			r.matchBrokerExec(argv, false, "socket-audit")
	case 6:
		return surfaceBrokerRelease,
			closedRuntimeSurfaceStructuredJSON,
			r.matchBrokerExec(argv, true, "release")
	case 7:
		return surfaceBrokerAudit,
			closedRuntimeSurfaceStructuredJSON,
			r.matchBrokerAudit(argv)
	case 8:
		return surfaceAdapterPeerBind,
			closedRuntimeSurfaceRaw,
			r.matchAdapterExec(argv, true, "bind-peer")
	case 9:
		name, namespaceID, stem, ok := r.matchVerifierRun(
			argv,
			"probe",
			"probe",
		)
		if !ok ||
			namespaceID != r.adapterID ||
			stem != r.adapterVerifierStem {
			return "", 0, false
		}
		r.pendingAbsence = name
		return surfaceProxyVerifier,
			closedRuntimeSurfaceStructuredJSON,
			true
	case 10:
		if !r.matchAbsence(argv, r.pendingAbsence) {
			return "", 0, false
		}
		r.pendingAbsence = ""
		return surfaceProxyVerifierAbsence,
			closedRuntimeSurfaceRaw,
			true
	case 11:
		name, namespaceID, stem, ok := r.matchVerifierRun(
			argv,
			"namespace-id",
			"identity",
		)
		if !ok || namespaceID != r.brokerID {
			return "", 0, false
		}
		r.brokerVerifierStem = stem
		r.pendingAbsence = name
		return surfaceBrokerNamespaceVerifier,
			closedRuntimeSurfaceStructuredJSON,
			true
	case 12:
		if !r.matchAbsence(argv, r.pendingAbsence) {
			return "", 0, false
		}
		r.pendingAbsence = ""
		return surfaceBrokerNamespaceAbsence,
			closedRuntimeSurfaceRaw,
			true
	case 13:
		runnerID, ok := r.matchRunnerNamespace(argv, "")
		if !ok {
			return "", 0, false
		}
		r.runnerID = runnerID
		return surfaceRunnerPreNamespace,
			closedRuntimeSurfaceStructuredJSON,
			true
	case 14:
		if !r.repeatedBrokerAudit {
			return "", 0, false
		}
		_, ok := r.matchRunnerNamespace(argv, r.runnerID)
		return surfaceRunnerFinalNamespace,
			closedRuntimeSurfaceStructuredJSON,
			ok
	case 15:
		name, namespaceID, stem, ok := r.matchVerifierRun(
			argv,
			"loopback-flood",
			"flood",
		)
		if !ok ||
			namespaceID != r.adapterID ||
			stem != r.adapterVerifierStem {
			return "", 0, false
		}
		r.pendingAbsence = name
		return surfaceLoopbackFloodVerifier,
			closedRuntimeSurfaceStructuredJSON,
			true
	case 16:
		if !r.matchAbsence(argv, r.pendingAbsence) {
			return "", 0, false
		}
		r.pendingAbsence = ""
		return surfaceLoopbackFloodAbsence,
			closedRuntimeSurfaceRaw,
			true
	default:
		return "", 0, false
	}
}

func (r *task11OneShotRecorder) matchHelperRun(
	argv []string,
) (string, bool) {
	if len(argv) != 48 ||
		!strings.HasPrefix(argv[6], "container:") {
		return "", false
	}
	brokerID := strings.TrimPrefix(argv[6], "container:")
	if !isLowerHex(brokerID, 64) {
		return "", false
	}
	want := task11HelperArgv(
		r.binding,
		r.binding.BrokerName+"-policy",
		brokerID,
	)
	return brokerID, slices.Equal(argv, want)
}

func (r *task11OneShotRecorder) matchVerifierRun(
	argv []string,
	operation string,
	suffix string,
) (string, string, string, bool) {
	if len(argv) != 42 ||
		!strings.HasPrefix(argv[6], "container:") {
		return "", "", "", false
	}
	name := argv[4]
	namespaceID := strings.TrimPrefix(argv[6], "container:")
	matches := task11VerifierNamePattern.FindStringSubmatch(name)
	if len(matches) != 3 ||
		matches[2] != suffix ||
		!isLowerHex(namespaceID, 64) {
		return "", "", "", false
	}
	want := task11VerifierArgv(
		r.binding,
		name,
		namespaceID,
		operation,
	)
	if !slices.Equal(argv, want) {
		return "", "", "", false
	}
	return name, namespaceID, matches[1], true
}

func (r *task11OneShotRecorder) matchAbsence(
	argv []string,
	name string,
) bool {
	return name != "" && slices.Equal(argv, []string{
		r.binding.DockerPath,
		"ps",
		"-a",
		"--filter",
		"name=^/" + name + "$",
		"--format",
		"{{.ID}}",
	})
}

func (r *task11OneShotRecorder) matchBrokerExec(
	argv []string,
	withStdin bool,
	operation string,
) bool {
	if !isLowerHex(r.brokerID, 64) {
		return false
	}
	want := []string{r.binding.DockerPath, "exec"}
	if withStdin {
		want = append(want, "-i")
	}
	want = append(
		want,
		r.brokerID,
		task11BrokerEntrypoint,
		operation,
	)
	return slices.Equal(argv, want)
}

func (r *task11OneShotRecorder) matchBrokerAudit(
	argv []string,
) bool {
	return r.matchBrokerExec(argv, false, "audit")
}

func (r *task11OneShotRecorder) matchAdapterExec(
	argv []string,
	withStdin bool,
	operation string,
) bool {
	if !isLowerHex(r.adapterID, 64) {
		return false
	}
	want := []string{r.binding.DockerPath, "exec"}
	if withStdin {
		want = append(want, "-i")
	}
	want = append(
		want,
		r.adapterID,
		task11AdapterEntrypoint,
		operation,
	)
	return slices.Equal(argv, want)
}

func (r *task11OneShotRecorder) matchRunnerNamespace(
	argv []string,
	expectedID string,
) (string, bool) {
	if len(argv) != 5 ||
		argv[0] != r.binding.DockerPath ||
		argv[1] != "exec" ||
		argv[3] != task11RunnerEntrypoint ||
		argv[4] != "netns-id" ||
		!isLowerHex(argv[2], 64) ||
		(expectedID != "" && argv[2] != expectedID) {
		return "", false
	}
	return argv[2], true
}

func (r *task11OneShotRecorder) looksRelevant(argv []string) bool {
	if len(argv) < 2 || argv[0] != r.binding.DockerPath {
		return false
	}
	for index, arg := range argv {
		switch arg {
		case task11HelperEntrypoint, task11VerifierEntrypoint:
			return index > 0
		}
	}
	if len(argv) >= 5 && argv[1] == "exec" {
		operation := argv[len(argv)-1]
		entrypoint := argv[len(argv)-2]
		switch entrypoint {
		case task11BrokerEntrypoint:
			return operation == "authority-id" ||
				operation == "socket-audit" ||
				operation == "release" ||
				operation == "audit"
		case task11AdapterEntrypoint:
			return operation == "bind-peer"
		case task11RunnerEntrypoint:
			return operation == "netns-id"
		}
	}
	if len(argv) == 7 &&
		argv[1] == "ps" &&
		argv[2] == "-a" &&
		argv[3] == "--filter" &&
		argv[5] == "--format" &&
		argv[6] == "{{.ID}}" {
		filter := argv[4]
		if filter ==
			"name=^/"+r.binding.BrokerName+"-policy$" {
			return true
		}
		const prefix = "name=^/"
		const suffix = "$"
		if strings.HasPrefix(filter, prefix) &&
			strings.HasSuffix(filter, suffix) {
			name := strings.TrimSuffix(
				strings.TrimPrefix(filter, prefix),
				suffix,
			)
			return task11VerifierNamePattern.MatchString(name)
		}
	}
	return false
}

func validTask11TranscriptResult(
	result hostruntime.Result,
	runErr error,
	encoding closedRuntimeSurfaceEncoding,
	id closedRuntimeSurfaceID,
) bool {
	if runErr != nil ||
		result.ExitCode != 0 ||
		result.Signaled ||
		result.StdoutTruncated ||
		result.StderrTruncated ||
		len(result.Stderr) != 0 ||
		len(result.Stdout) > maxTask11OneShotTranscriptBytes {
		return false
	}
	switch encoding {
	case closedRuntimeSurfaceStructuredJSON:
		value, err := parseGenericCanonicalJSONLine(result.Stdout)
		return err == nil && !genericJSONValuesContainSecret(value)
	case closedRuntimeSurfaceRaw:
		switch id {
		case surfaceAdapterEmptinessAbsence,
			surfacePolicyHelperAbsence,
			surfaceProxyVerifierAbsence,
			surfaceBrokerNamespaceAbsence,
			surfaceLoopbackFloodAbsence:
			return len(result.Stdout) == 0
		case surfaceAdapterPeerBind:
			return bytes.Equal(result.Stdout, []byte("OK\n"))
		}
	}
	return false
}

func task11HelperArgv(
	binding task11OneShotRecorderBinding,
	name string,
	brokerID string,
) []string {
	command := binding.Helper
	return []string{
		binding.DockerPath, "run", "--rm",
		"--name", name,
		"--network", "container:" + brokerID,
		"--cap-drop", "ALL",
		"--cap-add", "NET_ADMIN",
		"--read-only",
		"--security-opt", "no-new-privileges=true",
		"--security-opt", "seccomp=" + command.SeccompPath,
		"--user", "0:0",
		"--cpus", task11FormatMilliCPU(command.Limits.MilliCPU),
		"--memory", strconv.FormatUint(
			command.Limits.MemoryBytes,
			10,
		),
		"--memory-swap", strconv.FormatUint(
			command.Limits.MemorySwapBytes,
			10,
		),
		"--pids-limit", strconv.FormatUint(
			command.Limits.PIDs,
			10,
		),
		"--ulimit", fmt.Sprintf(
			"nofile=%d:%d",
			command.Limits.FileDescriptors,
			command.Limits.FileDescriptors,
		),
		"--tmpfs",
		"/run:rw,noexec,nosuid,nodev,size=65536,uid=0,gid=0,mode=0700",
		"--log-driver", "none",
		"--env", "XTABLES_LOCKFILE=/run/xtables.lock",
		"--label", "io.portable-ghar.managed=true",
		"--label", "io.portable-ghar.kind=network-policy-helper",
		"--label", "io.portable-ghar.build-id=" + command.BuildID,
		"--label", "io.portable-ghar.fleet-generation=" +
			strconv.FormatUint(command.FleetGeneration, 10),
		"--label", "io.portable-ghar.slot=" + command.SlotIdentity,
		"--entrypoint", task11HelperEntrypoint,
		command.Image,
		"apply",
	}
}

func task11VerifierArgv(
	binding task11OneShotRecorderBinding,
	name string,
	namespaceID string,
	operation string,
) []string {
	command := binding.Verifier
	return []string{
		binding.DockerPath, "run", "--rm",
		"--name", name,
		"--network", "container:" + namespaceID,
		"--cap-drop", "ALL",
		"--read-only",
		"--security-opt", "no-new-privileges=true",
		"--security-opt", "seccomp=" + command.SeccompPath,
		"--user", command.User,
		"--cpus", task11FormatMilliCPU(command.Limits.MilliCPU),
		"--memory", strconv.FormatUint(
			command.Limits.MemoryBytes,
			10,
		),
		"--memory-swap", strconv.FormatUint(
			command.Limits.MemorySwapBytes,
			10,
		),
		"--pids-limit", strconv.FormatUint(
			command.Limits.PIDs,
			10,
		),
		"--ulimit", fmt.Sprintf(
			"nofile=%d:%d",
			command.Limits.FileDescriptors,
			command.Limits.FileDescriptors,
		),
		"--log-driver", "none",
		"--label", "io.portable-ghar.managed=true",
		"--label", "io.portable-ghar.kind=network-verifier",
		"--label", "io.portable-ghar.build-id=" + command.BuildID,
		"--label", "io.portable-ghar.fleet-generation=" +
			strconv.FormatUint(command.FleetGeneration, 10),
		"--label", "io.portable-ghar.slot=" + command.SlotIdentity,
		"--entrypoint", task11VerifierEntrypoint,
		command.Image,
		operation,
	}
}

func task11FormatMilliCPU(value uint64) string {
	whole := value / 1000
	fraction := value % 1000
	if fraction == 0 {
		return strconv.FormatUint(whole, 10)
	}
	formatted := fmt.Sprintf("%d.%03d", whole, fraction)
	return strings.TrimRight(formatted, "0")
}
