package testenv

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"sync"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

const task11WorkflowToolEntrypoint = "/usr/local/bin/portable-ghar-workflow-tool-probe"

type task11WorkflowToolOutputWire struct {
	Version uint8              `json:"version"`
	ProbeID string             `json:"probe_id"`
	Action  workflowToolAction `json:"action"`
	Status  WorkflowToolStatus `json:"status"`
}

type task11WorkflowToolEntry struct {
	lease   workflowToolCleanupLease
	handle  cleanupHandle
	busy    bool
	ran     bool
	removed bool
}

type task11WorkflowToolRuntime struct {
	owner        *orchestratedFixtureRuntime
	dockerPath   string
	maximumBytes uint64
	runner       hostruntime.CommandRunner
	record       func(cleanupHandle) error
	bindings     []WorkflowToolBinding
	users        []string
	limits       workflowToolProbeLimits
	seccomp      hostruntime.SeccompBinding

	mu      sync.Mutex
	entries map[string]*task11WorkflowToolEntry
	handles map[cleanupHandle]*task11WorkflowToolEntry
}

func newTask11WorkflowToolRuntime(
	owner *orchestratedFixtureRuntime,
	dockerPath string,
	maximumBytes uint64,
	runner hostruntime.CommandRunner,
	record func(cleanupHandle) error,
	bindings []WorkflowToolBinding,
	users []string,
	limits workflowToolProbeLimits,
	seccomp hostruntime.SeccompBinding,
) (*task11WorkflowToolRuntime, error) {
	if owner == nil ||
		!validAbsolutePath(dockerPath) ||
		maximumBytes == 0 ||
		runner == nil ||
		record == nil ||
		!validWorkflowToolSourceBindings(bindings, users) ||
		!validWorkflowToolProbeLimits(limits) ||
		!validAbsolutePath(seccomp.Path) ||
		!isLowerHex(seccomp.SHA256, sha256.Size*2) {
		return nil, ErrFixtureStart
	}
	return &task11WorkflowToolRuntime{
		owner:        owner,
		dockerPath:   dockerPath,
		maximumBytes: maximumBytes,
		runner:       runner,
		record:       record,
		bindings:     append([]WorkflowToolBinding(nil), bindings...),
		users:        append([]string(nil), users...),
		limits:       limits,
		seccomp:      seccomp,
		entries:      make(map[string]*task11WorkflowToolEntry),
		handles:      make(map[cleanupHandle]*task11WorkflowToolEntry),
	}, nil
}

func (r *task11WorkflowToolRuntime) RegisterWorkflowToolCleanup(
	ctx context.Context,
	lease workflowToolCleanupLease,
) (string, error) {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return "", ErrFixtureStart
	}
	runnerID, ok := r.runnerID()
	if !ok {
		return "", ErrFixtureStart
	}
	expected, ok := workflowToolLeaseFor(runnerID, lease.ProbeID)
	if !ok || lease != expected || r.bindingIndex(lease.ProbeID) < 0 {
		return "", ErrFixtureStart
	}
	handle := cleanupHandle{
		kind: CleanupVerifier,
		id:   lease.IdentityDigest,
	}
	entry := &task11WorkflowToolEntry{
		lease:  lease,
		handle: handle,
	}
	r.mu.Lock()
	if _, exists := r.entries[lease.Name]; exists {
		r.mu.Unlock()
		return "", ErrFixtureStart
	}
	if _, exists := r.handles[handle]; exists {
		r.mu.Unlock()
		return "", ErrFixtureStart
	}
	r.entries[lease.Name] = entry
	r.handles[handle] = entry
	r.mu.Unlock()
	if err := r.record(handle); err != nil {
		r.mu.Lock()
		if r.entries[lease.Name] == entry {
			delete(r.entries, lease.Name)
			delete(r.handles, handle)
		}
		r.mu.Unlock()
		return "", ErrFixtureStart
	}
	digest, err := recordingCanonicalDigest(
		"portable-ghar.task11.workflow-tool-registration.v1\x00",
		struct {
			SchemaVersion uint32                   `json:"schema_version"`
			RunnerID      string                   `json:"runner_id"`
			Lease         workflowToolCleanupLease `json:"lease"`
		}{
			SchemaVersion: 1,
			RunnerID:      runnerID,
			Lease:         lease,
		},
	)
	if err != nil {
		return "", ErrFixtureStart
	}
	return digest, nil
}

func (r *task11WorkflowToolRuntime) RunWorkflowTool(
	ctx context.Context,
	spec workflowToolProbeSpec,
) (workflowToolExecution, error) {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return workflowToolExecution{}, ErrFixtureStart
	}
	index := r.bindingIndex(spec.ProbeID)
	if index < 0 {
		return workflowToolExecution{}, ErrFixtureStart
	}
	runnerID, ok := r.runnerID()
	if !ok {
		return workflowToolExecution{}, ErrFixtureStart
	}
	lease, ok := workflowToolLeaseFor(runnerID, spec.ProbeID)
	if !ok ||
		!validWorkflowToolProbeSpec(
			spec,
			r.bindings[index],
			lease,
		) ||
		spec.User != r.users[index] ||
		spec.NetworkContainerID != runnerID ||
		spec.Limits != r.limits ||
		spec.Seccomp != r.seccomp {
		return workflowToolExecution{}, ErrFixtureStart
	}
	r.mu.Lock()
	entry := r.entries[lease.Name]
	if entry == nil ||
		entry.lease != lease ||
		entry.busy ||
		entry.ran ||
		entry.removed {
		r.mu.Unlock()
		return workflowToolExecution{}, ErrFixtureStart
	}
	entry.busy = true
	entry.ran = true
	r.mu.Unlock()

	argv := task11WorkflowToolArgv(r.dockerPath, spec)
	result, runErr := r.runner.Run(ctx, argv, nil, nil)
	r.mu.Lock()
	if r.entries[lease.Name] == entry {
		entry.busy = false
	}
	r.mu.Unlock()
	defer destroyCommandResult(&result)
	if runErr != nil ||
		result.ExitCode != 0 ||
		result.Signaled ||
		result.StdoutTruncated ||
		result.StderrTruncated ||
		len(result.Stderr) != 0 ||
		uint64(len(result.Stdout)) > r.maximumBytes {
		return workflowToolExecution{}, ErrFixtureStart
	}
	wire, err := parseTask11WorkflowToolOutput(result.Stdout, spec)
	if err != nil {
		return workflowToolExecution{}, ErrFixtureStart
	}
	invocationDigest, err := recordingCanonicalDigest(
		"portable-ghar.task11.workflow-tool-invocation.v1\x00",
		struct {
			SchemaVersion uint32                `json:"schema_version"`
			Spec          workflowToolProbeSpec `json:"spec"`
			Argv          []string              `json:"argv"`
		}{
			SchemaVersion: 1,
			Spec:          spec,
			Argv:          argv,
		},
	)
	if err != nil {
		return workflowToolExecution{}, ErrFixtureStart
	}
	return workflowToolExecution{
		ProbeID:     wire.ProbeID,
		Status:      wire.Status,
		OutputBytes: uint64(len(result.Stdout)),
		OutputDigest: closedSessionDigest(
			"portable-ghar.task11.workflow-tool-output.v1\x00",
			result.Stdout,
		),
		InvocationDigest: invocationDigest,
	}, nil
}

func (r *task11WorkflowToolRuntime) ProveWorkflowToolAbsent(
	ctx context.Context,
	lease workflowToolCleanupLease,
) (string, error) {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return "", ErrFixtureStart
	}
	r.mu.Lock()
	entry := r.entries[lease.Name]
	if entry == nil ||
		entry.lease != lease ||
		entry.busy ||
		!entry.ran ||
		entry.removed {
		r.mu.Unlock()
		return "", ErrFixtureStart
	}
	entry.busy = true
	r.mu.Unlock()
	result, err := r.runner.Run(
		ctx,
		task11WorkflowToolInspectArgv(r.dockerPath, lease.Name),
		nil,
		nil,
	)
	absent := validTask11OneShotAbsence(
		result,
		err,
		lease.Name,
		r.maximumBytes,
	)
	destroyCommandResult(&result)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entries[lease.Name] != entry {
		return "", ErrFixtureStart
	}
	entry.busy = false
	if !absent {
		return "", ErrFixtureStart
	}
	entry.removed = true
	digest, digestErr := recordingCanonicalDigest(
		"portable-ghar.task11.workflow-tool-absence.v1\x00",
		struct {
			SchemaVersion uint32                   `json:"schema_version"`
			Lease         workflowToolCleanupLease `json:"lease"`
			Absent        bool                     `json:"absent"`
		}{
			SchemaVersion: 1,
			Lease:         lease,
			Absent:        true,
		},
	)
	if digestErr != nil {
		return "", ErrFixtureStart
	}
	return digest, nil
}

func (r *task11WorkflowToolRuntime) owns(handle cleanupHandle) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.handles[handle] != nil
}

func (r *task11WorkflowToolRuntime) remove(
	ctx context.Context,
	handle cleanupHandle,
) error {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return ErrFixtureCleanup
	}
	r.mu.Lock()
	entry := r.handles[handle]
	if entry == nil || entry.handle != handle || entry.busy {
		r.mu.Unlock()
		return ErrFixtureCleanup
	}
	if entry.removed {
		r.mu.Unlock()
		return nil
	}
	entry.busy = true
	name := entry.lease.Name
	r.mu.Unlock()

	result, err := r.runner.Run(
		ctx,
		[]string{r.dockerPath, "rm", "-f", name},
		nil,
		nil,
	)
	removed := validTask11OneShotRemoval(
		result,
		err,
		name,
		r.maximumBytes,
	) || validTask11OneShotAbsence(
		result,
		err,
		name,
		r.maximumBytes,
	)
	destroyCommandResult(&result)
	if removed {
		result, err = r.runner.Run(
			ctx,
			task11WorkflowToolInspectArgv(r.dockerPath, name),
			nil,
			nil,
		)
		removed = validTask11OneShotAbsence(
			result,
			err,
			name,
			r.maximumBytes,
		)
		destroyCommandResult(&result)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.handles[handle] != entry {
		return ErrFixtureCleanup
	}
	entry.busy = false
	if !removed {
		return ErrFixtureCleanup
	}
	entry.removed = true
	return nil
}

func (r *task11WorkflowToolRuntime) recordedRemoved(
	handle cleanupHandle,
) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.handles[handle]
	return entry != nil &&
		entry.handle == handle &&
		entry.removed &&
		!entry.busy
}

func (r *task11WorkflowToolRuntime) runnerID() (string, bool) {
	if r == nil || r.owner == nil {
		return "", false
	}
	r.owner.mu.Lock()
	defer r.owner.mu.Unlock()
	runner := r.owner.observation.Runner
	if !r.owner.observationReady ||
		r.owner.destroyAttempted ||
		r.owner.destroyed ||
		runner.kind != CleanupRunner ||
		!isLowerHex(runner.id, sha256.Size*2) {
		return "", false
	}
	return runner.id, true
}

func (r *task11WorkflowToolRuntime) bindingIndex(probeID string) int {
	if r == nil || probeID == "" {
		return -1
	}
	for index, binding := range r.bindings {
		if binding.ProbeID == probeID {
			return index
		}
	}
	return -1
}

func task11WorkflowToolArgv(
	dockerPath string,
	spec workflowToolProbeSpec,
) []string {
	uid, gid, _ := parseStaticNumericUser(spec.User)
	return []string{
		dockerPath, "run", "--rm",
		"--name", spec.Name,
		"--network", "container:" + spec.NetworkContainerID,
		"--cap-drop", "ALL",
		"--read-only",
		"--security-opt", "no-new-privileges=true",
		"--security-opt", "seccomp=" + spec.Seccomp.Path,
		"--user", spec.User,
		"--cpus", task11FormatMilliCPU(spec.Limits.MilliCPU),
		"--memory", strconv.FormatUint(spec.Limits.MemoryBytes, 10),
		"--memory-swap", strconv.FormatUint(
			spec.Limits.MemorySwapBytes,
			10,
		),
		"--pids-limit", strconv.FormatUint(spec.Limits.PIDs, 10),
		"--ulimit", fmt.Sprintf(
			"nofile=%d:%d",
			spec.Limits.FileDescriptors,
			spec.Limits.FileDescriptors,
		),
		"--tmpfs", fmt.Sprintf(
			"/work:rw,exec,nosuid,nodev,size=%d,uid=%d,gid=%d,mode=0700",
			spec.Limits.WorkTmpfsBytes,
			uid,
			gid,
		),
		"--tmpfs", fmt.Sprintf(
			"/tmp:rw,exec,nosuid,nodev,size=%d,uid=%d,gid=%d,mode=0700",
			spec.Limits.ScratchBytes,
			uid,
			gid,
		),
		"--log-driver", "none",
		"--entrypoint", task11WorkflowToolEntrypoint,
		spec.ImageReference,
		string(spec.Action),
	}
}

func task11WorkflowToolInspectArgv(
	dockerPath,
	name string,
) []string {
	return []string{
		dockerPath,
		"inspect",
		"--type",
		"container",
		name,
	}
}

func parseTask11WorkflowToolOutput(
	document []byte,
	spec workflowToolProbeSpec,
) (task11WorkflowToolOutputWire, error) {
	if len(document) == 0 ||
		document[len(document)-1] != '\n' {
		return task11WorkflowToolOutputWire{}, ErrFixtureStart
	}
	body := document[:len(document)-1]
	var wire task11WorkflowToolOutputWire
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil ||
		decoder.Decode(&struct{}{}) != io.EOF ||
		wire.Version != 1 ||
		wire.ProbeID != spec.ProbeID ||
		wire.Action != spec.Action ||
		!validTask11WorkflowToolStatus(wire.Status) {
		return task11WorkflowToolOutputWire{}, ErrFixtureStart
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, body) {
		return task11WorkflowToolOutputWire{}, ErrFixtureStart
	}
	return wire, nil
}

func validTask11WorkflowToolStatus(status WorkflowToolStatus) bool {
	switch status {
	case WorkflowToolSupported,
		WorkflowToolUnsupported,
		WorkflowToolFailed:
		return true
	default:
		return false
	}
}

var _ workflowToolProbeRuntime = (*task11WorkflowToolRuntime)(nil)
