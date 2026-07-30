package hostruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/sumitake/portable-ghar/internal/runtimeenv"
)

const (
	baseRunnerPath = runtimeenv.Path
	runnerHome     = runtimeenv.Home
	runnerLanguage = runtimeenv.Language
)

type runnerInspect struct {
	ID     string `json:"Id"`
	Config struct {
		Image      string            `json:"Image"`
		Labels     map[string]string `json:"Labels"`
		Env        []string          `json:"Env"`
		Entrypoint []string          `json:"Entrypoint"`
		Cmd        []string          `json:"Cmd"`
		User       string            `json:"User"`
	} `json:"Config"`
	State struct {
		Running    bool  `json:"Running"`
		Restarting bool  `json:"Restarting"`
		Dead       bool  `json:"Dead"`
		Pid        int64 `json:"Pid"`
		ExitCode   int   `json:"ExitCode"`
	} `json:"State"`
	HostConfig struct {
		NetworkMode     string            `json:"NetworkMode"`
		ReadonlyRootfs  bool              `json:"ReadonlyRootfs"`
		CapAdd          []string          `json:"CapAdd"`
		CapDrop         []string          `json:"CapDrop"`
		SecurityOpt     []string          `json:"SecurityOpt"`
		Binds           []string          `json:"Binds"`
		Devices         []json.RawMessage `json:"Devices"`
		Privileged      bool              `json:"Privileged"`
		PortBindings    map[string]any    `json:"PortBindings"`
		PublishAllPorts bool              `json:"PublishAllPorts"`
		PidMode         string            `json:"PidMode"`
		IpcMode         string            `json:"IpcMode"`
		UTSMode         string            `json:"UTSMode"`
		Tmpfs           map[string]string `json:"Tmpfs"`
		Memory          int64             `json:"Memory"`
		MemorySwap      int64             `json:"MemorySwap"`
		NanoCPUs        int64             `json:"NanoCpus"`
		PidsLimit       int64             `json:"PidsLimit"`
		Ulimits         []struct {
			Name string `json:"Name"`
			Soft int64  `json:"Soft"`
			Hard int64  `json:"Hard"`
		} `json:"Ulimits"`
		LogConfig struct {
			Type   string            `json:"Type"`
			Config map[string]string `json:"Config"`
		} `json:"LogConfig"`
		RestartPolicy struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
	} `json:"HostConfig"`
	Mounts []json.RawMessage `json:"Mounts"`
}

// AuditHeldRunner is a fail-closed, read-only audit. Failure is terminal for
// the runner because a configuration/process mismatch cannot be repaired
// without replacing the ephemeral container.
func (c *DockerCLI) AuditHeldRunner(ctx context.Context, handle RunnerHandle) (HeldRunnerAudit, error) {
	if c == nil || !handle.validFor(c.issuer) {
		return HeldRunnerAudit{}, errors.New("hostruntime: runner handle invalid")
	}
	c.mu.Lock()
	record := c.runners[handle.nonce]
	auditablePhase := record != nil &&
		(record.next == GateArm || record.next == GateRelease)
	if record == nil || record.destroyed || record.busy ||
		!auditablePhase || record.releaseAuthorized {
		if record != nil && !record.destroyed {
			record.destroyed = true
			zeroToken(&record.token)
			c.mu.Unlock()
			c.removeFailedRunner(ctx, record)
			return HeldRunnerAudit{}, errors.New("hostruntime: held runner audit order invalid")
		}
		c.mu.Unlock()
		return HeldRunnerAudit{}, errors.New("hostruntime: runner record unavailable")
	}
	record.busy = true
	c.mu.Unlock()

	proof, err := c.auditHeldRunnerRecord(ctx, record)
	c.mu.Lock()
	record.busy = false
	if err != nil {
		record.destroyed = true
		zeroToken(&record.token)
		c.mu.Unlock()
		c.removeFailedRunner(ctx, record)
		return HeldRunnerAudit{}, err
	}
	c.mu.Unlock()
	return proof, nil
}

func (c *DockerCLI) auditHeldRunnerRecord(ctx context.Context, record *runnerRecord) (HeldRunnerAudit, error) {
	if record == nil {
		return HeldRunnerAudit{}, errors.New("hostruntime: runner audit record unavailable")
	}
	if err := c.reinspectAdapter(ctx, record.adapter); err != nil {
		return HeldRunnerAudit{}, err
	}
	inspectResult, err := c.runner.Run(
		ctx,
		[]string{c.cfg.DockerPath, "inspect", "--type", "container", record.handle.id},
		nil,
		nil,
	)
	if err != nil || inspectResult.ExitCode != 0 || inspectResult.Signaled ||
		inspectResult.StdoutTruncated || inspectResult.StderrTruncated ||
		len(inspectResult.Stderr) != 0 {
		return HeldRunnerAudit{}, errors.New("hostruntime: runner inspection failed")
	}
	var documents []runnerInspect
	if err := json.Unmarshal(inspectResult.Stdout, &documents); err != nil || len(documents) != 1 {
		return HeldRunnerAudit{}, errors.New("hostruntime: runner inspection document invalid")
	}
	if err := validateHeldRunnerInspect(documents[0], record); err != nil {
		return HeldRunnerAudit{}, err
	}

	topResult, err := c.runner.Run(
		ctx,
		[]string{c.cfg.DockerPath, "top", record.handle.id, "-eo", "pid=,args="},
		nil,
		nil,
	)
	if err != nil || topResult.ExitCode != 0 || topResult.Signaled ||
		topResult.StdoutTruncated || topResult.StderrTruncated ||
		len(topResult.Stderr) != 0 ||
		!validHeldProcessInventory(topResult.Stdout, documents[0].State.Pid) {
		return HeldRunnerAudit{}, errors.New("hostruntime: held runner process inventory invalid")
	}
	digestInput := make([]byte, 0, len(inspectResult.Stdout)+len(topResult.Stdout)+1)
	digestInput = append(digestInput, inspectResult.Stdout...)
	digestInput = append(digestInput, 0)
	digestInput = append(digestInput, topResult.Stdout...)
	digest := sha256.Sum256(digestInput)
	zeroBytes(digestInput)
	return HeldRunnerAudit{
		runnerNonce: record.handle.nonce,
		issuer:      c.issuer,
		generation:  record.handle.fleetGeneration,
		digest:      digest,
	}, nil
}

func validateHeldRunnerInspect(document runnerInspect, record *runnerRecord) error {
	spec := record.spec
	labels := document.Config.Labels
	if document.ID != record.handle.id ||
		document.Config.Image != spec.Image ||
		len(labels) != 5 ||
		labels["io.portable-ghar.managed"] != "true" ||
		labels["io.portable-ghar.kind"] != "runner" ||
		labels["io.portable-ghar.build-id"] != spec.BuildID ||
		labels["io.portable-ghar.fleet-generation"] != strconv.FormatUint(spec.FleetGeneration, 10) ||
		labels["io.portable-ghar.slot"] != spec.SlotIdentity ||
		!equalStrings(document.Config.Entrypoint, []string{runnerEntrypoint}) ||
		!equalStrings(document.Config.Cmd, []string{"hold"}) ||
		document.Config.User != spec.User ||
		!validHeldRunnerEnvironment(document.Config.Env) ||
		!document.State.Running || document.State.Restarting || document.State.Dead ||
		document.State.Pid <= 0 || document.State.ExitCode != 0 {
		return errors.New("hostruntime: runner identity or state drifted")
	}
	host := document.HostConfig
	wantTmpfs := runnerTmpfs(spec)
	if host.NetworkMode != "container:"+spec.Adapter.id ||
		!host.ReadonlyRootfs ||
		!equalStrings(host.CapDrop, []string{"ALL"}) ||
		len(host.CapAdd) != 0 ||
		!equalStrings(host.SecurityOpt, []string{"no-new-privileges=true", "seccomp=" + spec.Seccomp.Path}) ||
		len(host.Binds) != 0 || len(host.Devices) != 0 || len(document.Mounts) != 0 ||
		host.Privileged || len(host.PortBindings) != 0 || host.PublishAllPorts ||
		host.PidMode != "" || host.IpcMode != "" || host.UTSMode != "" ||
		!equalStringMap(host.Tmpfs, wantTmpfs) ||
		host.Memory != int64(spec.Limits.MemoryBytes) ||
		host.MemorySwap != int64(spec.Limits.MemorySwapBytes) ||
		host.NanoCPUs != int64(spec.Limits.MilliCPU)*1_000_000 ||
		host.PidsLimit != int64(spec.Limits.PIDs) ||
		len(host.Ulimits) != 1 ||
		host.Ulimits[0].Name != "nofile" ||
		host.Ulimits[0].Soft != int64(spec.Limits.FileDescriptors) ||
		host.Ulimits[0].Hard != int64(spec.Limits.FileDescriptors) ||
		host.LogConfig.Type != "local" ||
		!equalStringMap(host.LogConfig.Config, map[string]string{
			"max-size": strconv.FormatUint(spec.Limits.LogBytes, 10) + "b",
			"max-file": strconv.FormatUint(spec.Limits.LogFiles, 10),
		}) ||
		host.RestartPolicy.Name != "no" {
		return errors.New("hostruntime: runner isolation or resource configuration drifted")
	}
	return nil
}

func validHeldRunnerEnvironment(environment []string) bool {
	return runtimeenv.MatchesImage(environment)
}

func validHeldProcessInventory(data []byte, wantPID int64) bool {
	if len(data) == 0 || !bytes.HasSuffix(data, []byte("\n")) ||
		bytes.Contains(data[:len(data)-1], []byte("\n")) ||
		bytes.Contains(data, []byte("\r")) {
		return false
	}
	fields := strings.Fields(string(data[:len(data)-1]))
	if len(fields) != 3 {
		return false
	}
	pid, err := strconv.ParseInt(fields[0], 10, 64)
	return err == nil &&
		strconv.FormatInt(pid, 10) == fields[0] &&
		pid == wantPID &&
		fields[1] == runnerEntrypoint &&
		fields[2] == "hold"
}

func runnerTmpfs(spec RunnerSpec) map[string]string {
	uid, gid, _ := parseUser(spec.User)
	return map[string]string{
		"/runner":  "rw,exec,nosuid,nodev,size=" + strconv.FormatUint(spec.Limits.RunnerTmpfsBytes, 10) + ",uid=" + strconv.FormatUint(uid, 10) + ",gid=" + strconv.FormatUint(gid, 10) + ",mode=0700",
		"/tmp":     "rw,exec,nosuid,nodev,size=" + strconv.FormatUint(spec.Limits.TmpTmpfsBytes, 10) + ",uid=" + strconv.FormatUint(uid, 10) + ",gid=" + strconv.FormatUint(gid, 10) + ",mode=0700",
		"/scratch": "rw,exec,nosuid,nodev,size=" + strconv.FormatUint(spec.Limits.ScratchBytes, 10) + ",uid=" + strconv.FormatUint(uid, 10) + ",gid=" + strconv.FormatUint(gid, 10) + ",mode=0700",
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalStringMap(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range right {
		if left[key] != value {
			return false
		}
	}
	return true
}
