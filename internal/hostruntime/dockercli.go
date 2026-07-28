package hostruntime

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

const (
	maxSeccompBytes   = 1 << 20
	maxDockerMilliCPU = uint64(math.MaxInt64 / 1_000_000)
	maxBrokerRecords  = 1024
	adapterMountDst   = "/run/portable-ghar/broker"
	adapterEntrypoint = "/usr/local/bin/portable-ghar-network-adapter"
	runnerEntrypoint  = "/usr/local/bin/portable-ghar-runner-gate"
)

var (
	containerNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	imageRefPattern      = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+@sha256:[0-9a-f]{64}$`)
)

// DockerCLIConfig binds every path-valued Docker argument to a
// controller-owned root. No environment-derived Docker endpoint is used.
type DockerCLIConfig struct {
	DockerPath    string
	BrokerRoot    string
	SeccompRoot   string
	BrokerNetwork string
}

// DockerCLI is the only Docker argv constructor in Task 5.
type DockerCLI struct {
	cfg                DockerCLIConfig
	runner             CommandRunner
	issuer             [32]byte
	mu                 sync.Mutex
	adapters           map[[32]byte]*adapterRecord
	brokers            map[[32]byte]*brokerRecord
	brokerReservations map[[32]byte]brokerReservation
	runners            map[[32]byte]*runnerRecord
}

// NewDockerCLI validates fixed roots and creates an in-process handle issuer.
func NewDockerCLI(cfg DockerCLIConfig, runner CommandRunner) (*DockerCLI, error) {
	if runner == nil {
		return nil, errors.New("hostruntime: command runner required")
	}
	if err := validateAbsolute(cfg.DockerPath, "docker path"); err != nil {
		return nil, err
	}
	if err := validateAbsolute(cfg.BrokerRoot, "broker root"); err != nil {
		return nil, err
	}
	if err := validateAbsolute(cfg.SeccompRoot, "seccomp root"); err != nil {
		return nil, err
	}
	cli := &DockerCLI{
		cfg:                cfg,
		runner:             runner,
		adapters:           make(map[[32]byte]*adapterRecord),
		brokers:            make(map[[32]byte]*brokerRecord),
		brokerReservations: make(map[[32]byte]brokerReservation),
		runners:            make(map[[32]byte]*runnerRecord),
	}
	if _, err := io.ReadFull(rand.Reader, cli.issuer[:]); err != nil {
		return nil, errors.New("hostruntime: handle issuer generation failed")
	}
	return cli, nil
}

// CreateNetworkAdapter creates and starts one held namespace owner. The
// adapter opens no loopback listener until BindBrokerPeer consumes its exact
// broker proof.
func (c *DockerCLI) CreateNetworkAdapter(ctx context.Context, spec AdapterSpec) (AdapterHandle, error) {
	if c == nil {
		return AdapterHandle{}, errors.New("hostruntime: docker cli required")
	}
	if err := c.validateAdapterSpec(spec); err != nil {
		return AdapterHandle{}, err
	}
	if err := c.verifySeccomp(spec.Seccomp); err != nil {
		return AdapterHandle{}, err
	}
	var nonce [32]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return AdapterHandle{}, errors.New("hostruntime: adapter nonce generation failed")
	}
	result, err := c.runner.Run(ctx, c.adapterCreateArgv(spec), nil, nil)
	if err != nil {
		return AdapterHandle{}, errors.New("hostruntime: adapter create failed")
	}
	if result.ExitCode != 0 || result.Signaled || result.StdoutTruncated ||
		result.StderrTruncated || len(result.Stderr) != 0 {
		return AdapterHandle{}, errors.New("hostruntime: adapter create did not return bounded success")
	}
	id, err := parseContainerID(result.Stdout)
	if err != nil {
		return AdapterHandle{}, err
	}
	handle := newAdapterHandle(id, spec.Image, spec.BuildID, spec.FleetGeneration, c.issuer, nonce)
	c.mu.Lock()
	c.adapters[nonce] = &adapterRecord{handle: handle, spec: spec}
	c.mu.Unlock()
	return handle, nil
}

// CreateRunner re-inspects an issuer-bound adapter, then creates but does not
// start the held runner.
func (c *DockerCLI) CreateRunner(ctx context.Context, spec RunnerSpec) (RunnerHandle, error) {
	if c == nil {
		return RunnerHandle{}, errors.New("hostruntime: docker cli required")
	}
	if !spec.Adapter.validFor(c.issuer) {
		return RunnerHandle{}, errors.New("hostruntime: adapter handle invalid")
	}
	if err := c.validateRunnerSpec(spec); err != nil {
		return RunnerHandle{}, err
	}
	if err := checkRunnerMemoryFit(spec.Limits); err != nil {
		return RunnerHandle{}, err
	}
	if err := c.verifySeccomp(spec.Seccomp); err != nil {
		return RunnerHandle{}, err
	}
	if err := c.reinspectAdapter(ctx, spec.Adapter); err != nil {
		return RunnerHandle{}, err
	}
	var nonce [32]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return RunnerHandle{}, errors.New("hostruntime: runner nonce generation failed")
	}
	result, err := c.runner.Run(ctx, c.runnerCreateArgv(spec), nil, nil)
	if err != nil {
		return RunnerHandle{}, errors.New("hostruntime: runner create failed")
	}
	if result.ExitCode != 0 || result.Signaled || result.StdoutTruncated ||
		result.StderrTruncated || len(result.Stderr) != 0 {
		return RunnerHandle{}, errors.New("hostruntime: runner create did not return bounded success")
	}
	id, err := parseContainerID(result.Stdout)
	if err != nil {
		return RunnerHandle{}, err
	}
	handle := newRunnerHandle(
		id,
		spec.BuildID,
		spec.FleetGeneration,
		c.issuer,
		nonce,
		spec.Profile == HostProfileQTSCaplessRoot,
	)
	var token [releaseTokenBytes]byte
	if _, err := io.ReadFull(rand.Reader, token[:]); err != nil {
		_ = c.removeRunnerID(context.Background(), id)
		return RunnerHandle{}, errors.New("hostruntime: release token generation failed")
	}
	c.mu.Lock()
	c.runners[nonce] = &runnerRecord{
		handle:  handle,
		adapter: spec.Adapter,
		spec:    spec,
		next:    GateHydrateSeeds,
		token:   token,
	}
	c.mu.Unlock()
	return handle, nil
}

func (c *DockerCLI) validateAdapterSpec(spec AdapterSpec) error {
	if err := validateContainerName(spec.Name); err != nil {
		return err
	}
	if err := validateImageRef(spec.Image); err != nil {
		return err
	}
	if !isLowerHex64(spec.BuildID) {
		return errors.New("hostruntime: build id must be lowercase sha256")
	}
	if spec.FleetGeneration == 0 {
		return errors.New("hostruntime: fleet generation required")
	}
	if _, _, err := parseUser(spec.User); err != nil {
		return err
	}
	if err := validateDescendant(c.cfg.BrokerRoot, spec.BrokerParent, "broker parent"); err != nil {
		return err
	}
	if strings.Contains(spec.BrokerParent, ",") {
		return errors.New("hostruntime: broker parent contains mount delimiter")
	}
	if err := validateDescendant(c.cfg.SeccompRoot, spec.Seccomp.Path, "seccomp path"); err != nil {
		return err
	}
	return validateContainerLimits(spec.Limits)
}

func (c *DockerCLI) validateRunnerSpec(spec RunnerSpec) error {
	if err := validateContainerName(spec.Name); err != nil {
		return err
	}
	if err := validateImageRef(spec.Image); err != nil {
		return err
	}
	if !isLowerHex64(spec.BuildID) {
		return errors.New("hostruntime: build id must be lowercase sha256")
	}
	if spec.FleetGeneration == 0 || spec.FleetGeneration != spec.Adapter.fleetGeneration {
		return errors.New("hostruntime: runner generation does not match adapter")
	}
	if spec.BuildID != spec.Adapter.buildID {
		return errors.New("hostruntime: runner build does not match adapter")
	}
	uid, gid, err := parseUser(spec.User)
	if err != nil {
		return err
	}
	switch spec.Profile {
	case HostProfileStrictLinux:
		if uid == 0 {
			return errors.New("hostruntime: strict profile rejects uid zero")
		}
	case HostProfileQTSCaplessRoot:
		if uid != 0 || gid != 0 {
			return errors.New("hostruntime: qts-capless-root requires exact uid 0 gid 0")
		}
	default:
		return errors.New("hostruntime: host profile unsupported")
	}
	if err := validateDescendant(c.cfg.SeccompRoot, spec.Seccomp.Path, "seccomp path"); err != nil {
		return err
	}
	return validateRunnerLimits(spec.Limits)
}

func (c *DockerCLI) verifySeccomp(binding SeccompBinding) error {
	if !isLowerHex64(binding.SHA256) {
		return errors.New("hostruntime: seccomp digest invalid")
	}
	resolved, err := filepath.EvalSymlinks(binding.Path)
	if err != nil || resolved != filepath.Clean(binding.Path) {
		return errors.New("hostruntime: seccomp path is unavailable or indirect")
	}
	info, err := os.Lstat(binding.Path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return errors.New("hostruntime: seccomp file identity invalid")
	}
	file, err := os.Open(binding.Path)
	if err != nil {
		return errors.New("hostruntime: seccomp file open failed")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxSeccompBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxSeccompBytes {
		zeroBytes(data)
		return errors.New("hostruntime: seccomp file size invalid")
	}
	defer zeroBytes(data)
	digest := sha256.Sum256(data)
	want, _ := hex.DecodeString(binding.SHA256)
	if subtle.ConstantTimeCompare(digest[:], want) != 1 {
		return errors.New("hostruntime: seccomp digest mismatch")
	}
	if err := validateSeccompJSON(data); err != nil {
		return err
	}
	return nil
}

func (c *DockerCLI) adapterCreateArgv(spec AdapterSpec) []string {
	uid, gid, _ := parseUser(spec.User)
	return []string{
		c.cfg.DockerPath, "run", "--detach",
		"--name", spec.Name,
		"--network", "none",
		"--cap-drop", "ALL",
		"--read-only",
		"--security-opt", "no-new-privileges=true",
		"--security-opt", "seccomp=" + spec.Seccomp.Path,
		"--restart", "no",
		"--user", spec.User,
		"--cpus", formatMilliCPU(spec.Limits.MilliCPU),
		"--memory", strconv.FormatUint(spec.Limits.MemoryBytes, 10),
		"--pids-limit", strconv.FormatUint(spec.Limits.PIDs, 10),
		"--ulimit", fmt.Sprintf("nofile=%d:%d", spec.Limits.FileDescriptors, spec.Limits.FileDescriptors),
		"--tmpfs", fmt.Sprintf("/run/portable-ghar/state:rw,noexec,nosuid,nodev,size=%d,uid=%d,gid=%d,mode=0700", spec.Limits.TmpfsBytes, uid, gid),
		"--tmpfs", fmt.Sprintf("/tmp:rw,noexec,nosuid,nodev,size=%d,uid=%d,gid=%d,mode=0700", spec.Limits.ScratchBytes, uid, gid),
		"--log-driver", "local",
		"--log-opt", fmt.Sprintf("max-size=%db", spec.Limits.LogBytes),
		"--log-opt", fmt.Sprintf("max-file=%d", spec.Limits.LogFiles),
		"--mount", "type=bind,src=" + spec.BrokerParent + ",dst=" + adapterMountDst + ",readonly",
		"--label", "io.portable-ghar.managed=true",
		"--label", "io.portable-ghar.kind=network-adapter",
		"--label", "io.portable-ghar.build-id=" + spec.BuildID,
		"--label", "io.portable-ghar.fleet-generation=" + strconv.FormatUint(spec.FleetGeneration, 10),
		"--entrypoint", adapterEntrypoint,
		spec.Image,
		"hold",
	}
}

func (c *DockerCLI) runnerCreateArgv(spec RunnerSpec) []string {
	uid, gid, _ := parseUser(spec.User)
	return []string{
		c.cfg.DockerPath, "run", "--detach",
		"--name", spec.Name,
		"--network", "container:" + spec.Adapter.id,
		"--cap-drop", "ALL",
		"--read-only",
		"--security-opt", "no-new-privileges=true",
		"--security-opt", "seccomp=" + spec.Seccomp.Path,
		"--restart", "no",
		"--user", spec.User,
		"--cpus", formatMilliCPU(spec.Limits.MilliCPU),
		"--memory", strconv.FormatUint(spec.Limits.MemoryBytes, 10),
		"--pids-limit", strconv.FormatUint(spec.Limits.PIDs, 10),
		"--ulimit", fmt.Sprintf("nofile=%d:%d", spec.Limits.FileDescriptors, spec.Limits.FileDescriptors),
		"--tmpfs", fmt.Sprintf("/runner:rw,exec,nosuid,nodev,size=%d,uid=%d,gid=%d,mode=0700", spec.Limits.RunnerTmpfsBytes, uid, gid),
		"--tmpfs", fmt.Sprintf("/tmp:rw,exec,nosuid,nodev,size=%d,uid=%d,gid=%d,mode=0700", spec.Limits.TmpTmpfsBytes, uid, gid),
		"--tmpfs", fmt.Sprintf("/scratch:rw,exec,nosuid,nodev,size=%d,uid=%d,gid=%d,mode=0700", spec.Limits.ScratchBytes, uid, gid),
		"--log-driver", "local",
		"--log-opt", fmt.Sprintf("max-size=%db", spec.Limits.LogBytes),
		"--log-opt", fmt.Sprintf("max-file=%d", spec.Limits.LogFiles),
		"--label", "io.portable-ghar.managed=true",
		"--label", "io.portable-ghar.kind=runner",
		"--label", "io.portable-ghar.build-id=" + spec.BuildID,
		"--label", "io.portable-ghar.fleet-generation=" + strconv.FormatUint(spec.FleetGeneration, 10),
		"--entrypoint", runnerEntrypoint,
		spec.Image,
		"hold",
	}
}

func (c *DockerCLI) reinspectAdapter(ctx context.Context, handle AdapterHandle) error {
	if c == nil || !handle.validFor(c.issuer) {
		return errors.New("hostruntime: adapter handle invalid")
	}
	c.mu.Lock()
	record := c.adapters[handle.nonce]
	if record == nil || record.destroyed || record.handle.id != handle.id {
		c.mu.Unlock()
		return errors.New("hostruntime: adapter record unavailable")
	}
	spec := record.spec
	c.mu.Unlock()
	result, err := c.runner.Run(
		ctx,
		[]string{c.cfg.DockerPath, "inspect", "--type", "container", handle.id},
		nil,
		nil,
	)
	if err != nil || result.ExitCode != 0 || result.Signaled ||
		result.StdoutTruncated || result.StderrTruncated || len(result.Stderr) != 0 {
		return errors.New("hostruntime: adapter reinspection failed")
	}
	var documents []adapterInspect
	if err := json.Unmarshal(result.Stdout, &documents); err != nil || len(documents) != 1 {
		return errors.New("hostruntime: adapter reinspection document invalid")
	}
	document := documents[0]
	labels := document.Config.Labels
	if document.ID != handle.id ||
		document.Config.Image != spec.Image ||
		len(labels) != 4 ||
		labels["io.portable-ghar.managed"] != "true" ||
		labels["io.portable-ghar.kind"] != "network-adapter" ||
		labels["io.portable-ghar.build-id"] != spec.BuildID ||
		labels["io.portable-ghar.fleet-generation"] != strconv.FormatUint(spec.FleetGeneration, 10) ||
		!equalStrings(document.Config.Entrypoint, []string{adapterEntrypoint}) ||
		!equalStrings(document.Config.Cmd, []string{"hold"}) ||
		document.Config.User != spec.User || len(document.Config.Env) != 0 ||
		!document.State.Running || document.State.Restarting || document.State.Dead ||
		document.State.Pid <= 0 || document.State.ExitCode != 0 {
		return errors.New("hostruntime: adapter identity or isolation drifted")
	}
	host := document.HostConfig
	if host.NetworkMode != "none" || !host.ReadonlyRootfs ||
		!equalStrings(host.CapDrop, []string{"ALL"}) || len(host.CapAdd) != 0 ||
		!equalStrings(host.SecurityOpt, []string{"no-new-privileges=true", "seccomp=" + spec.Seccomp.Path}) ||
		len(host.Binds) != 0 || len(host.Devices) != 0 ||
		host.Privileged || len(host.PortBindings) != 0 || host.PublishAllPorts ||
		host.PidMode != "" || host.IpcMode != "" || host.UTSMode != "" ||
		!equalStringMap(host.Tmpfs, adapterTmpfs(spec)) ||
		host.Memory != int64(spec.Limits.MemoryBytes) ||
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
		host.RestartPolicy.Name != "no" ||
		len(document.Mounts) != 1 {
		return errors.New("hostruntime: adapter isolation or resource configuration drifted")
	}
	mount := document.Mounts[0]
	if mount.Type != "bind" || mount.Source != spec.BrokerParent ||
		mount.Destination != adapterMountDst || mount.RW ||
		(mount.Mode != "" && mount.Mode != "ro") ||
		(mount.Propagation != "" && mount.Propagation != "rprivate") {
		return errors.New("hostruntime: adapter broker mount drifted")
	}
	return nil
}

type adapterInspect struct {
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
		ExitCode   int64 `json:"ExitCode"`
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
	Mounts []struct {
		Type        string `json:"Type"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		Mode        string `json:"Mode"`
		RW          bool   `json:"RW"`
		Propagation string `json:"Propagation"`
	} `json:"Mounts"`
}

func adapterTmpfs(spec AdapterSpec) map[string]string {
	uid, gid, _ := parseUser(spec.User)
	return map[string]string{
		"/run/portable-ghar/state": "rw,noexec,nosuid,nodev,size=" + strconv.FormatUint(spec.Limits.TmpfsBytes, 10) + ",uid=" + strconv.FormatUint(uid, 10) + ",gid=" + strconv.FormatUint(gid, 10) + ",mode=0700",
		"/tmp":                     "rw,noexec,nosuid,nodev,size=" + strconv.FormatUint(spec.Limits.ScratchBytes, 10) + ",uid=" + strconv.FormatUint(uid, 10) + ",gid=" + strconv.FormatUint(gid, 10) + ",mode=0700",
	}
}

func validateContainerLimits(limits ContainerLimits) error {
	if limits.MilliCPU == 0 || limits.MemoryBytes == 0 || limits.PIDs == 0 ||
		limits.FileDescriptors == 0 || limits.TmpfsBytes == 0 ||
		limits.ScratchBytes == 0 || limits.LogBytes == 0 || limits.LogFiles == 0 {
		return errors.New("hostruntime: adapter limits must all be nonzero")
	}
	if limits.MilliCPU > maxDockerMilliCPU ||
		limits.MemoryBytes > math.MaxInt64 || limits.PIDs > math.MaxInt64 || limits.FileDescriptors > math.MaxInt64 {
		return errors.New("hostruntime: adapter limit exceeds docker range")
	}
	sum, ok := checkedAdd(limits.TmpfsBytes, limits.ScratchBytes)
	if !ok || sum > limits.MemoryBytes {
		return errors.New("hostruntime: adapter tmpfs exceeds memory")
	}
	return nil
}

func validateRunnerLimits(limits RunnerLimits) error {
	if limits.MilliCPU == 0 || limits.MemoryBytes == 0 || limits.PIDs == 0 ||
		limits.FileDescriptors == 0 || limits.ScratchBytes == 0 ||
		limits.LogBytes == 0 || limits.LogFiles == 0 ||
		limits.RunnerTmpfsBytes == 0 || limits.TmpTmpfsBytes == 0 ||
		limits.ProcessMarginBytes == 0 {
		return errors.New("hostruntime: runner limits must all be nonzero")
	}
	if limits.MilliCPU > maxDockerMilliCPU ||
		limits.MemoryBytes > math.MaxInt64 || limits.PIDs > math.MaxInt64 || limits.FileDescriptors > math.MaxInt64 {
		return errors.New("hostruntime: runner limit exceeds docker range")
	}
	return nil
}

func checkRunnerMemoryFit(limits RunnerLimits) error {
	total, ok := checkedAdd(limits.RunnerTmpfsBytes, limits.TmpTmpfsBytes)
	if !ok {
		return errors.New("hostruntime: runner tmpfs arithmetic overflow")
	}
	total, ok = checkedAdd(total, limits.ScratchBytes)
	if !ok {
		return errors.New("hostruntime: runner scratch arithmetic overflow")
	}
	total, ok = checkedAdd(total, limits.ProcessMarginBytes)
	if !ok || total > limits.MemoryBytes {
		return errors.New("hostruntime: runner tmpfs and process margin exceed memory")
	}
	return nil
}

func checkedAdd(a, b uint64) (uint64, bool) {
	result := a + b
	return result, result >= a
}

func validateContainerName(name string) error {
	if !containerNamePattern.MatchString(name) || hasControl(name) {
		return errors.New("hostruntime: container name invalid")
	}
	return nil
}

func validateImageRef(image string) error {
	if !imageRefPattern.MatchString(image) || hasControl(image) {
		return errors.New("hostruntime: image must be canonical digest reference")
	}
	return nil
}

func validateAbsolute(path, label string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || hasControl(path) {
		return fmt.Errorf("hostruntime: %s invalid", label)
	}
	return nil
}

func validateDescendant(root, path, label string) error {
	if err := validateAbsolute(path, label); err != nil {
		return err
	}
	relative, err := filepath.Rel(filepath.Clean(root), path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("hostruntime: %s escapes configured root", label)
	}
	return nil
}

func parseUser(value string) (uint64, uint64, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || hasControl(value) {
		return 0, 0, errors.New("hostruntime: user must be canonical uid:gid")
	}
	uid, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil || strconv.FormatUint(uid, 10) != parts[0] {
		return 0, 0, errors.New("hostruntime: uid invalid")
	}
	gid, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil || strconv.FormatUint(gid, 10) != parts[1] {
		return 0, 0, errors.New("hostruntime: gid invalid")
	}
	return uid, gid, nil
}

func parseContainerID(output []byte) (string, error) {
	value := string(output)
	if strings.HasSuffix(value, "\r\n") {
		value = strings.TrimSuffix(value, "\r\n")
	} else if strings.HasSuffix(value, "\n") {
		value = strings.TrimSuffix(value, "\n")
	}
	if !isLowerHex64(value) {
		return "", errors.New("hostruntime: docker returned invalid container id")
	}
	return value, nil
}

func formatMilliCPU(value uint64) string {
	whole := value / 1000
	fraction := value % 1000
	if fraction == 0 {
		return strconv.FormatUint(whole, 10)
	}
	formatted := fmt.Sprintf("%d.%03d", whole, fraction)
	return strings.TrimRight(formatted, "0")
}

func isLowerHex64(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func hasNUL(value string) bool { return strings.IndexByte(value, 0) >= 0 }

func hasControl(value string) bool {
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return true
		}
	}
	return false
}
