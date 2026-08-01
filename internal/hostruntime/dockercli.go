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
	createRandom       io.Reader
	issuer             [32]byte
	mu                 sync.Mutex
	adapters           map[[32]byte]*adapterRecord
	brokers            map[[32]byte]*brokerRecord
	brokerReservations map[[32]byte]brokerReservation
	pendingNames       map[string]struct{}
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
		createRandom:       rand.Reader,
		adapters:           make(map[[32]byte]*adapterRecord),
		brokers:            make(map[[32]byte]*brokerRecord),
		brokerReservations: make(map[[32]byte]brokerReservation),
		pendingNames:       make(map[string]struct{}),
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
	if ctx == nil {
		return AdapterHandle{}, errors.New("hostruntime: context required")
	}
	if err := c.validateAdapterSpec(spec); err != nil {
		return AdapterHandle{}, err
	}
	if err := c.verifySeccomp(spec.Seccomp); err != nil {
		return AdapterHandle{}, err
	}
	if err := c.reserveCreateName(spec.Name); err != nil {
		return AdapterHandle{}, err
	}
	reserved := true
	defer func() {
		if reserved {
			c.releaseCreateName(spec.Name)
		}
	}()
	var nonce [32]byte
	if _, err := io.ReadFull(c.createRandom, nonce[:]); err != nil {
		return AdapterHandle{}, errors.Join(
			errors.New("hostruntime: adapter nonce generation failed"),
			err,
		)
	}
	candidateID := ""
	reject := func(primary error) (AdapterHandle, error) {
		if candidateID == "" {
			return AdapterHandle{}, primary
		}
		return AdapterHandle{}, c.cleanupRejectedCreate(
			ctx,
			rejectedCreateIdentity{
				ContainerID:     candidateID,
				Name:            spec.Name,
				Kind:            "network-adapter",
				BuildID:         spec.BuildID,
				FleetGeneration: spec.FleetGeneration,
				SlotIdentity:    spec.SlotIdentity,
			},
			primary,
		)
	}
	result, err := c.runner.Run(ctx, c.adapterCreateArgv(spec), nil, nil)
	if err != nil {
		return reject(errors.Join(
			errors.New("hostruntime: adapter create failed"),
			err,
		))
	}
	if result.ExitCode != 0 || result.Signaled || result.StdoutTruncated ||
		result.StderrTruncated || len(result.Stderr) != 0 {
		return reject(errors.New("hostruntime: adapter create did not return bounded success"))
	}
	id, err := parseContainerID(result.Stdout)
	if err != nil {
		return reject(err)
	}
	candidateID = id
	handle := newAdapterHandle(
		id,
		spec.Image,
		spec.BuildID,
		spec.SlotIdentity,
		spec.FleetGeneration,
		c.issuer,
		nonce,
	)
	c.mu.Lock()
	if _, exists := c.adapters[nonce]; exists {
		c.mu.Unlock()
		return reject(errors.New("hostruntime: adapter nonce collision"))
	}
	c.adapters[nonce] = &adapterRecord{handle: handle, spec: spec}
	delete(c.pendingNames, spec.Name)
	reserved = false
	c.mu.Unlock()
	return handle, nil
}

// CreateRunner re-inspects an issuer-bound adapter, then creates but does not
// start the held runner.
func (c *DockerCLI) CreateRunner(ctx context.Context, spec RunnerSpec) (RunnerHandle, error) {
	if c == nil {
		return RunnerHandle{}, errors.New("hostruntime: docker cli required")
	}
	if ctx == nil {
		return RunnerHandle{}, errors.New("hostruntime: context required")
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
	if err := c.reserveCreateName(spec.Name); err != nil {
		return RunnerHandle{}, err
	}
	reserved := true
	defer func() {
		if reserved {
			c.releaseCreateName(spec.Name)
		}
	}()
	if err := c.reinspectAdapter(ctx, spec.Adapter); err != nil {
		return RunnerHandle{}, err
	}
	var nonce [32]byte
	if _, err := io.ReadFull(c.createRandom, nonce[:]); err != nil {
		return RunnerHandle{}, errors.Join(
			errors.New("hostruntime: runner nonce generation failed"),
			err,
		)
	}
	candidateID := ""
	reject := func(primary error) (RunnerHandle, error) {
		if candidateID == "" {
			return RunnerHandle{}, primary
		}
		return RunnerHandle{}, c.cleanupRejectedCreate(
			ctx,
			rejectedCreateIdentity{
				ContainerID:     candidateID,
				Name:            spec.Name,
				Kind:            "runner",
				BuildID:         spec.BuildID,
				FleetGeneration: spec.FleetGeneration,
				SlotIdentity:    spec.SlotIdentity,
			},
			primary,
		)
	}
	result, err := c.runner.Run(ctx, c.runnerCreateArgv(spec), nil, nil)
	if err != nil {
		return reject(errors.Join(
			errors.New("hostruntime: runner create failed"),
			err,
		))
	}
	if result.ExitCode != 0 || result.Signaled || result.StdoutTruncated ||
		result.StderrTruncated || len(result.Stderr) != 0 {
		return reject(errors.New("hostruntime: runner create did not return bounded success"))
	}
	id, err := parseContainerID(result.Stdout)
	if err != nil {
		return reject(err)
	}
	candidateID = id
	handle := newRunnerHandle(
		id,
		spec.BuildID,
		spec.SlotIdentity,
		spec.FleetGeneration,
		c.issuer,
		nonce,
		spec.Profile == HostProfileQTSCaplessRoot,
	)
	var token [releaseTokenBytes]byte
	if _, err := io.ReadFull(c.createRandom, token[:]); err != nil {
		return reject(errors.Join(
			errors.New("hostruntime: release token generation failed"),
			err,
		))
	}
	c.mu.Lock()
	if _, exists := c.runners[nonce]; exists {
		c.mu.Unlock()
		zeroToken(&token)
		return reject(errors.New("hostruntime: runner nonce collision"))
	}
	c.runners[nonce] = &runnerRecord{
		handle:  handle,
		adapter: spec.Adapter,
		spec:    spec,
		next:    GateHydrateSeeds,
		token:   token,
	}
	delete(c.pendingNames, spec.Name)
	reserved = false
	c.mu.Unlock()
	return handle, nil
}

func (c *DockerCLI) reserveCreateName(name string) error {
	if c == nil {
		return errors.New("hostruntime: docker cli required")
	}
	if err := validateContainerName(name); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pendingNames == nil {
		c.pendingNames = make(map[string]struct{})
	}
	if _, exists := c.pendingNames[name]; exists {
		return errors.New("hostruntime: container name already reserved")
	}
	for _, record := range c.adapters {
		if record != nil && record.spec.Name == name {
			return errors.New("hostruntime: container name already reserved")
		}
	}
	for _, record := range c.runners {
		if record != nil && record.spec.Name == name {
			return errors.New("hostruntime: container name already reserved")
		}
	}
	for _, record := range c.brokers {
		if record != nil && !record.directoriesGone && record.spec.Name == name {
			return errors.New("hostruntime: container name already reserved")
		}
	}
	for _, reservation := range c.brokerReservations {
		if reservation.name == name {
			return errors.New("hostruntime: container name already reserved")
		}
	}
	c.pendingNames[name] = struct{}{}
	return nil
}

func (c *DockerCLI) releaseCreateName(name string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	delete(c.pendingNames, name)
	c.mu.Unlock()
}

func (c *DockerCLI) cleanupRejectedCreate(
	parent context.Context,
	expected rejectedCreateIdentity,
	primary error,
) error {
	if primary == nil {
		primary = errors.New("hostruntime: create rejected")
	}
	if c == nil {
		return primary
	}
	if !validRejectedCreateIdentity(expected) {
		return errors.Join(
			primary,
			errors.New("hostruntime: rejected create cleanup identity invalid"),
		)
	}
	base := context.Background()
	if parent != nil {
		base = context.WithoutCancel(parent)
	}
	ctx, cancel := context.WithTimeout(base, cleanupTimeout)
	defer cancel()
	return errors.Join(
		primary,
		c.cleanupOwnedContainer(ctx, expected, false),
	)
}

func (c *DockerCLI) cleanupRejectedNamedCreate(
	parent context.Context,
	expected rejectedCreateIdentity,
	primary error,
) error {
	if primary == nil {
		primary = errors.New("hostruntime: create rejected")
	}
	_, cleanupErr := c.cleanupNamedContainer(parent, expected)
	return errors.Join(primary, cleanupErr)
}

func (c *DockerCLI) cleanupNamedContainer(
	parent context.Context,
	expected rejectedCreateIdentity,
) (bool, error) {
	if c == nil || expected.ContainerID != "" ||
		!validRejectedCreateIdentityFields(expected) {
		return false, errors.New("hostruntime: named cleanup identity invalid")
	}
	base := context.Background()
	if parent != nil {
		base = context.WithoutCancel(parent)
	}
	ctx, cancel := context.WithTimeout(base, cleanupTimeout)
	defer cancel()
	id, err := c.containerIDByExactName(ctx, expected.Name)
	if err != nil {
		return false, errors.New("hostruntime: named cleanup inventory failed")
	}
	if id == "" {
		return false, nil
	}
	expected.ContainerID = id
	if err := c.cleanupOwnedContainer(ctx, expected, true); err != nil {
		return true, err
	}
	if err := c.proveContainerAbsent(ctx, expected.ContainerID, expected.Name); err != nil {
		return true, err
	}
	return true, nil
}

func (c *DockerCLI) cleanupOwnedContainer(
	ctx context.Context,
	expected rejectedCreateIdentity,
	acceptAlreadyGone bool,
) error {
	if c == nil || ctx == nil || !validRejectedCreateIdentity(expected) {
		return errors.New("hostruntime: rejected create cleanup identity invalid")
	}
	inspectResult, inspectErr := c.runner.Run(
		ctx,
		[]string{
			c.cfg.DockerPath,
			"inspect",
			"--type",
			"container",
			expected.ContainerID,
		},
		nil,
		nil,
	)
	if inspectErr != nil || inspectResult.ExitCode != 0 ||
		inspectResult.Signaled || inspectResult.StdoutTruncated ||
		inspectResult.StderrTruncated || len(inspectResult.Stderr) != 0 {
		if acceptAlreadyGone &&
			c.proveContainerAbsent(ctx, expected.ContainerID, expected.Name) == nil {
			return nil
		}
		return errors.Join(
			errors.New("hostruntime: rejected create cleanup inspection failed"),
			inspectErr,
		)
	}
	var documents []rejectedCreateInspect
	if err := json.Unmarshal(inspectResult.Stdout, &documents); err != nil ||
		len(documents) != 1 ||
		!rejectedCreateInspectMatches(documents[0], expected) {
		return errors.New("hostruntime: rejected create cleanup identity proof failed")
	}
	removeResult, removeErr := c.runner.Run(
		ctx,
		[]string{
			c.cfg.DockerPath,
			"rm",
			"-f",
			expected.ContainerID,
		},
		nil,
		nil,
	)
	if removeErr != nil || removeResult.ExitCode != 0 ||
		removeResult.Signaled || removeResult.StdoutTruncated ||
		removeResult.StderrTruncated || len(removeResult.Stderr) != 0 {
		return errors.Join(
			errors.New("hostruntime: rejected create cleanup removal failed"),
			removeErr,
		)
	}
	return nil
}

func (c *DockerCLI) containerIDByExactName(
	ctx context.Context,
	name string,
) (string, error) {
	if c == nil || ctx == nil || validateContainerName(name) != nil {
		return "", errors.New("hostruntime: container inventory invalid")
	}
	return c.containerIDByFilter(
		ctx,
		"name=^/"+regexp.QuoteMeta(name)+"$",
		"",
	)
}

func (c *DockerCLI) containerIDByExactID(
	ctx context.Context,
	id string,
) (string, error) {
	if c == nil || ctx == nil || !isLowerHex64(id) {
		return "", errors.New("hostruntime: container inventory invalid")
	}
	return c.containerIDByFilter(ctx, "id="+id, id)
}

func (c *DockerCLI) containerIDByFilter(
	ctx context.Context,
	filter string,
	exactID string,
) (string, error) {
	result, err := c.runner.Run(
		ctx,
		[]string{
			c.cfg.DockerPath, "ps", "-a", "--no-trunc",
			"--filter", filter,
			"--format", "{{.ID}}",
		},
		nil,
		nil,
	)
	if err != nil || result.ExitCode != 0 || result.Signaled ||
		result.StdoutTruncated || result.StderrTruncated ||
		len(result.Stderr) != 0 {
		return "", errors.New("hostruntime: container inventory failed")
	}
	if len(result.Stdout) == 0 {
		return "", nil
	}
	id, err := parseContainerID(result.Stdout)
	if err != nil || (exactID != "" && id != exactID) {
		return "", errors.New("hostruntime: container inventory invalid")
	}
	return id, nil
}

func (c *DockerCLI) proveContainerAbsent(
	ctx context.Context,
	id string,
	name string,
) error {
	byID, err := c.containerIDByExactID(ctx, id)
	if err != nil || byID != "" {
		return errors.New("hostruntime: container id absence unproven")
	}
	byName, err := c.containerIDByExactName(ctx, name)
	if err != nil || byName != "" {
		return errors.New("hostruntime: container name absence unproven")
	}
	return nil
}

type rejectedCreateIdentity struct {
	ContainerID     string
	Name            string
	Kind            string
	Image           string
	BuildID         string
	FleetGeneration uint64
	SlotIdentity    string
	Entrypoint      []string
	Cmd             []string
	NetworkMode     string
}

type rejectedCreateInspect struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		Image      string            `json:"Image"`
		Labels     map[string]string `json:"Labels"`
		Entrypoint []string          `json:"Entrypoint"`
		Cmd        []string          `json:"Cmd"`
	} `json:"Config"`
	HostConfig struct {
		NetworkMode string `json:"NetworkMode"`
	} `json:"HostConfig"`
}

func validRejectedCreateIdentity(identity rejectedCreateIdentity) bool {
	return isLowerHex64(identity.ContainerID) &&
		validRejectedCreateIdentityFields(identity)
}

func validRejectedCreateIdentityFields(identity rejectedCreateIdentity) bool {
	if validateContainerName(identity.Name) != nil ||
		!isLowerHex64(identity.BuildID) ||
		identity.FleetGeneration == 0 ||
		validateContainerName(identity.SlotIdentity) != nil {
		return false
	}
	switch identity.Kind {
	case "network-adapter", "runner":
		return identity.Image == "" && len(identity.Entrypoint) == 0 &&
			len(identity.Cmd) == 0 && identity.NetworkMode == ""
	case "network-broker":
		return validateImageRef(identity.Image) == nil &&
			equalStrings(identity.Entrypoint, []string{brokerEntrypoint}) &&
			equalStrings(identity.Cmd, []string{"hold"}) &&
			validateContainerName(identity.NetworkMode) == nil
	case "network-policy-helper":
		return validateImageRef(identity.Image) == nil &&
			equalStrings(identity.Entrypoint, []string{helperEntrypoint}) &&
			equalStrings(identity.Cmd, []string{"apply"}) &&
			strings.HasPrefix(identity.NetworkMode, "container:") &&
			isLowerHex64(strings.TrimPrefix(identity.NetworkMode, "container:"))
	default:
		return false
	}
}

func rejectedCreateInspectMatches(
	document rejectedCreateInspect,
	expected rejectedCreateIdentity,
) bool {
	if document.ID != expected.ContainerID ||
		document.Name != "/"+expected.Name ||
		!equalStringMap(document.Config.Labels, map[string]string{
			"io.portable-ghar.managed":          "true",
			"io.portable-ghar.kind":             expected.Kind,
			"io.portable-ghar.build-id":         expected.BuildID,
			"io.portable-ghar.fleet-generation": strconv.FormatUint(expected.FleetGeneration, 10),
			"io.portable-ghar.slot":             expected.SlotIdentity,
		}) {
		return false
	}
	if expected.Image == "" {
		return true
	}
	return document.Config.Image == expected.Image &&
		equalStrings(document.Config.Entrypoint, expected.Entrypoint) &&
		equalStrings(document.Config.Cmd, expected.Cmd) &&
		document.HostConfig.NetworkMode == expected.NetworkMode
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
	if err := validateContainerName(spec.SlotIdentity); err != nil {
		return errors.New("hostruntime: slot identity invalid")
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
	if spec.SlotIdentity == "" || spec.SlotIdentity != spec.Adapter.slotIdentity {
		return errors.New("hostruntime: runner slot does not match adapter")
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
		"--memory-swap", strconv.FormatUint(spec.Limits.MemorySwapBytes, 10),
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
		"--label", "io.portable-ghar.slot=" + spec.SlotIdentity,
		"--entrypoint", adapterEntrypoint,
		spec.Image,
		"hold",
	}
}

func (c *DockerCLI) runnerCreateArgv(spec RunnerSpec) []string {
	uid, gid, _ := parseUser(spec.User)
	loopback := strings.Join([]string{"127", "0", "0", "1"}, ".")
	ipv6Loopback := strings.Join([]string{"", "", "1"}, ":")
	proxyURL := "http://" + loopback + ":18080"
	noProxy := loopback + "," + ipv6Loopback
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
		"--env", "HTTPS_PROXY=" + proxyURL,
		"--env", "https_proxy=" + proxyURL,
		"--env", "NO_PROXY=" + noProxy,
		"--env", "no_proxy=" + noProxy,
		"--cpus", formatMilliCPU(spec.Limits.MilliCPU),
		"--memory", strconv.FormatUint(spec.Limits.MemoryBytes, 10),
		"--memory-swap", strconv.FormatUint(spec.Limits.MemorySwapBytes, 10),
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
		"--label", "io.portable-ghar.slot=" + spec.SlotIdentity,
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
		len(labels) != 5 ||
		labels["io.portable-ghar.managed"] != "true" ||
		labels["io.portable-ghar.kind"] != "network-adapter" ||
		labels["io.portable-ghar.build-id"] != spec.BuildID ||
		labels["io.portable-ghar.fleet-generation"] != strconv.FormatUint(spec.FleetGeneration, 10) ||
		labels["io.portable-ghar.slot"] != spec.SlotIdentity ||
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
		Sysctls         map[string]string `json:"Sysctls"`
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
		limits.MemoryBytes > math.MaxInt64 ||
		limits.MemorySwapBytes < limits.MemoryBytes ||
		limits.MemorySwapBytes > math.MaxInt64 ||
		limits.PIDs > math.MaxInt64 || limits.FileDescriptors > math.MaxInt64 {
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
		limits.MemoryBytes > math.MaxInt64 ||
		limits.MemorySwapBytes < limits.MemoryBytes ||
		limits.MemorySwapBytes > math.MaxInt64 ||
		limits.PIDs > math.MaxInt64 || limits.FileDescriptors > math.MaxInt64 {
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
