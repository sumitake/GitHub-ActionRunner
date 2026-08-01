package hostruntime

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	brokerRelayMountDst     = "/run/portable-ghar/relay"
	brokerAuthorityMountDst = "/run/portable-ghar/authority"
	brokerEntrypoint        = "/usr/local/bin/portable-ghar-network-broker-dialer"
	brokerParserEntrypoint  = "/usr/local/bin/portable-ghar-network-broker-parser"
	helperEntrypoint        = "/usr/local/bin/portable-ghar-network-helper"
	brokerArmFrameBytes     = 44
	helperRunTmpfsBytes     = 64 << 10
)

type brokerPhase uint8

const (
	brokerPhaseStarting brokerPhase = iota + 1
	brokerPhaseHeld
	brokerPhasePolicyApplied
	brokerPhaseAuthorityBound
	brokerPhaseReleased
)

type brokerRecord struct {
	handle           BrokerHandle
	spec             BrokerSpec
	phase            brokerPhase
	busy             bool
	destroyed        bool
	containerRemoved bool
	directoriesGone  bool
	releaseAttempted bool
	token            [releaseTokenBytes]byte
	policyDigest     [sha256.Size]byte
	policyPosture    PolicyIPv6Posture
	policyRuntime    []byte
	authority        AuthorityProof
	readiness        brokerReadinessWire
	peer             BrokerPeerProof
	heldSocketZero   [sha256.Size]byte
}

type brokerReservation struct {
	name            string
	relayParent     string
	authorityParent string
}

// CreateNetworkBrokerHeld creates and starts one capability-less broker,
// arms its one-use in-memory release digest, and proves that its namespace
// owner is the only process before returning an opaque handle.
func (c *DockerCLI) CreateNetworkBrokerHeld(ctx context.Context, spec BrokerSpec) (BrokerHandle, error) {
	if c == nil {
		return BrokerHandle{}, errors.New("hostruntime: docker cli required")
	}
	if err := c.validateBrokerSpec(spec); err != nil {
		return BrokerHandle{}, err
	}
	if err := c.verifySeccomp(spec.Seccomp); err != nil {
		return BrokerHandle{}, err
	}
	var nonce [32]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return BrokerHandle{}, errors.New("hostruntime: broker nonce generation failed")
	}
	if err := c.reserveBrokerRecordSlot(spec, nonce); err != nil {
		return BrokerHandle{}, err
	}
	if err := c.reinspectAdapter(ctx, spec.Adapter); err != nil {
		c.releaseBrokerReservation(nonce)
		return BrokerHandle{}, err
	}
	var token [releaseTokenBytes]byte
	if _, err := io.ReadFull(rand.Reader, token[:]); err != nil {
		c.releaseBrokerReservation(nonce)
		return BrokerHandle{}, errors.New("hostruntime: broker release token generation failed")
	}

	result, err := c.runner.Run(ctx, c.brokerCreateArgv(spec), nil, nil)
	if err != nil || result.ExitCode != 0 || result.Signaled ||
		result.StdoutTruncated || result.StderrTruncated || len(result.Stderr) != 0 {
		zeroToken(&token)
		failure := c.cleanupRejectedNamedCreate(
			ctx,
			c.brokerCreateIdentity(spec),
			errors.New("hostruntime: broker create failed"),
		)
		c.releaseBrokerReservation(nonce)
		return BrokerHandle{}, failure
	}
	id, parseErr := parseContainerID(result.Stdout)
	if parseErr != nil {
		zeroToken(&token)
		failure := c.cleanupRejectedNamedCreate(
			ctx,
			c.brokerCreateIdentity(spec),
			parseErr,
		)
		c.releaseBrokerReservation(nonce)
		return BrokerHandle{}, failure
	}

	handle := newBrokerHandle(
		id,
		spec.BuildID,
		spec.SlotIdentity,
		spec.FleetGeneration,
		spec.Adapter.nonce,
		c.issuer,
		nonce,
	)
	record := &brokerRecord{
		handle: handle,
		spec:   spec,
		phase:  brokerPhaseStarting,
		busy:   true,
		token:  token,
	}
	c.mu.Lock()
	delete(c.brokerReservations, nonce)
	c.brokers[nonce] = record
	c.mu.Unlock()

	startResult, startErr := c.runner.Run(
		ctx,
		[]string{c.cfg.DockerPath, "start", id},
		nil,
		nil,
	)
	if startErr != nil || startResult.ExitCode != 0 || startResult.Signaled ||
		startResult.StdoutTruncated || startResult.StderrTruncated ||
		len(startResult.Stderr) != 0 ||
		!bytes.Equal(startResult.Stdout, []byte(id+"\n")) {
		return handle, c.failBrokerOperation(ctx, record, errors.New("hostruntime: broker start failed"))
	}

	arm := makeBrokerArmFrame(token)
	armErr := c.runBrokerGateOK(ctx, id, "arm", arm)
	zeroBytes(arm)
	if armErr != nil {
		return handle, c.failBrokerOperation(ctx, record, armErr)
	}
	if _, err := c.inspectBrokerHeld(ctx, record); err != nil {
		return handle, c.failBrokerOperation(ctx, record, err)
	}

	c.mu.Lock()
	if record.destroyed || !record.busy || record.phase != brokerPhaseStarting {
		record.destroyed = true
		record.busy = false
		zeroToken(&record.token)
		c.mu.Unlock()
		c.removeFailedBroker(ctx, record)
		return handle, errors.New("hostruntime: broker creation state lost")
	}
	record.phase = brokerPhaseHeld
	record.busy = false
	c.mu.Unlock()
	return handle, nil
}

func (c *DockerCLI) validateBrokerSpec(spec BrokerSpec) error {
	if !spec.Adapter.validFor(c.issuer) {
		return errors.New("hostruntime: broker adapter handle invalid")
	}
	if err := validateContainerName(spec.Name); err != nil {
		return err
	}
	if err := validateContainerName(spec.Name + "-policy"); err != nil {
		return errors.New("hostruntime: policy helper name invalid")
	}
	if err := validateContainerName(c.cfg.BrokerNetwork); err != nil {
		return errors.New("hostruntime: broker network invalid")
	}
	if err := validateImageRef(spec.Image); err != nil {
		return err
	}
	if err := validateImageRef(spec.HelperImage); err != nil {
		return errors.New("hostruntime: helper image invalid")
	}
	if !isLowerHex64(spec.BuildID) ||
		spec.BuildID != spec.Adapter.buildID {
		return errors.New("hostruntime: broker build does not match adapter")
	}
	if spec.FleetGeneration == 0 ||
		spec.FleetGeneration != spec.Adapter.fleetGeneration {
		return errors.New("hostruntime: broker generation does not match adapter")
	}
	if spec.SlotIdentity == "" || spec.SlotIdentity != spec.Adapter.slotIdentity {
		return errors.New("hostruntime: broker slot does not match adapter")
	}
	if spec.CapacitySlotID == 0 || spec.JobGeneration == 0 {
		return errors.New("hostruntime: broker slot generation required")
	}
	if spec.PolicyIPv6Posture != PolicyIPv6DenyViaIP6Tables &&
		spec.PolicyIPv6Posture != PolicyIPv6KernelDisabled {
		return errors.New("hostruntime: broker ipv6 posture invalid")
	}
	uid, _, err := parseUser(spec.User)
	if err != nil || uid == 0 {
		return errors.New("hostruntime: broker requires a non-root user")
	}
	c.mu.Lock()
	adapter := c.adapters[spec.Adapter.nonce]
	c.mu.Unlock()
	if adapter == nil || adapter.destroyed ||
		adapter.handle.id != spec.Adapter.id ||
		adapter.spec.User != spec.User ||
		adapter.spec.BrokerParent != spec.RelayParent {
		return errors.New("hostruntime: broker adapter binding invalid")
	}
	if err := validateDescendant(c.cfg.BrokerRoot, spec.RelayParent, "relay parent"); err != nil {
		return err
	}
	if err := validateDescendant(c.cfg.BrokerRoot, spec.AuthorityParent, "authority parent"); err != nil {
		return err
	}
	if spec.RelayParent == spec.AuthorityParent ||
		strings.Contains(spec.RelayParent, ",") ||
		strings.Contains(spec.AuthorityParent, ",") {
		return errors.New("hostruntime: broker mount parent invalid")
	}
	if err := validateDirectPrivateDirectory(c.cfg.BrokerRoot, spec.RelayParent); err != nil {
		return err
	}
	if err := validateDirectPrivateDirectory(c.cfg.BrokerRoot, spec.AuthorityParent); err != nil {
		return err
	}
	if err := validateDescendant(c.cfg.SeccompRoot, spec.Seccomp.Path, "seccomp path"); err != nil {
		return err
	}
	if err := validateBrokerLimits(spec.Limits); err != nil {
		return err
	}
	return validateOneShotLimits(spec.HelperLimits)
}

func (c *DockerCLI) reserveBrokerRecordSlot(
	spec BrokerSpec,
	nonce [32]byte,
) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !nonzero32(nonce) ||
		len(c.brokers)+len(c.brokerReservations) >= maxBrokerRecords {
		return errors.New("hostruntime: broker record capacity exhausted")
	}
	for _, record := range c.brokers {
		if record != nil && !record.directoriesGone &&
			(record.spec.Name == spec.Name ||
				record.spec.RelayParent == spec.RelayParent ||
				record.spec.AuthorityParent == spec.AuthorityParent) {
			return errors.New("hostruntime: broker identity already reserved")
		}
	}
	for _, reservation := range c.brokerReservations {
		if reservation.name == spec.Name ||
			reservation.relayParent == spec.RelayParent ||
			reservation.authorityParent == spec.AuthorityParent {
			return errors.New("hostruntime: broker identity already reserved")
		}
	}
	c.brokerReservations[nonce] = brokerReservation{
		name:            spec.Name,
		relayParent:     spec.RelayParent,
		authorityParent: spec.AuthorityParent,
	}
	return nil
}

func (c *DockerCLI) releaseBrokerReservation(nonce [32]byte) {
	c.mu.Lock()
	delete(c.brokerReservations, nonce)
	c.mu.Unlock()
}

func (c *DockerCLI) brokerCreateArgv(spec BrokerSpec) []string {
	uid, gid, _ := parseUser(spec.User)
	argv := []string{
		c.cfg.DockerPath, "create",
		"--name", spec.Name,
		"--network", c.cfg.BrokerNetwork,
	}
	if spec.PolicyIPv6Posture == PolicyIPv6KernelDisabled {
		argv = append(
			argv,
			"--sysctl", "net.ipv6.conf.all.disable_ipv6=1",
			"--sysctl", "net.ipv6.conf.default.disable_ipv6=1",
		)
	}
	return append(argv,
		"--cap-drop", "ALL",
		"--read-only",
		"--security-opt", "no-new-privileges=true",
		"--security-opt", "seccomp="+spec.Seccomp.Path,
		"--restart", "no",
		"--user", spec.User,
		"--cpus", formatMilliCPU(spec.Limits.MilliCPU),
		"--memory", strconv.FormatUint(spec.Limits.MemoryBytes, 10),
		"--memory-swap", strconv.FormatUint(spec.Limits.MemorySwapBytes, 10),
		"--pids-limit", strconv.FormatUint(spec.Limits.PIDs, 10),
		"--ulimit", fmt.Sprintf("nofile=%d:%d", spec.Limits.FileDescriptors, spec.Limits.FileDescriptors),
		"--tmpfs", fmt.Sprintf("/run/portable-ghar/state:rw,noexec,nosuid,nodev,size=%d,uid=%d,gid=%d,mode=0700", spec.Limits.StateBytes, uid, gid),
		"--tmpfs", fmt.Sprintf("/tmp:rw,noexec,nosuid,nodev,size=%d,uid=%d,gid=%d,mode=0700", spec.Limits.ScratchBytes, uid, gid),
		"--log-driver", "local",
		"--log-opt", fmt.Sprintf("max-size=%db", spec.Limits.LogBytes),
		"--log-opt", fmt.Sprintf("max-file=%d", spec.Limits.LogFiles),
		"--mount", "type=bind,src="+spec.RelayParent+",dst="+brokerRelayMountDst,
		"--mount", "type=bind,src="+spec.AuthorityParent+",dst="+brokerAuthorityMountDst+",readonly",
		"--label", "io.portable-ghar.managed=true",
		"--label", "io.portable-ghar.kind=network-broker",
		"--label", "io.portable-ghar.build-id="+spec.BuildID,
		"--label", "io.portable-ghar.fleet-generation="+strconv.FormatUint(spec.FleetGeneration, 10),
		"--label", "io.portable-ghar.slot="+spec.SlotIdentity,
		"--entrypoint", brokerEntrypoint,
		spec.Image,
		"hold",
	)
}

func (c *DockerCLI) brokerCreateIdentity(spec BrokerSpec) rejectedCreateIdentity {
	return rejectedCreateIdentity{
		Name:            spec.Name,
		Kind:            "network-broker",
		Image:           spec.Image,
		BuildID:         spec.BuildID,
		FleetGeneration: spec.FleetGeneration,
		SlotIdentity:    spec.SlotIdentity,
		Entrypoint:      []string{brokerEntrypoint},
		Cmd:             []string{"hold"},
		NetworkMode:     c.cfg.BrokerNetwork,
	}
}

func brokerSysctls(posture PolicyIPv6Posture) map[string]string {
	if posture != PolicyIPv6KernelDisabled {
		return map[string]string{}
	}
	return map[string]string{
		"net.ipv6.conf.all.disable_ipv6":     "1",
		"net.ipv6.conf.default.disable_ipv6": "1",
	}
}

func brokerTmpfs(spec BrokerSpec) map[string]string {
	uid, gid, _ := parseUser(spec.User)
	return map[string]string{
		"/run/portable-ghar/state": "rw,noexec,nosuid,nodev,size=" + strconv.FormatUint(spec.Limits.StateBytes, 10) + ",uid=" + strconv.FormatUint(uid, 10) + ",gid=" + strconv.FormatUint(gid, 10) + ",mode=0700",
		"/tmp":                     "rw,noexec,nosuid,nodev,size=" + strconv.FormatUint(spec.Limits.ScratchBytes, 10) + ",uid=" + strconv.FormatUint(uid, 10) + ",gid=" + strconv.FormatUint(gid, 10) + ",mode=0700",
	}
}

func validateBrokerLimits(limits BrokerLimits) error {
	if limits.MilliCPU == 0 || limits.MemoryBytes == 0 || limits.PIDs == 0 ||
		limits.FileDescriptors == 0 || limits.StateBytes == 0 ||
		limits.ScratchBytes == 0 || limits.LogBytes == 0 || limits.LogFiles == 0 {
		return errors.New("hostruntime: broker limits must all be nonzero")
	}
	if limits.MilliCPU > maxDockerMilliCPU ||
		limits.MemoryBytes > math.MaxInt64 ||
		limits.MemorySwapBytes < limits.MemoryBytes ||
		limits.MemorySwapBytes > math.MaxInt64 ||
		limits.PIDs > math.MaxInt64 ||
		limits.FileDescriptors > math.MaxInt64 {
		return errors.New("hostruntime: broker limit exceeds docker range")
	}
	total, ok := checkedAdd(limits.StateBytes, limits.ScratchBytes)
	if !ok || total > limits.MemoryBytes {
		return errors.New("hostruntime: broker tmpfs exceeds memory")
	}
	return nil
}

func validateOneShotLimits(limits OneShotLimits) error {
	if limits.MilliCPU == 0 || limits.MemoryBytes == 0 || limits.PIDs == 0 ||
		limits.FileDescriptors == 0 {
		return errors.New("hostruntime: helper limits must all be nonzero")
	}
	if limits.MilliCPU > maxDockerMilliCPU ||
		limits.MemoryBytes > math.MaxInt64 ||
		limits.MemorySwapBytes < limits.MemoryBytes ||
		limits.MemorySwapBytes > math.MaxInt64 ||
		limits.PIDs > math.MaxInt64 ||
		limits.FileDescriptors > math.MaxInt64 ||
		limits.MemoryBytes < helperRunTmpfsBytes {
		return errors.New("hostruntime: helper limit exceeds docker range")
	}
	return nil
}

func validateDirectPrivateDirectory(root, path string) error {
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return errors.New("hostruntime: broker directory root unavailable")
	}
	resolved, err := filepath.EvalSymlinks(path)
	relative, relativeErr := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	if err != nil || relativeErr != nil || relative == "." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) ||
		relative == ".." ||
		resolved != filepath.Join(resolvedRoot, relative) {
		return errors.New("hostruntime: broker directory unavailable or indirect")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return errors.New("hostruntime: broker directory identity invalid")
	}
	return nil
}

func makeBrokerArmFrame(token [releaseTokenBytes]byte) []byte {
	digest := sha256.Sum256(token[:])
	frame := make([]byte, brokerArmFrameBytes)
	copy(frame[:8], "PGHBRARM")
	frame[8] = 1
	frame[9] = 1
	binary.BigEndian.PutUint16(frame[10:12], releaseTokenBytes)
	copy(frame[12:], digest[:])
	return frame
}

func (c *DockerCLI) runBrokerGateOK(
	ctx context.Context,
	id, operation string,
	payload []byte,
) error {
	argv := []string{c.cfg.DockerPath, "exec"}
	if payload != nil {
		argv = append(argv, "-i")
	}
	argv = append(argv, id, brokerEntrypoint, operation)
	var input io.Reader
	if payload != nil {
		input = bytes.NewReader(payload)
	}
	result, err := c.runner.Run(ctx, argv, nil, input)
	if err != nil || result.ExitCode != 0 || result.Signaled ||
		result.StdoutTruncated || result.StderrTruncated ||
		!bytes.Equal(result.Stdout, []byte("OK\n")) ||
		len(result.Stderr) != 0 {
		return errors.New("hostruntime: broker gate operation failed")
	}
	return nil
}

func (c *DockerCLI) failBrokerOperation(
	ctx context.Context,
	record *brokerRecord,
	failure error,
) error {
	c.mu.Lock()
	record.destroyed = true
	record.busy = false
	zeroToken(&record.token)
	zeroBytes(record.policyRuntime)
	record.policyRuntime = nil
	c.mu.Unlock()
	c.removeFailedBroker(ctx, record)
	return failure
}
