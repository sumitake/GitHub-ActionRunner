package hostruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
)

const (
	maxPolicyResultBytes = 4096
	brokerReleasePrefix  = 83
)

type policyApplicationWire struct {
	Version     uint8  `json:"version"`
	Digest      string `json:"policy_digest"`
	IPv6Posture string `json:"ipv6_posture"`
}

// ApplyNetworkPolicy runs the only NET_ADMIN process in the broker namespace.
// The helper is ephemeral, receives one canonical artifact over stdin, performs
// its own restore/readback, and must be positively absent before the broker can
// advance.
func (c *DockerCLI) ApplyNetworkPolicy(
	ctx context.Context,
	handle BrokerHandle,
	artifact PolicyArtifact,
) error {
	record, err := c.beginMutatingBrokerPhase(ctx, handle, brokerPhaseHeld)
	if err != nil {
		return err
	}
	if !artifact.valid() {
		return c.failBrokerOperation(ctx, record, errors.New("hostruntime: policy artifact invalid"))
	}
	payload, err := encodePolicyArtifact(artifact)
	if err != nil {
		return c.failBrokerOperation(ctx, record, err)
	}
	result, runErr := c.runner.Run(
		ctx,
		c.policyHelperArgv(record),
		nil,
		bytes.NewReader(payload),
	)
	zeroBytes(payload)
	if runErr != nil || result.ExitCode != 0 || result.Signaled ||
		result.StdoutTruncated || result.StderrTruncated ||
		len(result.Stderr) != 0 {
		return c.failBrokerOperation(ctx, record, errors.New("hostruntime: policy helper failed"))
	}
	applied, err := parsePolicyApplication(result.Stdout)
	if err != nil ||
		applied.Digest != artifact.Digest() ||
		applied.IPv6Posture != policyPostureName(artifact.posture) {
		return c.failBrokerOperation(ctx, record, errors.New("hostruntime: policy helper readback invalid"))
	}
	if err := c.provePolicyHelperGone(ctx, record); err != nil {
		return c.failBrokerOperation(ctx, record, err)
	}
	if _, err := c.inspectBrokerHeld(ctx, record); err != nil {
		return c.failBrokerOperation(ctx, record, err)
	}

	c.mu.Lock()
	if record.destroyed || !record.busy || record.phase != brokerPhaseHeld {
		record.destroyed = true
		record.busy = false
		zeroToken(&record.token)
		c.mu.Unlock()
		c.removeFailedBroker(ctx, record)
		return errors.New("hostruntime: policy application state lost")
	}
	record.policyDigest = artifact.digest
	record.policyPosture = artifact.posture
	record.policyRuntime = artifact.RuntimePolicy()
	record.phase = brokerPhasePolicyApplied
	record.busy = false
	c.mu.Unlock()
	return nil
}

func (c *DockerCLI) policyHelperArgv(record *brokerRecord) []string {
	spec := record.spec
	helperName := spec.Name + "-policy"
	return []string{
		c.cfg.DockerPath, "run", "--rm",
		"--name", helperName,
		"--network", "container:" + record.handle.id,
		"--cap-drop", "ALL",
		"--cap-add", "NET_ADMIN",
		"--read-only",
		"--security-opt", "no-new-privileges=true",
		"--security-opt", "seccomp=" + spec.Seccomp.Path,
		"--user", "0:0",
		"--cpus", formatMilliCPU(spec.HelperLimits.MilliCPU),
		"--memory", strconv.FormatUint(spec.HelperLimits.MemoryBytes, 10),
		"--pids-limit", strconv.FormatUint(spec.HelperLimits.PIDs, 10),
		"--ulimit", fmt.Sprintf(
			"nofile=%d:%d",
			spec.HelperLimits.FileDescriptors,
			spec.HelperLimits.FileDescriptors,
		),
		"--tmpfs", "/run:rw,noexec,nosuid,nodev,size=65536,uid=0,gid=0,mode=0700",
		"--log-driver", "none",
		"--env", "XTABLES_LOCKFILE=/run/xtables.lock",
		"--label", "io.portable-ghar.managed=true",
		"--label", "io.portable-ghar.kind=network-policy-helper",
		"--label", "io.portable-ghar.build-id=" + spec.BuildID,
		"--label", "io.portable-ghar.fleet-generation=" + strconv.FormatUint(spec.FleetGeneration, 10),
		"--label", "io.portable-ghar.slot=" + spec.SlotIdentity,
		"--entrypoint", helperEntrypoint,
		spec.HelperImage,
		"apply",
	}
}

func (c *DockerCLI) provePolicyHelperGone(
	ctx context.Context,
	record *brokerRecord,
) error {
	name := record.spec.Name + "-policy"
	result, err := c.runner.Run(
		ctx,
		[]string{
			c.cfg.DockerPath, "ps", "-a",
			"--filter", "name=^/" + name + "$",
			"--format", "{{.ID}}",
		},
		nil,
		nil,
	)
	if err != nil || result.ExitCode != 0 || result.Signaled ||
		result.StdoutTruncated || result.StderrTruncated ||
		len(result.Stdout) != 0 || len(result.Stderr) != 0 {
		return errors.New("hostruntime: policy helper absence unproven")
	}
	return nil
}

func parsePolicyApplication(data []byte) (policyApplicationWire, error) {
	if len(data) == 0 || len(data) > maxPolicyResultBytes {
		return policyApplicationWire{}, errors.New("hostruntime: policy application proof invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var wire policyApplicationWire
	if err := decoder.Decode(&wire); err != nil ||
		decoder.Decode(&struct{}{}) != io.EOF ||
		wire.Version != 1 || !isLowerHex64(wire.Digest) ||
		!validPolicyPostureName(wire.IPv6Posture) {
		return policyApplicationWire{}, errors.New("hostruntime: policy application proof invalid")
	}
	canonical, _ := json.Marshal(wire)
	canonical = append(canonical, '\n')
	if !bytes.Equal(canonical, data) {
		return policyApplicationWire{}, errors.New("hostruntime: policy application proof noncanonical")
	}
	return wire, nil
}

func policyPostureName(posture PolicyIPv6Posture) string {
	switch posture {
	case PolicyIPv6DenyViaIP6Tables:
		return "deny-via-ip6tables"
	case PolicyIPv6KernelDisabled:
		return "kernel-disabled"
	default:
		return ""
	}
}

// BindDialAuthority proves the exact read-only directory/socket identity from
// inside the still-held broker. It does not connect to or consume the authority
// socket; peer identity is proven after the one release.
func (c *DockerCLI) BindDialAuthority(
	ctx context.Context,
	handle BrokerHandle,
	proof AuthorityProof,
) error {
	record, err := c.beginMutatingBrokerPhase(
		ctx,
		handle,
		brokerPhasePolicyApplied,
	)
	if err != nil {
		return err
	}
	if err := validateAuthorityForBroker(proof, record.spec); err != nil {
		return c.failBrokerOperation(ctx, record, err)
	}
	result, runErr := c.runner.Run(
		ctx,
		[]string{
			c.cfg.DockerPath, "exec", record.handle.id,
			brokerEntrypoint, "authority-id",
		},
		nil,
		nil,
	)
	if runErr != nil || result.ExitCode != 0 || result.Signaled ||
		result.StdoutTruncated || result.StderrTruncated ||
		len(result.Stderr) != 0 {
		return c.failBrokerOperation(ctx, record, errors.New("hostruntime: authority inspection failed"))
	}
	filesystem, err := parseAuthorityFilesystem(result.Stdout)
	if err != nil ||
		filesystem.Directory != proof.binding.Directory ||
		filesystem.Socket != proof.binding.Socket {
		return c.failBrokerOperation(ctx, record, errors.New("hostruntime: authority identity mismatch"))
	}
	if _, err := c.inspectBrokerHeld(ctx, record); err != nil {
		return c.failBrokerOperation(ctx, record, err)
	}

	c.mu.Lock()
	if record.destroyed || !record.busy ||
		record.phase != brokerPhasePolicyApplied {
		record.destroyed = true
		record.busy = false
		zeroToken(&record.token)
		c.mu.Unlock()
		c.removeFailedBroker(ctx, record)
		return errors.New("hostruntime: authority binding state lost")
	}
	record.authority = proof
	record.phase = brokerPhaseAuthorityBound
	record.busy = false
	c.mu.Unlock()
	return nil
}

func validateAuthorityForBroker(proof AuthorityProof, spec BrokerSpec) error {
	if err := validateAuthorityBinding(proof.binding); err != nil {
		return err
	}
	uid, gid, err := parseUser(spec.User)
	if err != nil ||
		proof.binding.CapacitySlotID != spec.CapacitySlotID ||
		proof.binding.JobGeneration != spec.JobGeneration ||
		proof.binding.Directory.UID != uint32(uid) ||
		proof.binding.Directory.GID != uint32(gid) {
		return errors.New("hostruntime: authority owner does not match broker")
	}
	return nil
}

// ReleaseNetworkBroker consumes the release token once, validates the parser's
// TSYNC/filter/readiness proof, and returns only an adapter-bound peer proof.
func (c *DockerCLI) ReleaseNetworkBroker(
	ctx context.Context,
	handle BrokerHandle,
) (BrokerPeerProof, error) {
	record, err := c.beginMutatingBrokerPhase(
		ctx,
		handle,
		brokerPhaseAuthorityBound,
	)
	if err != nil {
		return BrokerPeerProof{}, err
	}
	record.releaseAttempted = true
	document, err := c.inspectBrokerHeld(ctx, record)
	if err != nil {
		return BrokerPeerProof{}, c.failBrokerOperation(ctx, record, err)
	}
	if document.State.Pid > math.MaxUint32 {
		return BrokerPeerProof{}, c.failBrokerOperation(
			ctx,
			record,
			errors.New("hostruntime: broker namespace owner unrepresentable"),
		)
	}
	payload, err := encodeBrokerRelease(record)
	if err != nil {
		return BrokerPeerProof{}, c.failBrokerOperation(ctx, record, err)
	}
	result, runErr := c.runner.Run(
		ctx,
		[]string{
			c.cfg.DockerPath, "exec", "-i", record.handle.id,
			brokerEntrypoint, "release",
		},
		nil,
		bytes.NewReader(payload),
	)
	zeroBytes(payload)
	if runErr != nil || result.ExitCode != 0 || result.Signaled ||
		result.StdoutTruncated || result.StderrTruncated ||
		len(result.Stderr) != 0 {
		return BrokerPeerProof{}, c.failBrokerOperation(ctx, record, errors.New("hostruntime: broker release failed"))
	}
	readiness, err := parseBrokerReadiness(result.Stdout)
	if err != nil ||
		validateReadinessForRecord(readiness, record, uint32(document.State.Pid)) != nil {
		return BrokerPeerProof{}, c.failBrokerOperation(ctx, record, errors.New("hostruntime: broker release proof invalid"))
	}
	record.readiness = readiness
	if _, err := c.auditReleasedBrokerRecord(ctx, record); err != nil {
		return BrokerPeerProof{}, c.failBrokerOperation(ctx, record, err)
	}

	adapter := record.spec.Adapter
	peer := newBrokerPeerProof(
		adapter,
		c.issuer,
		record.handle.fleetGeneration,
		brokerDirectoryIdentity{
			Device: readiness.RelayDirectory.Device,
			Inode:  readiness.RelayDirectory.Inode,
			UID:    readiness.RelayDirectory.UID,
			GID:    readiness.RelayDirectory.GID,
			Mode:   readiness.RelayDirectory.Mode,
		},
		brokerSocketIdentity{
			Name:   readiness.RelaySocket.Name,
			Device: readiness.RelaySocket.Device,
			Inode:  readiness.RelaySocket.Inode,
			UID:    readiness.RelaySocket.UID,
			GID:    readiness.RelaySocket.GID,
			Mode:   readiness.RelaySocket.Mode,
		},
		brokerProcessIdentity{
			PID:       readiness.Parser.PID,
			StartTime: readiness.Parser.StartTime,
		},
	)
	c.mu.Lock()
	if record.destroyed || !record.busy ||
		record.phase != brokerPhaseAuthorityBound ||
		!record.releaseAttempted {
		record.destroyed = true
		record.busy = false
		zeroToken(&record.token)
		c.mu.Unlock()
		c.removeFailedBroker(ctx, record)
		return BrokerPeerProof{}, errors.New("hostruntime: broker release state lost")
	}
	record.peer = peer
	record.phase = brokerPhaseReleased
	record.busy = false
	zeroToken(&record.token)
	zeroBytes(record.policyRuntime)
	record.policyRuntime = nil
	c.mu.Unlock()
	return peer, nil
}

func encodeBrokerRelease(record *brokerRecord) ([]byte, error) {
	authority, err := encodeAuthorityBinding(record.authority.binding)
	if err != nil || len(authority) > maxAuthorityProofBytes ||
		validateRuntimePolicy(record.policyRuntime) != nil {
		return nil, errors.New("hostruntime: broker release authority invalid")
	}
	frame := make(
		[]byte,
		brokerReleasePrefix+releaseTokenBytes+
			len(record.policyRuntime)+len(authority),
	)
	copy(frame[:8], "PGHBRREL")
	frame[8] = 1
	binary.BigEndian.PutUint16(frame[9:11], releaseTokenBytes)
	copy(frame[11:43], record.policyDigest[:])
	binary.BigEndian.PutUint32(frame[43:47], uint32(len(authority)))
	binary.BigEndian.PutUint32(frame[47:51], uint32(len(record.policyRuntime)))
	runtimeDigest := sha256.Sum256(record.policyRuntime)
	copy(frame[51:83], runtimeDigest[:])
	copy(
		frame[brokerReleasePrefix:brokerReleasePrefix+releaseTokenBytes],
		record.token[:],
	)
	runtimeOffset := brokerReleasePrefix + releaseTokenBytes
	copy(frame[runtimeOffset:runtimeOffset+len(record.policyRuntime)], record.policyRuntime)
	copy(frame[runtimeOffset+len(record.policyRuntime):], authority)
	zeroBytes(authority)
	return frame, nil
}

func validateReadinessForRecord(
	wire brokerReadinessWire,
	record *brokerRecord,
	ownerPID uint32,
) error {
	uid, gid, err := parseUser(record.spec.User)
	if err != nil ||
		wire.NamespaceOwner.PID != ownerPID ||
		wire.PolicyDigest != hex.EncodeToString(record.policyDigest[:]) ||
		wire.PolicyIPv6Posture != policyPostureName(record.policyPosture) ||
		wire.RelayDirectory.UID != uint32(uid) ||
		wire.RelayDirectory.GID != uint32(gid) ||
		wire.AuthorityDirectory != record.authority.binding.Directory ||
		wire.AuthoritySocket != record.authority.binding.Socket ||
		wire.AuthorityPeer != record.authority.binding.Peer {
		return errors.New("hostruntime: broker readiness binding mismatch")
	}
	return nil
}

func (c *DockerCLI) beginMutatingBrokerPhase(
	ctx context.Context,
	handle BrokerHandle,
	phase brokerPhase,
) (*brokerRecord, error) {
	if c == nil || !handle.validFor(c.issuer) {
		return nil, errors.New("hostruntime: broker handle invalid")
	}
	c.mu.Lock()
	record := c.brokers[handle.nonce]
	if record == nil || record.destroyed || record.handle.id != handle.id {
		c.mu.Unlock()
		return nil, errors.New("hostruntime: broker record unavailable")
	}
	if record.busy || record.phase != phase {
		record.destroyed = true
		record.busy = false
		zeroToken(&record.token)
		c.mu.Unlock()
		c.removeFailedBroker(ctx, record)
		return nil, errors.New("hostruntime: broker operation order invalid")
	}
	record.busy = true
	c.mu.Unlock()
	return record, nil
}
