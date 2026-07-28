package hostruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
)

const (
	maxBrokerReadinessBytes = 16 << 10
	parserControlFD         = 3
	parserFilterVersion     = 1
	parserSocketErrno       = 1
)

type brokerReadinessWire struct {
	Version             uint8                 `json:"version"`
	ReleaseGeneration   uint64                `json:"release_generation"`
	PolicyDigest        string                `json:"policy_digest"`
	PolicyIPv6Posture   string                `json:"policy_ipv6_posture"`
	NamespaceOwner      ProcessIdentity       `json:"namespace_owner"`
	Parser              childProcessIdentity  `json:"parser"`
	RelayDirectory      DirectoryIdentity     `json:"relay_directory"`
	RelaySocket         SocketIdentity        `json:"relay_socket"`
	Control             controlSocketIdentity `json:"control"`
	AuthorityDirectory  DirectoryIdentity     `json:"authority_directory"`
	AuthoritySocket     SocketIdentity        `json:"authority_socket"`
	AuthorityPeer       ProcessIdentity       `json:"authority_peer"`
	ParserControlFD     uint32                `json:"parser_control_fd"`
	FilterVersion       uint32                `json:"filter_version"`
	FilterTSYNC         bool                  `json:"filter_tsync"`
	AFINETErrno         uint32                `json:"af_inet_errno"`
	AFINET6Errno        uint32                `json:"af_inet6_errno"`
	UnexpectedFDs       uint32                `json:"unexpected_fds"`
	ParserTaskCount     uint32                `json:"parser_task_count"`
	ParserTasksVerified uint32                `json:"parser_tasks_verified"`
}

type childProcessIdentity struct {
	PID       uint32 `json:"pid"`
	PPID      uint32 `json:"ppid"`
	StartTime uint64 `json:"start_time"`
}

type controlSocketIdentity struct {
	Device      uint64 `json:"device"`
	DialerInode uint64 `json:"dialer_inode"`
	ParserInode uint64 `json:"parser_inode"`
}

func (c *DockerCLI) inspectBrokerHeld(
	ctx context.Context,
	record *brokerRecord,
) (adapterInspect, error) {
	document, raw, err := c.inspectBrokerContainer(ctx, record)
	zeroBytes(raw)
	if err != nil {
		return adapterInspect{}, err
	}
	top, err := c.runner.Run(
		ctx,
		[]string{c.cfg.DockerPath, "top", record.handle.id, "-eo", "pid=,ppid=,args="},
		nil,
		nil,
	)
	if err != nil || top.ExitCode != 0 || top.Signaled ||
		top.StdoutTruncated || top.StderrTruncated ||
		len(top.Stderr) != 0 ||
		!validHeldBrokerInventory(top.Stdout, document.State.Pid) {
		return adapterInspect{}, errors.New("hostruntime: held broker process inventory invalid")
	}
	return document, nil
}

func (c *DockerCLI) inspectBrokerContainer(
	ctx context.Context,
	record *brokerRecord,
) (adapterInspect, []byte, error) {
	if record == nil {
		return adapterInspect{}, nil, errors.New("hostruntime: broker record unavailable")
	}
	result, err := c.runner.Run(
		ctx,
		[]string{c.cfg.DockerPath, "inspect", "--type", "container", record.handle.id},
		nil,
		nil,
	)
	if err != nil || result.ExitCode != 0 || result.Signaled ||
		result.StdoutTruncated || result.StderrTruncated ||
		len(result.Stderr) != 0 {
		return adapterInspect{}, nil, errors.New("hostruntime: broker inspection failed")
	}
	var documents []adapterInspect
	if err := json.Unmarshal(result.Stdout, &documents); err != nil ||
		len(documents) != 1 {
		return adapterInspect{}, nil, errors.New("hostruntime: broker inspection document invalid")
	}
	if err := validateBrokerInspect(documents[0], record, c.cfg.BrokerNetwork); err != nil {
		return adapterInspect{}, nil, err
	}
	return documents[0], result.Stdout, nil
}

func validateBrokerInspect(
	document adapterInspect,
	record *brokerRecord,
	network string,
) error {
	spec := record.spec
	labels := document.Config.Labels
	if document.ID != record.handle.id ||
		document.Config.Image != spec.Image ||
		len(labels) != 5 ||
		labels["io.portable-ghar.managed"] != "true" ||
		labels["io.portable-ghar.kind"] != "network-broker" ||
		labels["io.portable-ghar.build-id"] != spec.BuildID ||
		labels["io.portable-ghar.fleet-generation"] != strconv.FormatUint(spec.FleetGeneration, 10) ||
		labels["io.portable-ghar.slot"] != spec.SlotIdentity ||
		!equalStrings(document.Config.Entrypoint, []string{brokerEntrypoint}) ||
		!equalStrings(document.Config.Cmd, []string{"hold"}) ||
		document.Config.User != spec.User ||
		len(document.Config.Env) != 0 ||
		!document.State.Running || document.State.Restarting ||
		document.State.Dead || document.State.Pid <= 0 ||
		document.State.ExitCode != 0 {
		return errors.New("hostruntime: broker identity or state drifted")
	}
	host := document.HostConfig
	if host.NetworkMode != network || !host.ReadonlyRootfs ||
		!equalStrings(host.CapDrop, []string{"ALL"}) ||
		len(host.CapAdd) != 0 ||
		!equalStrings(host.SecurityOpt, []string{
			"no-new-privileges=true",
			"seccomp=" + spec.Seccomp.Path,
		}) ||
		len(host.Binds) != 0 || len(host.Devices) != 0 ||
		host.Privileged || len(host.PortBindings) != 0 ||
		host.PublishAllPorts || host.PidMode != "" ||
		host.IpcMode != "" || host.UTSMode != "" ||
		!equalStringMap(host.Tmpfs, brokerTmpfs(spec)) ||
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
		len(document.Mounts) != 2 {
		return errors.New("hostruntime: broker isolation or resource configuration drifted")
	}
	if !validBrokerMounts(document, spec) {
		return errors.New("hostruntime: broker mount identity drifted")
	}
	return nil
}

func validBrokerMounts(document adapterInspect, spec BrokerSpec) bool {
	relayFound := false
	authorityFound := false
	for _, mount := range document.Mounts {
		if mount.Type != "bind" ||
			(mount.Propagation != "" && mount.Propagation != "rprivate") {
			return false
		}
		switch mount.Destination {
		case brokerRelayMountDst:
			if relayFound || mount.Source != spec.RelayParent || !mount.RW ||
				(mount.Mode != "" && mount.Mode != "rw") {
				return false
			}
			relayFound = true
		case brokerAuthorityMountDst:
			if authorityFound || mount.Source != spec.AuthorityParent || mount.RW ||
				(mount.Mode != "" && mount.Mode != "ro") {
				return false
			}
			authorityFound = true
		default:
			return false
		}
	}
	return relayFound && authorityFound
}

func validHeldBrokerInventory(data []byte, wantPID int64) bool {
	lines, ok := strictProcessLines(data, 1)
	if !ok {
		return false
	}
	fields := strings.Fields(lines[0])
	if len(fields) != 4 {
		return false
	}
	pid, err := strconv.ParseInt(fields[0], 10, 64)
	ppid, ppidErr := strconv.ParseUint(fields[1], 10, 64)
	return err == nil && ppidErr == nil && ppid != 0 &&
		strconv.FormatInt(pid, 10) == fields[0] &&
		strconv.FormatUint(ppid, 10) == fields[1] &&
		pid == wantPID &&
		fields[2] == brokerEntrypoint &&
		fields[3] == "hold"
}

func validReleasedBrokerInventory(
	data []byte,
	owner ProcessIdentity,
	parser childProcessIdentity,
) bool {
	lines, ok := strictProcessLines(data, 2)
	if !ok {
		return false
	}
	seenOwner := false
	seenParser := false
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 4 {
			return false
		}
		pid, err := strconv.ParseUint(fields[0], 10, 32)
		ppid, ppidErr := strconv.ParseUint(fields[1], 10, 32)
		if err != nil || ppidErr != nil ||
			strconv.FormatUint(pid, 10) != fields[0] ||
			strconv.FormatUint(ppid, 10) != fields[1] {
			return false
		}
		switch {
		case uint32(pid) == owner.PID:
			if seenOwner || ppid == 0 ||
				fields[2] != brokerEntrypoint || fields[3] != "hold" {
				return false
			}
			seenOwner = true
		case uint32(pid) == parser.PID:
			if seenParser || uint32(ppid) != owner.PID ||
				parser.PPID != owner.PID ||
				fields[2] != brokerParserEntrypoint || fields[3] != "serve" {
				return false
			}
			seenParser = true
		default:
			return false
		}
	}
	return seenOwner && seenParser
}

func strictProcessLines(data []byte, count int) ([]string, bool) {
	if len(data) == 0 || bytes.Contains(data, []byte("\r")) ||
		!bytes.HasSuffix(data, []byte("\n")) {
		return nil, false
	}
	lines := strings.Split(string(data[:len(data)-1]), "\n")
	return lines, len(lines) == count
}

func parseBrokerReadiness(data []byte) (brokerReadinessWire, error) {
	if len(data) == 0 || len(data) > maxBrokerReadinessBytes {
		return brokerReadinessWire{}, errors.New("hostruntime: broker readiness invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var wire brokerReadinessWire
	if err := decoder.Decode(&wire); err != nil ||
		decoder.Decode(&struct{}{}) != io.EOF {
		return brokerReadinessWire{}, errors.New("hostruntime: broker readiness invalid")
	}
	if err := validateBrokerReadiness(wire); err != nil {
		return brokerReadinessWire{}, err
	}
	canonical, err := encodeBrokerReadiness(wire)
	if err != nil || !bytes.Equal(canonical, data) {
		return brokerReadinessWire{}, errors.New("hostruntime: broker readiness noncanonical")
	}
	return wire, nil
}

func encodeBrokerReadiness(wire brokerReadinessWire) ([]byte, error) {
	if err := validateBrokerReadiness(wire); err != nil {
		return nil, err
	}
	document, err := json.Marshal(wire)
	if err != nil || len(document)+1 > maxBrokerReadinessBytes {
		return nil, errors.New("hostruntime: broker readiness encoding failed")
	}
	return append(document, '\n'), nil
}

func validateBrokerReadiness(wire brokerReadinessWire) error {
	if wire.Version != 1 || wire.ReleaseGeneration != 1 ||
		!isLowerHex64(wire.PolicyDigest) ||
		!validPolicyPostureName(wire.PolicyIPv6Posture) ||
		wire.NamespaceOwner.PID == 0 || wire.NamespaceOwner.StartTime == 0 ||
		wire.Parser.PID == 0 || wire.Parser.PID == wire.NamespaceOwner.PID ||
		wire.Parser.PPID != wire.NamespaceOwner.PID ||
		wire.Parser.StartTime == 0 ||
		wire.RelayDirectory.Device == 0 || wire.RelayDirectory.Inode == 0 ||
		wire.RelayDirectory.Mode != 0o700 ||
		wire.RelaySocket.Name != "https.sock" ||
		wire.RelaySocket.Device != wire.RelayDirectory.Device ||
		wire.RelaySocket.Inode == 0 ||
		wire.RelaySocket.UID != wire.RelayDirectory.UID ||
		wire.RelaySocket.GID != wire.RelayDirectory.GID ||
		wire.RelaySocket.Mode != 0o600 ||
		wire.Control.Device == 0 || wire.Control.DialerInode == 0 ||
		wire.Control.ParserInode == 0 ||
		wire.Control.DialerInode == wire.Control.ParserInode ||
		wire.AuthorityDirectory.Device == 0 ||
		wire.AuthorityDirectory.Inode == 0 ||
		wire.AuthorityDirectory.Mode != 0o700 ||
		wire.AuthoritySocket.Name != dialAuthoritySocketName ||
		wire.AuthoritySocket.Device != wire.AuthorityDirectory.Device ||
		wire.AuthoritySocket.Inode == 0 ||
		wire.AuthoritySocket.UID != wire.AuthorityDirectory.UID ||
		wire.AuthoritySocket.GID != wire.AuthorityDirectory.GID ||
		wire.AuthoritySocket.Mode != 0o600 ||
		wire.AuthorityPeer.PID == 0 || wire.AuthorityPeer.StartTime == 0 ||
		wire.ParserControlFD != parserControlFD ||
		wire.FilterVersion != parserFilterVersion || !wire.FilterTSYNC ||
		wire.AFINETErrno != parserSocketErrno ||
		wire.AFINET6Errno != parserSocketErrno ||
		wire.UnexpectedFDs != 0 ||
		wire.ParserTaskCount == 0 ||
		wire.ParserTasksVerified != wire.ParserTaskCount {
		return errors.New("hostruntime: broker readiness fields invalid")
	}
	return nil
}

func validPolicyPostureName(value string) bool {
	return value == "deny-via-ip6tables" || value == "kernel-disabled"
}

func (c *DockerCLI) auditReleasedBrokerRecord(
	ctx context.Context,
	record *brokerRecord,
) (BrokerAudit, error) {
	document, inspectRaw, err := c.inspectBrokerContainer(ctx, record)
	if err != nil {
		return BrokerAudit{}, err
	}
	if document.State.Pid != int64(record.readiness.NamespaceOwner.PID) {
		zeroBytes(inspectRaw)
		return BrokerAudit{}, errors.New("hostruntime: broker namespace owner changed")
	}
	result, err := c.runner.Run(
		ctx,
		[]string{c.cfg.DockerPath, "exec", record.handle.id, brokerEntrypoint, "audit"},
		nil,
		nil,
	)
	if err != nil || result.ExitCode != 0 || result.Signaled ||
		result.StdoutTruncated || result.StderrTruncated ||
		len(result.Stderr) != 0 {
		zeroBytes(inspectRaw)
		return BrokerAudit{}, errors.New("hostruntime: broker audit command failed")
	}
	readiness, err := parseBrokerReadiness(result.Stdout)
	if err != nil || readiness != record.readiness {
		zeroBytes(inspectRaw)
		return BrokerAudit{}, errors.New("hostruntime: broker readiness drifted")
	}
	top, err := c.runner.Run(
		ctx,
		[]string{c.cfg.DockerPath, "top", record.handle.id, "-eo", "pid=,ppid=,args="},
		nil,
		nil,
	)
	if err != nil || top.ExitCode != 0 || top.Signaled ||
		top.StdoutTruncated || top.StderrTruncated ||
		len(top.Stderr) != 0 ||
		!validReleasedBrokerInventory(
			top.Stdout,
			record.readiness.NamespaceOwner,
			record.readiness.Parser,
		) {
		zeroBytes(inspectRaw)
		return BrokerAudit{}, errors.New("hostruntime: released broker process inventory invalid")
	}
	input := make([]byte, 0, len(inspectRaw)+len(result.Stdout)+len(top.Stdout)+2)
	input = append(input, inspectRaw...)
	input = append(input, 0)
	input = append(input, result.Stdout...)
	input = append(input, 0)
	input = append(input, top.Stdout...)
	digest := sha256.Sum256(input)
	zeroBytes(input)
	zeroBytes(inspectRaw)
	return BrokerAudit{
		brokerNonce: record.handle.nonce,
		issuer:      c.issuer,
		generation:  record.handle.fleetGeneration,
		digest:      digest,
	}, nil
}

// AuditNetworkBroker is a repeatable read-only audit after the one release.
// Any mismatch is terminal and cleanup-first.
func (c *DockerCLI) AuditNetworkBroker(
	ctx context.Context,
	handle BrokerHandle,
) (BrokerAudit, error) {
	record, err := c.beginMutatingBrokerPhase(ctx, handle, brokerPhaseReleased)
	if err != nil {
		return BrokerAudit{}, err
	}
	audit, auditErr := c.auditReleasedBrokerRecord(ctx, record)
	c.mu.Lock()
	if auditErr == nil &&
		(record.destroyed || !record.busy || record.phase != brokerPhaseReleased) {
		auditErr = errors.New("hostruntime: broker audit state lost")
	}
	record.busy = false
	if auditErr != nil {
		record.destroyed = true
		zeroToken(&record.token)
	}
	c.mu.Unlock()
	if auditErr != nil {
		c.removeFailedBroker(ctx, record)
		return BrokerAudit{}, auditErr
	}
	return audit, nil
}
