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
	"strconv"

	"github.com/sumitake/portable-ghar/internal/linuxcap"
)

const (
	verifierEntrypoint     = "/usr/local/bin/portable-ghar-network-verifier"
	maxVerifierResultBytes = 16 << 10
)

type verifierNamespaceWire struct {
	Version      uint8         `json:"version"`
	Capabilities linuxcap.Wire `json:"capabilities"`
	Namespace    struct {
		Identity       NetworkNamespaceIdentity `json:"identity"`
		LoopbackOnly   bool                     `json:"loopback_only"`
		TablesEmpty    bool                     `json:"tables_empty"`
		ConntrackEmpty bool                     `json:"conntrack_empty"`
	} `json:"namespace"`
}

type verifierIdentityWire struct {
	Version      uint8                    `json:"version"`
	Capabilities linuxcap.Wire            `json:"capabilities"`
	Identity     NetworkNamespaceIdentity `json:"identity"`
}

type verifierProxyWire struct {
	Version              uint8                    `json:"version"`
	Capabilities         linuxcap.Wire            `json:"capabilities"`
	PolicyDigest         string                   `json:"policy_digest"`
	EgressBackend        string                   `json:"egress_backend"`
	RunnerNetNSID        NetworkNamespaceIdentity `json:"runner_netns_id"`
	RunnerLoopbackOnly   bool                     `json:"runner_loopback_only"`
	RunnerTablesEmpty    bool                     `json:"runner_tables_empty"`
	RunnerConntrackEmpty bool                     `json:"runner_conntrack_empty"`
	PositiveOK           bool                     `json:"positive_ok"`
	NegativeOK           bool                     `json:"negative_ok"`
}

type verifierFloodRequestWire struct {
	Version  uint8  `json:"version"`
	Attempts uint64 `json:"attempts"`
}

type verifierFloodWire struct {
	Version      uint8         `json:"version"`
	Attempts     uint64        `json:"attempts"`
	Completed    bool          `json:"completed"`
	Capabilities linuxcap.Wire `json:"capabilities"`
	Namespace    struct {
		Identity       NetworkNamespaceIdentity `json:"identity"`
		LoopbackOnly   bool                     `json:"loopback_only"`
		TablesEmpty    bool                     `json:"tables_empty"`
		ConntrackEmpty bool                     `json:"conntrack_empty"`
	} `json:"namespace"`
	RoutesComplete bool `json:"routes_complete"`
}

type runtimePolicyIdentityWire struct {
	Version       uint8  `json:"version"`
	PolicyDigest  string `json:"policy_digest"`
	EgressBackend string `json:"egress_backend"`
}

// VerifyLoopbackFlood performs exactly one closed, serial loopback flood in
// the already-bound adapter namespace and accepts only a capability-less
// canonical post-flood report. It deliberately does not widen Engine.
func (c *DockerCLI) VerifyLoopbackFlood(
	ctx context.Context,
	handle AdapterHandle,
	spec VerifierSpec,
	attempts uint64,
) (LoopbackFloodEvidence, error) {
	if attempts == 0 {
		return LoopbackFloodEvidence{},
			errors.New("hostruntime: loopback flood attempts invalid")
	}
	record, err := c.beginAdapterVerification(handle, spec, true)
	if err != nil {
		return LoopbackFloodEvidence{}, err
	}
	defer c.finishAdapterVerification(record)

	if err := c.reinspectAdapter(ctx, handle); err != nil {
		return LoopbackFloodEvidence{}, err
	}
	request, err := json.Marshal(verifierFloodRequestWire{
		Version:  1,
		Attempts: attempts,
	})
	if err != nil {
		return LoopbackFloodEvidence{},
			errors.New("hostruntime: loopback flood request invalid")
	}
	request = append(request, '\n')
	output, err := c.runNetworkVerifier(
		ctx,
		handle.nonce,
		handle.id,
		spec,
		"loopback-flood",
		bytes.NewReader(request),
	)
	zeroBytes(request)
	if err != nil {
		return LoopbackFloodEvidence{}, err
	}
	report, err := parseVerifierFlood(output, attempts)
	if err != nil {
		return LoopbackFloodEvidence{}, err
	}
	if err := c.reinspectAdapter(ctx, handle); err != nil {
		return LoopbackFloodEvidence{}, err
	}
	if !c.adapterVerificationStillCurrent(record, true) {
		return LoopbackFloodEvidence{},
			errors.New("hostruntime: loopback flood state lost")
	}
	digest := digestVerifierEvidence(
		"portable-ghar.loopback-flood.v1",
		handle.id,
		spec.Image,
		spec.BuildID,
		strconv.FormatUint(spec.FleetGeneration, 10),
		strconv.FormatUint(attempts, 10),
		string(output),
	)
	return LoopbackFloodEvidence{
		adapterID: handle.id,
		report:    report,
		issuer:    c.issuer,
		nonce:     handle.nonce,
		digest:    digest,
	}, nil
}

func (c *DockerCLI) VerifyNetworkAdapterEmpty(
	ctx context.Context,
	handle AdapterHandle,
	spec VerifierSpec,
) (AdapterEmptinessEvidence, error) {
	record, err := c.beginAdapterVerification(handle, spec, false)
	if err != nil {
		return AdapterEmptinessEvidence{}, err
	}
	defer c.finishAdapterVerification(record)

	if err := c.reinspectAdapter(ctx, handle); err != nil {
		return AdapterEmptinessEvidence{}, err
	}
	output, err := c.runNetworkVerifier(
		ctx,
		handle.nonce,
		handle.id,
		spec,
		"namespace-empty",
		nil,
	)
	if err != nil {
		return AdapterEmptinessEvidence{}, err
	}
	namespace, err := parseVerifierNamespace(output)
	if err != nil {
		return AdapterEmptinessEvidence{}, err
	}
	if err := c.reinspectAdapter(ctx, handle); err != nil {
		return AdapterEmptinessEvidence{}, err
	}
	if !c.adapterVerificationStillCurrent(record, false) {
		return AdapterEmptinessEvidence{},
			errors.New("hostruntime: adapter verification state lost")
	}
	digest := digestVerifierEvidence(
		"portable-ghar.adapter-emptiness.v1",
		handle.id,
		spec.Image,
		spec.BuildID,
		strconv.FormatUint(spec.FleetGeneration, 10),
		string(output),
	)
	return AdapterEmptinessEvidence{
		adapterID: handle.id,
		namespace: namespace,
		issuer:    c.issuer,
		nonce:     handle.nonce,
		digest:    digest,
	}, nil
}

func (c *DockerCLI) VerifyNetworkEgress(
	ctx context.Context,
	adapter AdapterHandle,
	broker BrokerHandle,
	artifact PolicyArtifact,
	spec VerifierSpec,
) (NetworkEgressEvidence, error) {
	adapterRecord, brokerRecord, err := c.beginEgressVerification(
		adapter,
		broker,
		artifact,
		spec,
	)
	if err != nil {
		return NetworkEgressEvidence{}, err
	}
	defer c.finishEgressVerification(adapterRecord, brokerRecord)

	if err := c.reinspectAdapter(ctx, adapter); err != nil {
		return NetworkEgressEvidence{}, err
	}
	if _, raw, err := c.inspectBrokerContainer(ctx, brokerRecord); err != nil {
		zeroBytes(raw)
		return NetworkEgressEvidence{}, err
	} else {
		zeroBytes(raw)
	}
	runtimePolicy := artifact.RuntimePolicy()
	defer zeroBytes(runtimePolicy)
	policyIdentity, err := parseRuntimePolicyIdentity(runtimePolicy)
	if err != nil {
		return NetworkEgressEvidence{}, err
	}
	proxyOutput, err := c.runNetworkVerifier(
		ctx,
		adapter.nonce,
		adapter.id,
		spec,
		"probe",
		bytes.NewReader(runtimePolicy),
	)
	if err != nil {
		return NetworkEgressEvidence{}, err
	}
	proxy, err := parseVerifierProxy(proxyOutput)
	if err != nil ||
		proxy.PolicyDigest != policyIdentity.PolicyDigest ||
		proxy.EgressBackend != policyIdentity.EgressBackend {
		return NetworkEgressEvidence{},
			errors.New("hostruntime: verifier policy proof invalid")
	}
	brokerOutput, err := c.runNetworkVerifier(
		ctx,
		broker.nonce,
		broker.id,
		spec,
		"namespace-id",
		nil,
	)
	if err != nil {
		return NetworkEgressEvidence{}, err
	}
	brokerNamespace, err := parseVerifierIdentity(brokerOutput)
	if err != nil || proxy.RunnerNetNSID == brokerNamespace {
		return NetworkEgressEvidence{},
			errors.New("hostruntime: verifier namespace proof invalid")
	}
	if validateBrokerReadiness(brokerRecord.readiness) != nil {
		return NetworkEgressEvidence{},
			errors.New("hostruntime: parser sandbox proof invalid")
	}
	readiness, err := encodeBrokerReadiness(brokerRecord.readiness)
	if err != nil {
		return NetworkEgressEvidence{},
			errors.New("hostruntime: parser sandbox proof invalid")
	}
	defer zeroBytes(readiness)
	if err := c.reinspectAdapter(ctx, adapter); err != nil {
		return NetworkEgressEvidence{}, err
	}
	if _, raw, err := c.inspectBrokerContainer(ctx, brokerRecord); err != nil {
		zeroBytes(raw)
		return NetworkEgressEvidence{}, err
	} else {
		zeroBytes(raw)
	}
	if !c.egressVerificationStillCurrent(adapterRecord, brokerRecord, artifact) {
		return NetworkEgressEvidence{},
			errors.New("hostruntime: egress verification state lost")
	}
	report := NetworkVerifierReport{
		PolicyDigest:         proxy.PolicyDigest,
		EgressBackend:        proxy.EgressBackend,
		RunnerNetNSID:        proxy.RunnerNetNSID,
		BrokerNetNSID:        brokerNamespace,
		RunnerLoopbackOnly:   true,
		RunnerTablesEmpty:    true,
		RunnerConntrackEmpty: true,
		ParserHasNoSocket:    true,
		PositiveOK:           true,
		NegativeOK:           true,
	}
	digest := digestVerifierEvidence(
		"portable-ghar.network-egress.v1",
		adapter.id,
		broker.id,
		artifact.Digest(),
		spec.Image,
		spec.BuildID,
		strconv.FormatUint(spec.FleetGeneration, 10),
		string(proxyOutput),
		string(brokerOutput),
		string(readiness),
	)
	return NetworkEgressEvidence{
		adapterID:      adapter.id,
		brokerID:       broker.id,
		policyArtifact: artifact.Digest(),
		report:         report,
		issuer:         c.issuer,
		adapterNonce:   adapter.nonce,
		brokerNonce:    broker.nonce,
		digest:         digest,
	}, nil
}

func (c *DockerCLI) beginAdapterVerification(
	handle AdapterHandle,
	spec VerifierSpec,
	requireBound bool,
) (*adapterRecord, error) {
	if c == nil || !handle.validFor(c.issuer) {
		return nil, errors.New("hostruntime: adapter handle invalid")
	}
	if err := c.validateVerifierSpec(handle, spec); err != nil {
		return nil, err
	}
	if err := c.verifySeccomp(spec.Seccomp); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	record := c.adapters[handle.nonce]
	if record == nil || record.handle.id != handle.id ||
		record.destroyed || record.busy || record.bound != requireBound {
		return nil, errors.New("hostruntime: adapter verification unavailable")
	}
	record.busy = true
	return record, nil
}

func (c *DockerCLI) finishAdapterVerification(record *adapterRecord) {
	if c == nil || record == nil {
		return
	}
	c.mu.Lock()
	if current := c.adapters[record.handle.nonce]; current == record {
		record.busy = false
	}
	c.mu.Unlock()
}

func (c *DockerCLI) adapterVerificationStillCurrent(
	record *adapterRecord,
	bound bool,
) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return record != nil &&
		c.adapters[record.handle.nonce] == record &&
		!record.destroyed &&
		record.busy &&
		record.bound == bound
}

func (c *DockerCLI) beginEgressVerification(
	adapter AdapterHandle,
	broker BrokerHandle,
	artifact PolicyArtifact,
	spec VerifierSpec,
) (*adapterRecord, *brokerRecord, error) {
	if c == nil || !adapter.validFor(c.issuer) ||
		!broker.validFor(c.issuer) || !artifact.valid() {
		return nil, nil, errors.New("hostruntime: egress verification unavailable")
	}
	if err := c.validateVerifierSpec(adapter, spec); err != nil {
		return nil, nil, err
	}
	if err := c.verifySeccomp(spec.Seccomp); err != nil {
		return nil, nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	adapterRecord := c.adapters[adapter.nonce]
	brokerRecord := c.brokers[broker.nonce]
	if adapterRecord == nil || brokerRecord == nil ||
		adapterRecord.handle.id != adapter.id ||
		brokerRecord.handle.id != broker.id ||
		brokerRecord.handle.adapterNonce != adapter.nonce ||
		adapterRecord.destroyed || brokerRecord.destroyed ||
		adapterRecord.busy || brokerRecord.busy ||
		!adapterRecord.bound ||
		brokerRecord.phase != brokerPhaseReleased ||
		brokerRecord.policyDigest != artifact.digest {
		return nil, nil, errors.New("hostruntime: egress verification unavailable")
	}
	adapterRecord.busy = true
	brokerRecord.busy = true
	return adapterRecord, brokerRecord, nil
}

func (c *DockerCLI) finishEgressVerification(
	adapter *adapterRecord,
	broker *brokerRecord,
) {
	if c == nil {
		return
	}
	c.mu.Lock()
	if adapter != nil && c.adapters[adapter.handle.nonce] == adapter {
		adapter.busy = false
	}
	if broker != nil && c.brokers[broker.handle.nonce] == broker {
		broker.busy = false
	}
	c.mu.Unlock()
}

func (c *DockerCLI) egressVerificationStillCurrent(
	adapter *adapterRecord,
	broker *brokerRecord,
	artifact PolicyArtifact,
) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return adapter != nil && broker != nil &&
		c.adapters[adapter.handle.nonce] == adapter &&
		c.brokers[broker.handle.nonce] == broker &&
		!adapter.destroyed && !broker.destroyed &&
		adapter.busy && broker.busy && adapter.bound &&
		broker.phase == brokerPhaseReleased &&
		broker.policyDigest == artifact.digest
}

func (c *DockerCLI) validateVerifierSpec(
	adapter AdapterHandle,
	spec VerifierSpec,
) error {
	if err := validateImageRef(spec.Image); err != nil {
		return errors.New("hostruntime: verifier image invalid")
	}
	if !spec.Adapter.validFor(c.issuer) ||
		spec.Adapter.id != adapter.id ||
		spec.Adapter.nonce != adapter.nonce ||
		spec.BuildID != adapter.buildID ||
		spec.FleetGeneration != adapter.fleetGeneration ||
		spec.SlotIdentity == "" ||
		spec.SlotIdentity != adapter.slotIdentity {
		return errors.New("hostruntime: verifier adapter binding invalid")
	}
	uid, _, err := parseUser(spec.User)
	if err != nil || uid == 0 {
		return errors.New("hostruntime: verifier requires a non-root user")
	}
	if err := validateDescendant(
		c.cfg.SeccompRoot,
		spec.Seccomp.Path,
		"seccomp path",
	); err != nil {
		return err
	}
	return validateOneShotLimits(spec.Limits)
}

func (c *DockerCLI) runNetworkVerifier(
	ctx context.Context,
	nonce [32]byte,
	namespaceID string,
	spec VerifierSpec,
	operation string,
	stdin io.Reader,
) ([]byte, error) {
	name := verifierContainerName(nonce, operation)
	result, runErr := c.runner.Run(
		ctx,
		c.networkVerifierArgv(name, namespaceID, spec, operation),
		nil,
		stdin,
	)
	inventoryCtx, cancelInventory := context.WithTimeout(
		context.WithoutCancel(ctx),
		cleanupTimeout,
	)
	residualID, inventoryErr := c.verifierContainerID(inventoryCtx, name)
	cancelInventory()
	if ctx.Err() != nil || runErr != nil || result.ExitCode != 0 || result.Signaled ||
		result.StdoutTruncated || result.StderrTruncated ||
		len(result.Stderr) != 0 ||
		len(result.Stdout) == 0 ||
		len(result.Stdout) > maxVerifierResultBytes ||
		inventoryErr != nil || residualID != "" {
		if inventoryErr == nil && residualID != "" {
			_ = c.removeVerifier(ctx, verifierCleanupIdentity{
				ContainerID:     residualID,
				Name:            name,
				Image:           spec.Image,
				BuildID:         spec.BuildID,
				FleetGeneration: spec.FleetGeneration,
				SlotIdentity:    spec.SlotIdentity,
				Operation:       operation,
			})
		}
		return nil, errors.New("hostruntime: network verifier failed")
	}
	return result.Stdout, nil
}

func (c *DockerCLI) networkVerifierArgv(
	name,
	namespaceID string,
	spec VerifierSpec,
	operation string,
) []string {
	return []string{
		c.cfg.DockerPath, "run", "--rm",
		"--name", name,
		"--network", "container:" + namespaceID,
		"--cap-drop", "ALL",
		"--read-only",
		"--security-opt", "no-new-privileges=true",
		"--security-opt", "seccomp=" + spec.Seccomp.Path,
		"--user", spec.User,
		"--cpus", formatMilliCPU(spec.Limits.MilliCPU),
		"--memory", strconv.FormatUint(spec.Limits.MemoryBytes, 10),
		"--memory-swap", strconv.FormatUint(spec.Limits.MemorySwapBytes, 10),
		"--pids-limit", strconv.FormatUint(spec.Limits.PIDs, 10),
		"--ulimit", fmt.Sprintf(
			"nofile=%d:%d",
			spec.Limits.FileDescriptors,
			spec.Limits.FileDescriptors,
		),
		"--log-driver", "none",
		"--label", "io.portable-ghar.managed=true",
		"--label", "io.portable-ghar.kind=network-verifier",
		"--label", "io.portable-ghar.build-id=" + spec.BuildID,
		"--label", "io.portable-ghar.fleet-generation=" +
			strconv.FormatUint(spec.FleetGeneration, 10),
		"--label", "io.portable-ghar.slot=" + spec.SlotIdentity,
		"--entrypoint", verifierEntrypoint,
		spec.Image,
		operation,
	}
}

func (c *DockerCLI) proveVerifierGone(
	ctx context.Context,
	name string,
) error {
	id, err := c.verifierContainerID(ctx, name)
	if err != nil || id != "" {
		return errors.New("hostruntime: network verifier absence unproven")
	}
	return nil
}

func (c *DockerCLI) verifierContainerID(
	ctx context.Context,
	name string,
) (string, error) {
	id, err := c.containerIDByExactName(ctx, name)
	if err != nil {
		return "", errors.New("hostruntime: network verifier inventory failed")
	}
	return id, nil
}

type verifierCleanupIdentity struct {
	ContainerID     string
	Name            string
	Image           string
	BuildID         string
	FleetGeneration uint64
	SlotIdentity    string
	Operation       string
}

type verifierCleanupInspect struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		Image      string            `json:"Image"`
		Labels     map[string]string `json:"Labels"`
		Entrypoint []string          `json:"Entrypoint"`
		Cmd        []string          `json:"Cmd"`
	} `json:"Config"`
}

func (c *DockerCLI) removeVerifier(
	parent context.Context,
	expected verifierCleanupIdentity,
) error {
	ctx, cancel := context.WithTimeout(
		context.WithoutCancel(parent),
		cleanupTimeout,
	)
	defer cancel()
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
		return errors.New("hostruntime: network verifier cleanup inspection failed")
	}
	var documents []verifierCleanupInspect
	if err := json.Unmarshal(inspectResult.Stdout, &documents); err != nil ||
		len(documents) != 1 ||
		!verifierCleanupInspectMatches(documents[0], expected) {
		return errors.New("hostruntime: network verifier cleanup identity unproven")
	}
	removeResult, removeErr := c.runner.Run(
		ctx,
		[]string{c.cfg.DockerPath, "rm", "-f", expected.ContainerID},
		nil,
		nil,
	)
	if removeErr != nil || removeResult.ExitCode != 0 ||
		removeResult.Signaled || removeResult.StdoutTruncated ||
		removeResult.StderrTruncated || len(removeResult.Stderr) != 0 {
		return errors.New("hostruntime: network verifier cleanup removal failed")
	}
	if err := c.proveVerifierGone(ctx, expected.Name); err != nil {
		return errors.New("hostruntime: network verifier cleanup failed")
	}
	return nil
}

func verifierCleanupInspectMatches(
	document verifierCleanupInspect,
	expected verifierCleanupIdentity,
) bool {
	return document.ID == expected.ContainerID &&
		document.Name == "/"+expected.Name &&
		document.Config.Image == expected.Image &&
		len(document.Config.Entrypoint) == 1 &&
		document.Config.Entrypoint[0] == verifierEntrypoint &&
		len(document.Config.Cmd) == 1 &&
		document.Config.Cmd[0] == expected.Operation &&
		equalStringMap(document.Config.Labels, map[string]string{
			"io.portable-ghar.managed":          "true",
			"io.portable-ghar.kind":             "network-verifier",
			"io.portable-ghar.build-id":         expected.BuildID,
			"io.portable-ghar.fleet-generation": strconv.FormatUint(expected.FleetGeneration, 10),
			"io.portable-ghar.slot":             expected.SlotIdentity,
		})
}

func verifierContainerName(nonce [32]byte, operation string) string {
	suffix := "empty"
	switch operation {
	case "probe":
		suffix = "probe"
	case "namespace-id":
		suffix = "identity"
	case "loopback-flood":
		suffix = "flood"
	}
	return "pghar-verifier-" + hex.EncodeToString(nonce[:16]) + "-" + suffix
}

func parseVerifierFlood(
	data []byte,
	expectedAttempts uint64,
) (LoopbackFloodReport, error) {
	var wire verifierFloodWire
	if expectedAttempts == 0 ||
		parseCanonicalVerifierJSON(data, &wire) != nil ||
		wire.Version != 2 ||
		wire.Attempts != expectedAttempts ||
		!wire.Completed ||
		linuxcap.ValidateEmpty(wire.Capabilities) != nil ||
		wire.Namespace.Identity.Device == 0 ||
		wire.Namespace.Identity.Inode == 0 ||
		!wire.Namespace.LoopbackOnly ||
		!wire.Namespace.TablesEmpty ||
		!wire.Namespace.ConntrackEmpty ||
		!wire.RoutesComplete {
		return LoopbackFloodReport{},
			errors.New("hostruntime: verifier flood proof invalid")
	}
	return LoopbackFloodReport{
		Attempts:       wire.Attempts,
		Completed:      true,
		Namespace:      wire.Namespace.Identity,
		LoopbackOnly:   true,
		TablesEmpty:    true,
		ConntrackEmpty: true,
		RoutesComplete: true,
	}, nil
}

func parseVerifierNamespace(
	data []byte,
) (NetworkNamespaceIdentity, error) {
	var wire verifierNamespaceWire
	if parseCanonicalVerifierJSON(data, &wire) != nil ||
		wire.Version != 2 ||
		linuxcap.ValidateEmpty(wire.Capabilities) != nil ||
		wire.Namespace.Identity.Device == 0 ||
		wire.Namespace.Identity.Inode == 0 ||
		!wire.Namespace.LoopbackOnly ||
		!wire.Namespace.TablesEmpty ||
		!wire.Namespace.ConntrackEmpty {
		return NetworkNamespaceIdentity{},
			errors.New("hostruntime: verifier namespace proof invalid")
	}
	return wire.Namespace.Identity, nil
}

func parseVerifierIdentity(
	data []byte,
) (NetworkNamespaceIdentity, error) {
	var wire verifierIdentityWire
	if parseCanonicalVerifierJSON(data, &wire) != nil ||
		wire.Version != 2 ||
		linuxcap.ValidateEmpty(wire.Capabilities) != nil ||
		wire.Identity.Device == 0 ||
		wire.Identity.Inode == 0 {
		return NetworkNamespaceIdentity{},
			errors.New("hostruntime: verifier identity proof invalid")
	}
	return wire.Identity, nil
}

func parseVerifierProxy(data []byte) (verifierProxyWire, error) {
	var wire verifierProxyWire
	if parseCanonicalVerifierJSON(data, &wire) != nil ||
		wire.Version != 2 ||
		linuxcap.ValidateEmpty(wire.Capabilities) != nil ||
		!isLowerHex64(wire.PolicyDigest) ||
		wire.EgressBackend != "restricted-broker-v1" ||
		wire.RunnerNetNSID.Device == 0 ||
		wire.RunnerNetNSID.Inode == 0 ||
		!wire.RunnerLoopbackOnly ||
		!wire.RunnerTablesEmpty ||
		!wire.RunnerConntrackEmpty ||
		!wire.PositiveOK ||
		!wire.NegativeOK {
		return verifierProxyWire{},
			errors.New("hostruntime: verifier proxy proof invalid")
	}
	return wire, nil
}

func parseCanonicalVerifierJSON(data []byte, target any) error {
	if len(data) == 0 || len(data) > maxVerifierResultBytes {
		return errors.New("hostruntime: verifier result invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil ||
		decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("hostruntime: verifier result invalid")
	}
	canonical, err := json.Marshal(target)
	if err != nil {
		return errors.New("hostruntime: verifier result invalid")
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(canonical, data) {
		return errors.New("hostruntime: verifier result noncanonical")
	}
	return nil
}

func parseRuntimePolicyIdentity(
	data []byte,
) (runtimePolicyIdentityWire, error) {
	var wire runtimePolicyIdentityWire
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&wire); err != nil ||
		decoder.Decode(&struct{}{}) != io.EOF ||
		wire.Version != 1 ||
		!isLowerHex64(wire.PolicyDigest) ||
		wire.EgressBackend != "restricted-broker-v1" {
		return runtimePolicyIdentityWire{},
			errors.New("hostruntime: runtime policy identity invalid")
	}
	return wire, nil
}

func digestVerifierEvidence(label string, values ...string) [32]byte {
	hash := sha256.New()
	writeVerifierDigestField(hash, label)
	for _, value := range values {
		writeVerifierDigestField(hash, value)
	}
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func writeVerifierDigestField(writer io.Writer, value string) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = io.WriteString(writer, value)
}
