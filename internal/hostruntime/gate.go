package hostruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"sort"
	"time"

	"github.com/sumitake/portable-ghar/internal/redaction"
)

const (
	releaseTokenBytes = 32
	maxJITBytes       = 65536
	maxSeedIDs        = 128
	maxSeedIDBytes    = 64
	maxSeedFrameBytes = 16 << 10
	cleanupTimeout    = 10 * time.Second
)

var seedIDPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)

type adapterRecord struct {
	handle    AdapterHandle
	spec      AdapterSpec
	busy      bool
	bound     bool
	destroyed bool
}

type runnerRecord struct {
	handle            RunnerHandle
	adapter           AdapterHandle
	spec              RunnerSpec
	next              GateOperation
	busy              bool
	destroyed         bool
	releaseAuthorized bool
	token             [releaseTokenBytes]byte
	preArm            NetworkNamespaceProof
	final             NetworkNamespaceProof
}

type namespaceWire struct {
	Version uint8  `json:"version"`
	Device  uint64 `json:"device"`
	Inode   uint64 `json:"inode"`
}

// HydrateSeeds performs the mandatory first held-runner operation. Even an
// empty selection is sent as one canonical, bounded frame.
func (c *DockerCLI) HydrateSeeds(ctx context.Context, handle RunnerHandle, ids []string) error {
	payload, err := encodeSeedIDs(ids)
	if err != nil {
		return c.rejectGate(ctx, handle, err)
	}
	record, err := c.beginGate(ctx, handle, GateHydrateSeeds, false)
	if err != nil {
		return err
	}
	err = c.runGateOK(ctx, record.handle.id, "hydrate-seeds", payload)
	return c.finishGate(ctx, record, GateHydrateSeeds, NetworkNamespaceProof{}, err)
}

// ProbeRunnerNetworkNamespace executes only one of the two ordered,
// input-free namespace probes.
func (c *DockerCLI) ProbeRunnerNetworkNamespace(ctx context.Context, handle RunnerHandle, operation GateOperation) (NetworkNamespaceProof, error) {
	if operation != GateNetNSIDPreArm && operation != GateNetNSIDFinal {
		return NetworkNamespaceProof{}, c.rejectGate(ctx, handle, errors.New("hostruntime: namespace probe operation invalid"))
	}
	record, err := c.beginGate(ctx, handle, operation, false)
	if err != nil {
		return NetworkNamespaceProof{}, err
	}
	proof, runErr := c.runNamespaceCommand(
		ctx,
		record.handle.id,
		runnerEntrypoint,
		record.handle.fleetGeneration,
	)
	if err := c.finishGate(ctx, record, operation, proof, runErr); err != nil {
		return NetworkNamespaceProof{}, err
	}
	return proof, nil
}

// ArmRunner sends only SHA-256(token); the random token remains in the
// controller-owned record until the one release attempt.
func (c *DockerCLI) ArmRunner(ctx context.Context, handle RunnerHandle) error {
	record, err := c.beginGate(ctx, handle, GateArm, false)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(record.token[:])
	frame := make([]byte, 44)
	copy(frame[:8], "PGHARARM")
	frame[8] = 1
	frame[9] = 1
	binary.BigEndian.PutUint16(frame[10:12], 32)
	copy(frame[12:], digest[:])
	err = c.runGateOK(ctx, record.handle.id, "arm", frame)
	zeroBytes(frame)
	return c.finishGate(ctx, record, GateArm, NetworkNamespaceProof{}, err)
}

// AuthorizeRelease creates an opaque authority only after the exact equality
// triangle pre-arm == final == freshly inspected adapter is proven.
func (c *DockerCLI) AuthorizeRelease(ctx context.Context, handle RunnerHandle, preArm, final NetworkNamespaceProof) (ReleaseAuthorization, error) {
	record, err := c.beginAuthorization(ctx, handle)
	if err != nil {
		return ReleaseAuthorization{}, err
	}
	if !equalNamespaceProof(preArm, record.preArm) ||
		!equalNamespaceProof(final, record.final) ||
		!equalNamespaceProof(preArm, final) {
		return ReleaseAuthorization{}, c.failAuthorization(ctx, record, errors.New("hostruntime: runner namespace proofs differ"))
	}
	adapterProof, err := c.runNamespaceCommand(
		ctx,
		record.adapter.id,
		adapterEntrypoint,
		record.adapter.fleetGeneration,
	)
	if err != nil || !equalNamespaceProof(final, adapterProof) {
		if err == nil {
			err = errors.New("hostruntime: adapter namespace proof differs")
		}
		return ReleaseAuthorization{}, c.failAuthorization(ctx, record, err)
	}
	if _, err := c.auditHeldRunnerRecord(ctx, record); err != nil {
		return ReleaseAuthorization{}, c.failAuthorization(ctx, record, err)
	}

	c.mu.Lock()
	if record.destroyed || !record.busy {
		c.mu.Unlock()
		return ReleaseAuthorization{}, errors.New("hostruntime: release authorization lost")
	}
	record.busy = false
	record.releaseAuthorized = true
	c.mu.Unlock()
	return ReleaseAuthorization{
		runnerNonce: handle.nonce,
		issuer:      c.issuer,
		generation:  handle.fleetGeneration,
		namespace:   adapterProof,
	}, nil
}

// ReleaseRunner consumes one scoped JIT secret and the controller-owned token.
// It destroys the JIT on every terminal path.
func (c *DockerCLI) ReleaseRunner(ctx context.Context, handle RunnerHandle, authority ReleaseAuthorization, jit *redaction.Secret) error {
	if jit != nil {
		defer jit.Destroy()
	}
	record, err := c.beginGate(ctx, handle, GateRelease, true)
	if err != nil {
		return err
	}
	if jit == nil || !validReleaseAuthorization(authority, handle, c.issuer, record) {
		return c.finishGate(ctx, record, GateRelease, NetworkNamespaceProof{}, errors.New("hostruntime: release authorization invalid"))
	}

	err = jit.Use(func(reader io.Reader) error {
		jitBytes, readErr := readAtMost(reader, maxJITBytes)
		if readErr != nil || len(jitBytes) == 0 {
			zeroBytes(jitBytes)
			return errors.New("hostruntime: jit payload invalid")
		}
		defer zeroBytes(jitBytes)
		frame := make([]byte, 47+len(jitBytes))
		defer zeroBytes(frame)
		copy(frame[:8], "PGHARREL")
		frame[8] = 1
		binary.BigEndian.PutUint16(frame[9:11], releaseTokenBytes)
		binary.BigEndian.PutUint32(frame[11:15], uint32(len(jitBytes)))
		copy(frame[15:47], record.token[:])
		copy(frame[47:], jitBytes)
		return c.runGateOK(ctx, record.handle.id, "release", frame)
	})
	return c.finishGate(ctx, record, GateRelease, NetworkNamespaceProof{}, err)
}

func (c *DockerCLI) runGateOK(ctx context.Context, id, operation string, payload []byte) error {
	argv := []string{c.cfg.DockerPath, "exec"}
	if payload != nil {
		argv = append(argv, "-i")
	}
	argv = append(argv, id, runnerEntrypoint, operation)
	var input io.Reader
	if payload != nil {
		input = bytes.NewReader(payload)
	}
	result, err := c.runner.Run(ctx, argv, nil, input)
	if err != nil || result.ExitCode != 0 || result.Signaled || result.StdoutTruncated || result.StderrTruncated ||
		!bytes.Equal(result.Stdout, []byte("OK\n")) || len(result.Stderr) != 0 {
		return errors.New("hostruntime: gate operation failed")
	}
	return nil
}

func (c *DockerCLI) runNamespaceCommand(ctx context.Context, id, executable string, generation uint64) (NetworkNamespaceProof, error) {
	result, err := c.runner.Run(ctx, []string{c.cfg.DockerPath, "exec", id, executable, "netns-id"}, nil, nil)
	if err != nil || result.ExitCode != 0 || result.Signaled || result.StdoutTruncated || result.StderrTruncated || len(result.Stderr) != 0 {
		return NetworkNamespaceProof{}, errors.New("hostruntime: namespace probe failed")
	}
	wire, err := parseNamespaceWire(result.Stdout)
	if err != nil {
		return NetworkNamespaceProof{}, err
	}
	return NetworkNamespaceProof{device: wire.Device, inode: wire.Inode, generation: generation, issuer: c.issuer}, nil
}

func parseNamespaceWire(data []byte) (namespaceWire, error) {
	var wire namespaceWire
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return namespaceWire{}, errors.New("hostruntime: namespace proof invalid")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF || wire.Version != 1 || wire.Device == 0 || wire.Inode == 0 {
		return namespaceWire{}, errors.New("hostruntime: namespace proof invalid")
	}
	canonical, _ := json.Marshal(wire)
	canonical = append(canonical, '\n')
	if !bytes.Equal(data, canonical) {
		return namespaceWire{}, errors.New("hostruntime: namespace proof noncanonical")
	}
	return wire, nil
}

func encodeSeedIDs(ids []string) ([]byte, error) {
	if len(ids) > maxSeedIDs {
		return nil, errors.New("hostruntime: seed selection too large")
	}
	canonical := slices.Clone(ids)
	if !sort.StringsAreSorted(canonical) {
		return nil, errors.New("hostruntime: seed ids not sorted")
	}
	for i, id := range canonical {
		if len(id) == 0 || len(id) > maxSeedIDBytes || !seedIDPattern.MatchString(id) {
			return nil, errors.New("hostruntime: seed id invalid")
		}
		if i > 0 && id == canonical[i-1] {
			return nil, errors.New("hostruntime: seed id duplicated")
		}
	}
	payload, err := json.Marshal(canonical)
	if err != nil || len(payload)+1 > maxSeedFrameBytes {
		return nil, errors.New("hostruntime: seed selection encoding failed")
	}
	return append(payload, '\n'), nil
}

func (c *DockerCLI) beginGate(ctx context.Context, handle RunnerHandle, operation GateOperation, requireAuthorization bool) (*runnerRecord, error) {
	if c == nil || !handle.validFor(c.issuer) {
		return nil, errors.New("hostruntime: runner handle invalid")
	}
	c.mu.Lock()
	record := c.runners[handle.nonce]
	if record == nil || record.handle.id != handle.id || record.destroyed {
		c.mu.Unlock()
		return nil, errors.New("hostruntime: runner record unavailable")
	}
	if record.busy || record.next != operation || (requireAuthorization && !record.releaseAuthorized) {
		record.destroyed = true
		zeroToken(&record.token)
		c.mu.Unlock()
		c.removeFailedRunner(ctx, record)
		return nil, errors.New("hostruntime: gate operation order invalid")
	}
	record.busy = true
	c.mu.Unlock()
	return record, nil
}

func (c *DockerCLI) finishGate(ctx context.Context, record *runnerRecord, operation GateOperation, proof NetworkNamespaceProof, operationErr error) error {
	c.mu.Lock()
	if record.destroyed || !record.busy || record.next != operation || operationErr != nil {
		record.destroyed = true
		record.busy = false
		zeroToken(&record.token)
		c.mu.Unlock()
		c.removeFailedRunner(ctx, record)
		if operationErr != nil {
			return operationErr
		}
		return errors.New("hostruntime: gate state lost")
	}
	switch operation {
	case GateNetNSIDPreArm:
		record.preArm = proof
	case GateNetNSIDFinal:
		record.final = proof
	}
	record.busy = false
	if operation == GateRelease {
		record.destroyed = true
		zeroToken(&record.token)
	} else {
		record.next++
	}
	c.mu.Unlock()
	return nil
}

func (c *DockerCLI) beginAuthorization(ctx context.Context, handle RunnerHandle) (*runnerRecord, error) {
	if c == nil || !handle.validFor(c.issuer) {
		return nil, errors.New("hostruntime: runner handle invalid")
	}
	c.mu.Lock()
	record := c.runners[handle.nonce]
	if record == nil || record.destroyed {
		c.mu.Unlock()
		return nil, errors.New("hostruntime: runner record unavailable")
	}
	if record.busy || record.next != GateRelease || record.releaseAuthorized {
		record.destroyed = true
		zeroToken(&record.token)
		c.mu.Unlock()
		c.removeFailedRunner(ctx, record)
		return nil, errors.New("hostruntime: release authorization order invalid")
	}
	record.busy = true
	c.mu.Unlock()
	return record, nil
}

func (c *DockerCLI) failAuthorization(ctx context.Context, record *runnerRecord, err error) error {
	c.mu.Lock()
	record.destroyed = true
	record.busy = false
	zeroToken(&record.token)
	c.mu.Unlock()
	c.removeFailedRunner(ctx, record)
	return err
}

func (c *DockerCLI) rejectGate(ctx context.Context, handle RunnerHandle, err error) error {
	if c == nil || !handle.validFor(c.issuer) {
		return err
	}
	c.mu.Lock()
	record := c.runners[handle.nonce]
	if record == nil || record.destroyed {
		c.mu.Unlock()
		return err
	}
	record.destroyed = true
	record.busy = false
	zeroToken(&record.token)
	c.mu.Unlock()
	c.removeFailedRunner(ctx, record)
	return err
}

func (c *DockerCLI) removeRunnerID(parent context.Context, id string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), cleanupTimeout)
	defer cancel()
	result, err := c.runner.Run(ctx, []string{c.cfg.DockerPath, "rm", "-f", id}, nil, nil)
	if err != nil || result.ExitCode != 0 || result.StdoutTruncated || result.StderrTruncated {
		return errors.New("hostruntime: runner removal failed")
	}
	return nil
}

func validReleaseAuthorization(authority ReleaseAuthorization, handle RunnerHandle, issuer [32]byte, record *runnerRecord) bool {
	return subtle.ConstantTimeCompare(authority.issuer[:], issuer[:]) == 1 &&
		subtle.ConstantTimeCompare(authority.runnerNonce[:], handle.nonce[:]) == 1 &&
		authority.generation == handle.fleetGeneration &&
		equalNamespaceProof(authority.namespace, record.final) &&
		record.releaseAuthorized
}

func equalNamespaceProof(a, b NetworkNamespaceProof) bool {
	return a.device != 0 && a.inode != 0 && a.generation != 0 &&
		a.device == b.device && a.inode == b.inode && a.generation == b.generation &&
		subtle.ConstantTimeCompare(a.issuer[:], b.issuer[:]) == 1
}

func zeroToken(token *[releaseTokenBytes]byte) {
	for i := range token {
		token[i] = 0
	}
}
