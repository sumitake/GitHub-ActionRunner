package hostruntime

import "crypto/subtle"

// AdapterHandle is constructed only after the engine has created a managed
// adapter. Unexported issuer and nonce fields prevent a caller in another
// package from turning an arbitrary Docker ID into network authority.
type AdapterHandle struct {
	id              string
	image           string
	buildID         string
	fleetGeneration uint64
	issuer          [32]byte
	nonce           [32]byte
}

// ID returns the nonsecret Docker identity for diagnostics and exact readback.
func (h AdapterHandle) ID() string { return h.id }

func (h AdapterHandle) validFor(issuer [32]byte) bool {
	return h.id != "" &&
		h.image != "" &&
		h.buildID != "" &&
		h.fleetGeneration != 0 &&
		nonzero32(h.nonce) &&
		subtle.ConstantTimeCompare(h.issuer[:], issuer[:]) == 1
}

func newAdapterHandle(id, image, buildID string, generation uint64, issuer, nonce [32]byte) AdapterHandle {
	return AdapterHandle{
		id:              id,
		image:           image,
		buildID:         buildID,
		fleetGeneration: generation,
		issuer:          issuer,
		nonce:           nonce,
	}
}

// BrokerHandle is the only broker-container identity accepted after creation.
// It binds the broker to the same engine, build, fleet generation, and adapter
// without exposing any constructor outside this package.
type BrokerHandle struct {
	id              string
	buildID         string
	fleetGeneration uint64
	adapterNonce    [32]byte
	issuer          [32]byte
	nonce           [32]byte
}

// ID returns the nonsecret Docker identity for diagnostics and persistence.
func (h BrokerHandle) ID() string { return h.id }

func (h BrokerHandle) validFor(issuer [32]byte) bool {
	return h.id != "" &&
		h.buildID != "" &&
		h.fleetGeneration != 0 &&
		nonzero32(h.adapterNonce) &&
		nonzero32(h.nonce) &&
		subtle.ConstantTimeCompare(h.issuer[:], issuer[:]) == 1
}

func newBrokerHandle(
	id, buildID string,
	generation uint64,
	adapterNonce, issuer, nonce [32]byte,
) BrokerHandle {
	return BrokerHandle{
		id:              id,
		buildID:         buildID,
		fleetGeneration: generation,
		adapterNonce:    adapterNonce,
		issuer:          issuer,
		nonce:           nonce,
	}
}

// RunnerHandle is likewise engine-issued. The degraded bit is an explicit
// non-conformance signal, never a fallback profile selection.
type RunnerHandle struct {
	id              string
	buildID         string
	fleetGeneration uint64
	issuer          [32]byte
	nonce           [32]byte
	degraded        bool
}

// ID returns the nonsecret Docker identity for diagnostics and exact readback.
func (h RunnerHandle) ID() string { return h.id }

// Degraded reports exact qts-capless-root selection. Degraded handles cannot
// satisfy strict target conformance.
func (h RunnerHandle) Degraded() bool { return h.degraded }

func (h RunnerHandle) validFor(issuer [32]byte) bool {
	return h.id != "" &&
		h.buildID != "" &&
		h.fleetGeneration != 0 &&
		nonzero32(h.nonce) &&
		subtle.ConstantTimeCompare(h.issuer[:], issuer[:]) == 1
}

func newRunnerHandle(id, buildID string, generation uint64, issuer, nonce [32]byte, degraded bool) RunnerHandle {
	return RunnerHandle{
		id:              id,
		buildID:         buildID,
		fleetGeneration: generation,
		issuer:          issuer,
		nonce:           nonce,
		degraded:        degraded,
	}
}

func nonzero32(value [32]byte) bool {
	var combined byte
	for _, b := range value {
		combined |= b
	}
	return combined != 0
}
