// portable-ghar-runner-gate is the single held process in each runner.
// This file keeps protocol parsing and one-use authority independent from the
// container/socket entrypoint so the security state machine is exhaustively
// testable without Docker.
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"slices"
	"sort"
	"sync"
)

const (
	maxJITLength = 65536
	maxSeedCount = 128
	maxSeedIDLen = 64
)

var seedIDPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)

type gateOperation uint8

const (
	opHydrateSeeds gateOperation = iota + 1
	opNetNSID
	opArm
	opRelease
)

type gatePhase uint8

const (
	phaseHydrate gatePhase = iota
	phasePreNetNS
	phaseArm
	phaseFinalNetNS
	phaseRelease
	phaseConsumed
	phaseFailed
)

type gateMachine struct {
	phase     gatePhase
	digest    [sha256.Size]byte
	hydrate   func([]string) error
	namespace func() ([]byte, error)
	execute   func([]byte) error
}

func newGateMachine(hydrate func([]string) error, namespace func() ([]byte, error), execute func([]byte) error) *gateMachine {
	return &gateMachine{phase: phaseHydrate, hydrate: hydrate, namespace: namespace, execute: execute}
}

func (g *gateMachine) apply(operation gateOperation, payload []byte) ([]byte, func() error, error) {
	if g == nil || g.phase == phaseFailed || g.phase == phaseConsumed || g.hydrate == nil || g.namespace == nil || g.execute == nil {
		return nil, nil, errors.New("runner-gate: terminal state")
	}

	fail := func() ([]byte, func() error, error) {
		zero(g.digest[:])
		g.phase = phaseFailed
		return nil, nil, errors.New("runner-gate: operation rejected")
	}

	switch g.phase {
	case phaseHydrate:
		if operation != opHydrateSeeds {
			return fail()
		}
		ids, err := parseSeedSelection(payload)
		if err != nil || g.hydrate(ids) != nil {
			return fail()
		}
		g.phase = phasePreNetNS
		return []byte("OK\n"), nil, nil

	case phasePreNetNS:
		if operation != opNetNSID || len(payload) != 0 {
			return fail()
		}
		proof, err := g.namespace()
		if err != nil || !validNamespaceResponse(proof) {
			return fail()
		}
		g.phase = phaseArm
		return proof, nil, nil

	case phaseArm:
		if operation != opArm {
			return fail()
		}
		digest, err := parseArmFrame(payload)
		if err != nil {
			return fail()
		}
		g.digest = digest
		g.phase = phaseFinalNetNS
		return []byte("OK\n"), nil, nil

	case phaseFinalNetNS:
		if operation != opNetNSID || len(payload) != 0 {
			return fail()
		}
		proof, err := g.namespace()
		if err != nil || !validNamespaceResponse(proof) {
			return fail()
		}
		g.phase = phaseRelease
		return proof, nil, nil

	case phaseRelease:
		if operation != opRelease {
			return fail()
		}
		token, jit, err := parseReleaseFrame(payload)
		if err != nil {
			return fail()
		}
		digest := sha256.Sum256(token[:])
		zero(token[:])
		if subtle.ConstantTimeCompare(digest[:], g.digest[:]) != 1 {
			zero(digest[:])
			zero(jit)
			return fail()
		}
		zero(digest[:])
		zero(g.digest[:])
		g.phase = phaseConsumed

		var mu sync.Mutex
		used := false
		action := func() error {
			mu.Lock()
			defer mu.Unlock()
			if used {
				return errors.New("runner-gate: release action consumed")
			}
			used = true
			defer zero(jit)
			if err := g.execute(jit); err != nil {
				g.phase = phaseFailed
				return errors.New("runner-gate: listener execution failed")
			}
			return nil
		}
		return []byte("OK\n"), action, nil
	}
	return fail()
}

func parseArmFrame(frame []byte) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	if len(frame) != 44 || string(frame[:8]) != "PGHARARM" || frame[8] != 1 || frame[9] != 1 || binary.BigEndian.Uint16(frame[10:12]) != sha256.Size {
		return digest, errors.New("runner-gate: arm frame invalid")
	}
	copy(digest[:], frame[12:44])
	if allZero(digest[:]) {
		zero(digest[:])
		return digest, errors.New("runner-gate: arm digest invalid")
	}
	return digest, nil
}

func parseReleaseFrame(frame []byte) ([32]byte, []byte, error) {
	var token [32]byte
	if len(frame) < 48 || string(frame[:8]) != "PGHARREL" || frame[8] != 1 || binary.BigEndian.Uint16(frame[9:11]) != 32 {
		return token, nil, errors.New("runner-gate: release frame invalid")
	}
	jitLength := binary.BigEndian.Uint32(frame[11:15])
	if jitLength == 0 || jitLength > maxJITLength || uint64(len(frame)) != uint64(47)+uint64(jitLength) {
		return token, nil, errors.New("runner-gate: release length invalid")
	}
	copy(token[:], frame[15:47])
	if allZero(token[:]) {
		zero(token[:])
		return token, nil, errors.New("runner-gate: release token invalid")
	}
	jit := slices.Clone(frame[47:])
	return token, jit, nil
}

func parseSeedSelection(payload []byte) ([]string, error) {
	var ids []string
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(&ids); err != nil {
		return nil, errors.New("runner-gate: seed selection invalid")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF || len(ids) > maxSeedCount || !sort.StringsAreSorted(ids) {
		return nil, errors.New("runner-gate: seed selection invalid")
	}
	for i, id := range ids {
		if len(id) == 0 || len(id) > maxSeedIDLen || !seedIDPattern.MatchString(id) || (i > 0 && id == ids[i-1]) {
			return nil, errors.New("runner-gate: seed selection invalid")
		}
	}
	canonical, _ := json.Marshal(ids)
	canonical = append(canonical, '\n')
	if !bytes.Equal(payload, canonical) {
		return nil, errors.New("runner-gate: seed selection noncanonical")
	}
	return slices.Clone(ids), nil
}

func validNamespaceResponse(response []byte) bool {
	var wire struct {
		Version uint8  `json:"version"`
		Device  uint64 `json:"device"`
		Inode   uint64 `json:"inode"`
	}
	decoder := json.NewDecoder(bytes.NewReader(response))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF || wire.Version != 1 || wire.Device == 0 || wire.Inode == 0 {
		return false
	}
	canonical, _ := json.Marshal(wire)
	canonical = append(canonical, '\n')
	return bytes.Equal(response, canonical)
}

func allZero(data []byte) bool {
	var combined byte
	for _, value := range data {
		combined |= value
	}
	return combined == 0
}

func zero(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, defaultGateRuntime()))
}
