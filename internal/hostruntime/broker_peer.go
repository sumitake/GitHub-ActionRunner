package hostruntime

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"

	"github.com/sumitake/portable-ghar/internal/relaycontract"
)

type brokerDirectoryIdentity struct {
	Device uint64
	Inode  uint64
	UID    uint32
	GID    uint32
	Mode   uint32
}

type brokerSocketIdentity struct {
	Name   string
	Device uint64
	Inode  uint64
	UID    uint32
	GID    uint32
	Mode   uint32
}

type brokerProcessIdentity struct {
	PID       uint32
	StartTime uint64
}

type brokerDirectoryProof struct {
	device uint64
	inode  uint64
	uid    uint32
	gid    uint32
	mode   uint32
}

type brokerSocketProof struct {
	name   string
	device uint64
	inode  uint64
	uid    uint32
	gid    uint32
	mode   uint32
}

type brokerProcessProof struct {
	pid       uint32
	startTime uint64
}

// BrokerPeerProof is issued only by the future held-broker lifecycle after
// exact controller-side container, mount, socket, and process inspection.
// Its fields remain opaque so a UID or caller-supplied path cannot become
// adapter-release authority.
type BrokerPeerProof struct {
	adapterNonce     [32]byte
	issuer           [32]byte
	brokerGeneration uint64
	heldSocketZero   [32]byte
	directory        brokerDirectoryProof
	socket           brokerSocketProof
	peer             brokerProcessProof
}

func newBrokerPeerProof(
	adapter AdapterHandle,
	issuer [32]byte,
	brokerGeneration uint64,
	heldSocketZero [32]byte,
	directory brokerDirectoryIdentity,
	socket brokerSocketIdentity,
	peer brokerProcessIdentity,
) BrokerPeerProof {
	return BrokerPeerProof{
		adapterNonce:     adapter.nonce,
		issuer:           issuer,
		brokerGeneration: brokerGeneration,
		heldSocketZero:   heldSocketZero,
		directory: brokerDirectoryProof{
			device: directory.Device,
			inode:  directory.Inode,
			uid:    directory.UID,
			gid:    directory.GID,
			mode:   directory.Mode,
		},
		socket: brokerSocketProof{
			name:   socket.Name,
			device: socket.Device,
			inode:  socket.Inode,
			uid:    socket.UID,
			gid:    socket.GID,
			mode:   socket.Mode,
		},
		peer: brokerProcessProof{
			pid:       peer.PID,
			startTime: peer.StartTime,
		},
	}
}

// HeldSocketZeroDigest returns the nonsecret receipt for the exact pre-release
// AF_INET/AF_INET6 TCP, UDP, and raw zero-count audit.
func (proof BrokerPeerProof) HeldSocketZeroDigest() string {
	return hex.EncodeToString(proof.heldSocketZero[:])
}

func validBrokerPeerProof(proof BrokerPeerProof, adapter AdapterHandle, issuer [32]byte, spec AdapterSpec) bool {
	uid, gid, err := parseUser(spec.User)
	return err == nil &&
		subtle.ConstantTimeCompare(proof.issuer[:], issuer[:]) == 1 &&
		subtle.ConstantTimeCompare(proof.adapterNonce[:], adapter.nonce[:]) == 1 &&
		proof.brokerGeneration == adapter.fleetGeneration &&
		nonzero32(proof.heldSocketZero) &&
		proof.directory.device != 0 && proof.directory.inode != 0 &&
		proof.directory.uid == uint32(uid) && proof.directory.gid == uint32(gid) &&
		proof.directory.mode == 0o700 &&
		proof.socket.name == relaycontract.HTTPSProxySocket &&
		proof.socket.device == proof.directory.device && proof.socket.inode != 0 &&
		proof.socket.uid == proof.directory.uid && proof.socket.gid == proof.directory.gid &&
		proof.socket.mode == 0o600 &&
		proof.peer.pid != 0 && proof.peer.startTime != 0
}

func wireFromBrokerPeerProof(proof BrokerPeerProof) relaycontract.Binding {
	return relaycontract.Binding{
		Version:          1,
		BrokerGeneration: proof.brokerGeneration,
		Directory: relaycontract.Directory{
			Device: proof.directory.device,
			Inode:  proof.directory.inode,
			UID:    proof.directory.uid,
			GID:    proof.directory.gid,
			Mode:   proof.directory.mode,
		},
		Socket: relaycontract.Socket{
			Name:   proof.socket.name,
			Device: proof.socket.device,
			Inode:  proof.socket.inode,
			UID:    proof.socket.uid,
			GID:    proof.socket.gid,
			Mode:   proof.socket.mode,
		},
		Peer: relaycontract.Process{
			PID:       proof.peer.pid,
			StartTime: proof.peer.startTime,
		},
	}
}

// BindBrokerPeer consumes one same-engine opaque proof and opens the adapter
// relay exactly once. Repeated or concurrent binding destroys the adapter.
func (c *DockerCLI) BindBrokerPeer(ctx context.Context, handle AdapterHandle, proof BrokerPeerProof) error {
	if c == nil || !handle.validFor(c.issuer) {
		return errors.New("hostruntime: adapter handle invalid")
	}
	c.mu.Lock()
	record := c.adapters[handle.nonce]
	if record == nil || record.destroyed || record.handle.id != handle.id {
		c.mu.Unlock()
		return errors.New("hostruntime: adapter record unavailable")
	}
	if !validBrokerPeerProof(proof, handle, c.issuer, record.spec) {
		c.mu.Unlock()
		return errors.New("hostruntime: broker peer proof invalid")
	}
	if record.busy || record.bound {
		record.destroyed = true
		c.mu.Unlock()
		c.removeFailedAdapter(ctx, record)
		return errors.New("hostruntime: broker peer bind order invalid")
	}
	record.busy = true
	c.mu.Unlock()

	if err := c.reinspectAdapter(ctx, handle); err != nil {
		return c.failBrokerPeerBind(ctx, record, err)
	}
	payload, err := relaycontract.Encode(wireFromBrokerPeerProof(proof))
	if err != nil {
		return c.failBrokerPeerBind(ctx, record, err)
	}
	result, runErr := c.runner.Run(
		ctx,
		[]string{c.cfg.DockerPath, "exec", "-i", handle.id, adapterEntrypoint, "bind-peer"},
		nil,
		bytes.NewReader(payload),
	)
	zeroBytes(payload)
	if runErr != nil || result.ExitCode != 0 || result.Signaled ||
		result.StdoutTruncated || result.StderrTruncated ||
		!bytes.Equal(result.Stdout, []byte("OK\n")) || len(result.Stderr) != 0 {
		return c.failBrokerPeerBind(ctx, record, errors.New("hostruntime: broker peer bind failed"))
	}

	c.mu.Lock()
	if record.destroyed || !record.busy || record.bound {
		record.destroyed = true
		record.busy = false
		c.mu.Unlock()
		c.removeFailedAdapter(ctx, record)
		return errors.New("hostruntime: broker peer bind state lost")
	}
	record.busy = false
	record.bound = true
	c.mu.Unlock()
	return nil
}

func (c *DockerCLI) failBrokerPeerBind(ctx context.Context, record *adapterRecord, failure error) error {
	c.mu.Lock()
	record.destroyed = true
	record.busy = false
	c.mu.Unlock()
	c.removeFailedAdapter(ctx, record)
	return failure
}

func (c *DockerCLI) removeAdapterID(parent context.Context, id string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), cleanupTimeout)
	defer cancel()
	result, err := c.runner.Run(ctx, []string{c.cfg.DockerPath, "rm", "-f", id}, nil, nil)
	if err != nil || result.ExitCode != 0 || result.Signaled ||
		result.StdoutTruncated || result.StderrTruncated {
		return errors.New("hostruntime: adapter removal failed")
	}
	return nil
}
