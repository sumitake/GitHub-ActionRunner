package networkjail

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

type PermitPeer struct {
	pid       int
	uid       uint32
	startTime uint64
}

func newPermitPeer(pid int, uid uint32, startTime uint64) PermitPeer {
	return PermitPeer{pid: pid, uid: uid, startTime: startTime}
}

func (peer PermitPeer) PID() int          { return peer.pid }
func (peer PermitPeer) UID() uint32       { return peer.uid }
func (peer PermitPeer) StartTime() uint64 { return peer.startTime }

func (peer PermitPeer) valid() bool {
	return peer.pid > 0 && peer.startTime > 0
}

type PermitPeerValidator interface {
	ValidatePermitPeer(
		context.Context,
		CapacitySlotID,
		JobGeneration,
		DialClass,
		PermitPeer,
	) error
}

type LedgerReferenceGuard interface {
	HasLedgerReferences(context.Context, CapacitySlotID) (bool, error)
}

type EmptyConntrackProof struct {
	tag [sha256.Size]byte
}

type EmptyConntrackValidator interface {
	ValidateEmptyConntrack(
		context.Context,
		CapacitySlotID,
		BootID,
		BootID,
		EmptyConntrackProof,
	) error
}

func newEmptyConntrackProof(
	key [sha256.Size]byte,
	slot CapacitySlotID,
	from BootID,
	to BootID,
) EmptyConntrackProof {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("portable-ghar.empty-conntrack-proof.v1\x00"))
	var slotBytes [4]byte
	binary.BigEndian.PutUint32(slotBytes[:], uint32(slot))
	_, _ = mac.Write(slotBytes[:])
	_, _ = mac.Write(from[:])
	_, _ = mac.Write(to[:])
	var proof EmptyConntrackProof
	copy(proof.tag[:], mac.Sum(nil))
	return proof
}
