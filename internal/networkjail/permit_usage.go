package networkjail

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

const permitUsageProofDomain = "portable-ghar.permit-usage-proof.v1\x00"
const permitUsageAuthorityDomain = "portable-ghar.permit-usage-authority.v1\x00"

type permitClassUsage struct {
	issued   bool
	number   uint64
	sequence PermitSequence
}

type permitUsageReceipt struct {
	generation         JobGeneration
	activationRevision uint64
	job                permitClassUsage
	doh                permitClassUsage
	sealed             [sha256.Size]byte
}

// PermitUsageProof is an opaque, read-only proof that both permit classes
// issued successfully for one exact active slot and generation. It is not a
// permit and grants no release or dialing authority.
type PermitUsageProof struct {
	digest             [sha256.Size]byte
	slot               CapacitySlotID
	generation         JobGeneration
	activationRevision uint64
	currentRevision    uint64
	valid              bool
}

func newPermitUsageReceipt(
	generation JobGeneration,
	activationRevision uint64,
) permitUsageReceipt {
	return permitUsageReceipt{
		generation:         generation,
		activationRevision: activationRevision,
	}
}

func (authority *PermitAuthority) recordPermitUsage(
	slot CapacitySlotID,
	generation JobGeneration,
	class DialClass,
	sequence PermitSequence,
	number uint64,
) {
	receipt, found := authority.usage[slot]
	if !found || receipt.generation != generation ||
		receipt.activationRevision == 0 || sequence == 0 || number == 0 {
		return
	}
	used := permitClassUsage{
		issued:   true,
		number:   number,
		sequence: sequence,
	}
	switch class {
	case DialClassJob:
		receipt.job = used
	case DialClassDoH:
		receipt.doh = used
	default:
		return
	}
	authority.usage[slot] = receipt
}

// AuditActiveUsage independently binds the live in-memory ledger, the
// durable reservation row, and successful current-process use of both permit
// classes. It never loads a missing in-memory ledger into existence.
func (authority *PermitAuthority) AuditActiveUsage(
	ctx context.Context,
	slot CapacitySlotID,
	generation JobGeneration,
) (PermitUsageProof, error) {
	if authority == nil || ctx == nil || ctx.Err() != nil ||
		slot == 0 || generation == 0 {
		return PermitUsageProof{}, ErrPermitUsageProofInvalid
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()

	receipt, found := authority.usage[slot]
	current, currentFound := authority.ledgers[slot]
	if !found || !currentFound ||
		receipt.generation != generation ||
		receipt.activationRevision == 0 ||
		!receipt.job.issued || !receipt.doh.issued ||
		receipt.job.number == 0 || receipt.job.sequence == 0 ||
		receipt.doh.number == 0 || receipt.doh.sequence == 0 ||
		validatePermitLedger(current, slot) != nil ||
		current.ActiveJobGeneration != generation ||
		current.Revision < receipt.activationRevision {
		return PermitUsageProof{}, ErrPermitUsageProofInvalid
	}

	durable, durableFound, err := authority.store.load(ctx, slot)
	if err != nil || !durableFound ||
		validatePermitLedger(durable, slot) != nil ||
		!samePermitUsageLedgerIdentity(current, durable) ||
		!permitUsageClassCovered(current.Job, durable.Job, receipt.job) ||
		!permitUsageClassCovered(current.DoH, durable.DoH, receipt.doh) {
		return PermitUsageProof{}, ErrPermitUsageProofInvalid
	}

	proof := sealPermitUsageProof(
		authority.graph.Digest(),
		current,
		receipt,
		durable,
	)
	if !proof.valid {
		return PermitUsageProof{}, ErrPermitUsageProofInvalid
	}
	if receipt.sealed != ([sha256.Size]byte{}) &&
		receipt.sealed != proof.digest {
		return PermitUsageProof{}, ErrPermitUsageProofInvalid
	}
	receipt.sealed = proof.digest
	authority.usage[slot] = receipt
	return proof, nil
}

func samePermitUsageLedgerIdentity(
	current permitLedger,
	durable permitLedger,
) bool {
	return current.Version == durable.Version &&
		current.Version == permitLedgerVersion &&
		current.SlotID == durable.SlotID &&
		current.BootID == durable.BootID &&
		current.ActiveJobGeneration == durable.ActiveJobGeneration &&
		current.Revision == durable.Revision
}

func permitUsageClassCovered(
	current permitClassLedger,
	durable permitClassLedger,
	receipt permitClassUsage,
) bool {
	return receipt.issued &&
		current.IssuedHighWater >= receipt.number &&
		current.IssuedSequence >= receipt.sequence &&
		durable.ReservedHighWater >= receipt.number &&
		durable.ReservedSequence >= receipt.sequence &&
		durable.ReservedHighWater == current.ReservedHighWater &&
		durable.ReservedSequence == current.ReservedSequence &&
		durable.IssuedHighWater <= current.IssuedHighWater &&
		durable.IssuedSequence <= current.IssuedSequence
}

func sealPermitUsageProof(
	graph Digest,
	current permitLedger,
	receipt permitUsageReceipt,
	durable permitLedger,
) PermitUsageProof {
	if graph == (Digest{}) || current.BootID == (BootID{}) ||
		current.SlotID == 0 || current.ActiveJobGeneration == 0 ||
		receipt.activationRevision == 0 || current.Revision == 0 {
		return PermitUsageProof{}
	}
	var preimage bytes.Buffer
	preimage.WriteString(permitUsageProofDomain)
	preimage.Write(graph[:])
	preimage.Write(current.BootID[:])
	writePermitUsageUint32(&preimage, uint32(current.SlotID))
	writePermitUsageUint64(
		&preimage,
		uint64(current.ActiveJobGeneration),
	)
	writePermitUsageUint64(&preimage, receipt.activationRevision)
	writePermitUsageUint64(&preimage, current.Revision)
	writePermitUsageClass(
		&preimage,
		DialClassJob,
		receipt.job,
		durable.Job,
	)
	writePermitUsageClass(
		&preimage,
		DialClassDoH,
		receipt.doh,
		durable.DoH,
	)
	return PermitUsageProof{
		digest:             sha256.Sum256(preimage.Bytes()),
		slot:               current.SlotID,
		generation:         current.ActiveJobGeneration,
		activationRevision: receipt.activationRevision,
		currentRevision:    current.Revision,
		valid:              true,
	}
}

func writePermitUsageClass(
	target *bytes.Buffer,
	class DialClass,
	receipt permitClassUsage,
	durable permitClassLedger,
) {
	target.WriteByte(byte(class))
	writePermitUsageUint64(target, receipt.number)
	writePermitUsageUint64(target, uint64(receipt.sequence))
	writePermitUsageUint64(target, durable.ReservedHighWater)
	writePermitUsageUint64(target, uint64(durable.ReservedSequence))
}

func writePermitUsageUint32(target *bytes.Buffer, value uint32) {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	target.Write(encoded[:])
}

func writePermitUsageUint64(target *bytes.Buffer, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	target.Write(encoded[:])
}

func (proof PermitUsageProof) Digest() string {
	if !proof.valid {
		return ""
	}
	return hex.EncodeToString(proof.digest[:])
}

func (proof PermitUsageProof) Matches(
	slot CapacitySlotID,
	generation JobGeneration,
) bool {
	return proof.valid && slot != 0 && generation != 0 &&
		proof.slot == slot && proof.generation == generation
}

// BindAuthority proves that the opaque broker authority proof was created for
// the exact activation revision that began this usage interval.
func (proof PermitUsageProof) BindAuthority(
	authority hostruntime.AuthorityProof,
) (string, error) {
	if !proof.valid ||
		!authority.MatchesPermitActivation(
			uint32(proof.slot),
			uint64(proof.generation),
			proof.activationRevision,
		) {
		return "", ErrPermitUsageProofInvalid
	}
	var preimage bytes.Buffer
	preimage.WriteString(permitUsageAuthorityDomain)
	preimage.Write(proof.digest[:])
	writePermitUsageUint32(&preimage, uint32(proof.slot))
	writePermitUsageUint64(&preimage, uint64(proof.generation))
	writePermitUsageUint64(&preimage, proof.activationRevision)
	writePermitUsageUint64(&preimage, proof.currentRevision)
	digest := sha256.Sum256(preimage.Bytes())
	return hex.EncodeToString(digest[:]), nil
}
