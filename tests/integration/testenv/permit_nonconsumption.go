package testenv

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sync"

	"github.com/sumitake/portable-ghar/internal/networkjail"
)

const permitNonconsumptionDomain = "portable-ghar.task11.permit-nonconsumption.v1\x00"

type permitUsageAuditSnapshot struct {
	Digest     string
	Slot       networkjail.CapacitySlotID
	Generation networkjail.JobGeneration
}

type permitUsageAuditSource interface {
	AuditActiveUsage(
		context.Context,
		networkjail.CapacitySlotID,
		networkjail.JobGeneration,
	) (permitUsageAuditSnapshot, error)
}

type permitAuthorityUsageAuditSource struct {
	authority *networkjail.PermitAuthority
}

func (s permitAuthorityUsageAuditSource) AuditActiveUsage(
	ctx context.Context,
	slot networkjail.CapacitySlotID,
	generation networkjail.JobGeneration,
) (permitUsageAuditSnapshot, error) {
	if s.authority == nil ||
		ctx == nil ||
		ctx.Err() != nil ||
		slot == 0 ||
		generation == 0 {
		return permitUsageAuditSnapshot{}, ErrFixtureStart
	}
	proof, err := s.authority.AuditActiveUsage(
		ctx,
		slot,
		generation,
	)
	if err != nil ||
		!proof.Matches(slot, generation) ||
		!isLowerHex(proof.Digest(), sha256.Size*2) {
		return permitUsageAuditSnapshot{}, ErrFixtureStart
	}
	return permitUsageAuditSnapshot{
		Digest:     proof.Digest(),
		Slot:       slot,
		Generation: generation,
	}, nil
}

type permitNonconsumptionInput struct {
	PreparedUsageDigest string
	RepeatedAuditDigest string
	PolicyDigest        string
	Slot                networkjail.CapacitySlotID
	Generation          networkjail.JobGeneration
	ClosedDenialsDigest string
}

type permitNonconsumptionProof struct {
	digest              [sha256.Size]byte
	preparedUsageDigest string
	policyDigest        string
	slot                networkjail.CapacitySlotID
	generation          networkjail.JobGeneration
	closedDenialsDigest string
	valid               bool
}

func (p permitNonconsumptionProof) Digest() string {
	if !p.valid {
		return ""
	}
	return hex.EncodeToString(p.digest[:])
}

func (p permitNonconsumptionProof) Matches(
	preparedUsageDigest string,
	policyDigest string,
	slot networkjail.CapacitySlotID,
	generation networkjail.JobGeneration,
	closedDenialsDigest string,
) bool {
	return p.valid &&
		isLowerHex(preparedUsageDigest, sha256.Size*2) &&
		isLowerHex(policyDigest, sha256.Size*2) &&
		slot != 0 &&
		generation != 0 &&
		isLowerHex(closedDenialsDigest, sha256.Size*2) &&
		p.preparedUsageDigest == preparedUsageDigest &&
		p.policyDigest == policyDigest &&
		p.slot == slot &&
		p.generation == generation &&
		p.closedDenialsDigest == closedDenialsDigest
}

func sealPermitNonconsumption(
	input permitNonconsumptionInput,
) (permitNonconsumptionProof, error) {
	if !isLowerHex(input.PreparedUsageDigest, sha256.Size*2) ||
		!isLowerHex(input.RepeatedAuditDigest, sha256.Size*2) ||
		input.PreparedUsageDigest != input.RepeatedAuditDigest ||
		!isLowerHex(input.PolicyDigest, sha256.Size*2) ||
		input.Slot == 0 ||
		input.Generation == 0 ||
		!isLowerHex(input.ClosedDenialsDigest, sha256.Size*2) {
		return permitNonconsumptionProof{}, ErrFixtureStart
	}
	prepared, preparedErr := decodePermitNonconsumptionDigest(
		input.PreparedUsageDigest,
	)
	repeated, repeatedErr := decodePermitNonconsumptionDigest(
		input.RepeatedAuditDigest,
	)
	policy, policyErr := decodePermitNonconsumptionDigest(
		input.PolicyDigest,
	)
	closedDenials, closedErr := decodePermitNonconsumptionDigest(
		input.ClosedDenialsDigest,
	)
	if preparedErr != nil ||
		repeatedErr != nil ||
		policyErr != nil ||
		closedErr != nil {
		return permitNonconsumptionProof{}, ErrFixtureStart
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(permitNonconsumptionDomain))
	_, _ = hash.Write(prepared[:])
	_, _ = hash.Write(repeated[:])
	_, _ = hash.Write(policy[:])
	_ = binary.Write(hash, binary.BigEndian, uint32(input.Slot))
	_ = binary.Write(hash, binary.BigEndian, uint64(input.Generation))
	_, _ = hash.Write(closedDenials[:])
	var sealed [sha256.Size]byte
	copy(sealed[:], hash.Sum(nil))
	proof := permitNonconsumptionProof{
		digest:              sealed,
		preparedUsageDigest: input.PreparedUsageDigest,
		policyDigest:        input.PolicyDigest,
		slot:                input.Slot,
		generation:          input.Generation,
		closedDenialsDigest: input.ClosedDenialsDigest,
		valid:               true,
	}
	if proof.Digest() == "" {
		return permitNonconsumptionProof{}, ErrFixtureStart
	}
	return proof, nil
}

func decodePermitNonconsumptionDigest(
	value string,
) ([sha256.Size]byte, error) {
	var decoded [sha256.Size]byte
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != len(decoded) {
		return decoded, ErrFixtureStart
	}
	copy(decoded[:], raw)
	for index := range raw {
		raw[index] = 0
	}
	return decoded, nil
}

type permitNonconsumptionTracker struct {
	mu sync.Mutex

	preparedUsageDigest string
	slot                networkjail.CapacitySlotID
	generation          networkjail.JobGeneration
	attempted           bool
	proof               permitNonconsumptionProof
}

func newPermitNonconsumptionTracker(
	preparedUsageDigest string,
	slot networkjail.CapacitySlotID,
	generation networkjail.JobGeneration,
) (*permitNonconsumptionTracker, error) {
	if !isLowerHex(preparedUsageDigest, sha256.Size*2) ||
		slot == 0 ||
		generation == 0 {
		return nil, ErrFixtureStart
	}
	return &permitNonconsumptionTracker{
		preparedUsageDigest: preparedUsageDigest,
		slot:                slot,
		generation:          generation,
	}, nil
}

func (t *permitNonconsumptionTracker) PreparedUsageDigest() string {
	if t == nil {
		return ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.preparedUsageDigest
}

func (t *permitNonconsumptionTracker) Prove(
	ctx context.Context,
	source permitUsageAuditSource,
	policyDigest string,
	closedDenialsDigest string,
) (permitNonconsumptionProof, error) {
	if t == nil ||
		ctx == nil ||
		ctx.Err() != nil ||
		source == nil ||
		!isLowerHex(policyDigest, sha256.Size*2) ||
		!isLowerHex(closedDenialsDigest, sha256.Size*2) {
		return permitNonconsumptionProof{}, ErrFixtureStart
	}
	t.mu.Lock()
	if t.attempted ||
		t.proof.valid ||
		!isLowerHex(t.preparedUsageDigest, sha256.Size*2) ||
		t.slot == 0 ||
		t.generation == 0 {
		t.mu.Unlock()
		return permitNonconsumptionProof{}, ErrFixtureStart
	}
	t.attempted = true
	prepared := t.preparedUsageDigest
	slot := t.slot
	generation := t.generation
	t.mu.Unlock()

	repeated, err := source.AuditActiveUsage(
		ctx,
		slot,
		generation,
	)
	if err != nil ||
		repeated.Digest != prepared ||
		repeated.Slot != slot ||
		repeated.Generation != generation {
		return permitNonconsumptionProof{}, ErrFixtureStart
	}
	proof, err := sealPermitNonconsumption(
		permitNonconsumptionInput{
			PreparedUsageDigest: prepared,
			RepeatedAuditDigest: repeated.Digest,
			PolicyDigest:        policyDigest,
			Slot:                slot,
			Generation:          generation,
			ClosedDenialsDigest: closedDenialsDigest,
		},
	)
	if err != nil {
		return permitNonconsumptionProof{}, ErrFixtureStart
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.proof.valid ||
		t.preparedUsageDigest != prepared ||
		t.slot != slot ||
		t.generation != generation {
		return permitNonconsumptionProof{}, ErrFixtureStart
	}
	t.proof = proof
	return proof, nil
}
