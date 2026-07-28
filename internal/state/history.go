package state

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
)

// OfferDisposition classifies a durable offer insert or replay.
type OfferDisposition uint8

const (
	OfferInserted OfferDisposition = iota + 1
	OfferActiveReplay
	OfferTerminalReplay
)

// OfferEvidenceKind identifies the authenticated source used to admit an
// identity that is absent from durable history.
type OfferEvidenceKind uint8

const (
	EvidenceCurrentPoll OfferEvidenceKind = iota + 1
	EvidenceSelectiveReadback
)

// OfferEvidence is the bounded, secret-free evidence attached to RecordOffer.
type OfferEvidence struct {
	Kind       OfferEvidenceKind
	MessageID  int
	QueueTime  time.Time
	ObservedAt time.Time
}

// OfferReceipt is RecordOffer's exact durable classification.
type OfferReceipt struct {
	Key         controllerAssignmentKey
	Disposition OfferDisposition
	State       controllerState
}

// HistoryLimits contains every explicit durable-history and maintenance bound.
// Production configuration supplies all values; this package has no defaults.
type HistoryLimits struct {
	MinRetention                 time.Duration
	MaxHistoryRows               uint64
	MaxHistoryLogicalBytes       uint64
	MaxNetworkLedgerRows         uint64
	MaxNetworkLedgerLogicalBytes uint64
	InflightReserveRows          uint64
	InflightReserveLogicalBytes  uint64
	GCBatchRows                  uint64
	NetworkGCBatchRows           uint64
	VacuumBatchPages             uint64
	MaintenanceCadence           time.Duration
}

// HistoryUsage is an aggregate, identity-free history/storage snapshot.
type HistoryUsage struct {
	LiveRows                  uint64
	LiveLogicalBytes          uint64
	ProtectedTerminalRows     uint64
	ProtectedTerminalBytes    uint64
	MessageReceiptRows        uint64
	MessageReceiptBytes       uint64
	TombstoneRows             uint64
	TombstoneLogicalBytes     uint64
	NetworkLedgerRows         uint64
	NetworkLedgerLogicalBytes uint64
	InflightAssignments       uint64
	ReservedRows              uint64
	ReservedLogicalBytes      uint64
	OldestRetainedAt          time.Time
}

// AdmissionPhase is the durable, state-owned representation of the broker's
// queued/reserved/active live phases. Keeping the projection in state avoids a
// persistence-to-scheduler package cycle; the controller converts it at the
// Restore boundary.
type AdmissionPhase uint8

const (
	AdmissionQueued AdmissionPhase = iota + 1
	AdmissionReserved
	AdmissionActive
)

// ResourceProjection is the exact persisted nine-dimensional slot charge.
type ResourceProjection struct {
	MilliCPU          int64
	MemoryBytes       int64
	PIDs              int64
	FileDescriptors   int64
	TmpfsBytes        int64
	ScratchBytes      int64
	SocketStateBytes  int64
	DurableStateBytes int64
	Inodes            int64
}

// AdmissionProjection is the secret-free broker state required at restart.
type AdmissionProjection struct {
	Valid           bool
	Phase           AdmissionPhase
	SlotID          uint32
	FullCharge      ResourceProjection
	LedgerCharge    ResourceProjection
	LedgerCreatedAt time.Time
	LedgerEverUsed  bool
}

var (
	ErrIdentityConflict = errors.New("state: durable identity conflict")
	ErrHistoryBudget    = errors.New("state: history budget unavailable")
	ErrReplayEvidence   = errors.New("state: replay evidence unavailable")
	ErrAckUncertain     = errors.New("state: message acknowledgement is uncertain")
	ErrAckConfirmed     = errors.New("state: message acknowledgement is already confirmed")
	ErrOfflineMigration = errors.New("state: offline database migration required")
)

const (
	offerDigestDomain        = "portable-ghar.offer.v1"
	offerPayloadDigestDomain = "portable-ghar.offer-payload.v1"
	messageDigestDomain      = "portable-ghar.message.v1"

	historyStringStructuralBytes = uint64(16)
	historySliceStructuralBytes  = uint64(24)
	historyOfferFixedBytes       = uint64(256)
	historyReceiptFixedBytes     = uint64(128 + sha256.Size)
	historyTombstoneFixedBytes   = uint64(160 + sha256.Size)
	historyRunnerSlotFixedBytes  = uint64(128)
	historyReservationFixedBytes = uint64(96)
	historyEffectFixedBytes      = uint64(160)
)

// Small aliases keep this file's public type declarations readable without
// weakening Store's existing controller-domain ownership.
type controllerAssignmentKey = controller.AssignmentKey
type controllerState = controller.State

// CanonicalOfferDigest uses a versioned, domain-separated, length-prefixed
// binary encoding. It intentionally excludes mutable display metadata: the
// durable offer identity is repository alias + runner request + workflow job.
func CanonicalOfferDigest(offer OfferIdentity) [sha256.Size]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(offerDigestDomain))
	writeLengthPrefixed(h, []byte(offer.RepositoryAlias))
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], uint64(offer.RunnerRequestID))
	_, _ = h.Write(scalar[:])
	binary.BigEndian.PutUint64(scalar[:], uint64(offer.WorkflowJobID))
	_, _ = h.Write(scalar[:])
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// CanonicalOfferPayloadDigest binds every persisted, secret-free offer field.
// The separate identity digest remains stable and follows its fixed three-field
// contract; this payload digest is the durable authority that distinguishes an
// equal replay from the same key carrying changed labels or metadata.
func CanonicalOfferPayloadDigest(offer OfferIdentity) [sha256.Size]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(offerPayloadDigestDomain))
	for _, value := range []string{
		offer.RepositoryAlias,
		offer.JobID,
		offer.RepositoryName,
		offer.OwnerName,
		offer.JobWorkflowRef,
		offer.JobDisplayName,
		offer.EventName,
		offer.AcquireJobURL,
	} {
		writeLengthPrefixed(h, []byte(value))
	}
	writeInt64(h, offer.RunnerRequestID)
	writeInt64(h, offer.WorkflowJobID)
	writeInt64(h, offer.WorkflowRunID)
	writeUint64(h, uint64(len(offer.RequestLabels)))
	for _, label := range offer.RequestLabels {
		writeLengthPrefixed(h, []byte(label))
	}
	for _, value := range []time.Time{
		offer.QueueTime,
		offer.ScaleSetAssignTime,
		offer.RunnerAssignTime,
		offer.FinishTime,
	} {
		text := ""
		if !value.IsZero() {
			text = value.UTC().Format(time.RFC3339Nano)
		}
		writeLengthPrefixed(h, []byte(text))
	}
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

func writeLengthPrefixed(h interface{ Write([]byte) (int, error) }, value []byte) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	_, _ = h.Write(size[:])
	_, _ = h.Write(value)
}

func writeInt64(h interface{ Write([]byte) (int, error) }, value int64) {
	writeUint64(h, uint64(value))
}

func writeUint64(h interface{ Write([]byte) (int, error) }, value uint64) {
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], value)
	_, _ = h.Write(scalar[:])
}

func canonicalMessageDigest(repositoryAlias string, messageID int, offerDigests [][]byte) [sha256.Size]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(messageDigestDomain))
	writeLengthPrefixed(h, []byte(repositoryAlias))
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], uint64(int64(messageID)))
	_, _ = h.Write(scalar[:])
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(offerDigests)))
	_, _ = h.Write(count[:])
	for _, digest := range offerDigests {
		writeLengthPrefixed(h, digest)
	}
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

func offerLogicalBytesV1(offer OfferIdentity) (uint64, error) {
	total := historyOfferFixedBytes + historySliceStructuralBytes
	values := [...]string{
		offer.RepositoryAlias,
		offer.JobID,
		offer.RepositoryName,
		offer.OwnerName,
		offer.JobWorkflowRef,
		offer.JobDisplayName,
		offer.EventName,
		offer.AcquireJobURL,
	}
	for _, value := range values {
		var err error
		total, err = addHistoryBytes(total, historyStringStructuralBytes, uint64(len(value)))
		if err != nil {
			return 0, err
		}
	}
	for _, label := range offer.RequestLabels {
		var err error
		total, err = addHistoryBytes(total, historyStringStructuralBytes, uint64(len(label)))
		if err != nil {
			return 0, err
		}
	}
	return total, nil
}

func tombstoneLogicalBytes(repositoryAlias string) (uint64, error) {
	return addHistoryBytes(historyTombstoneFixedBytes, uint64(len(repositoryAlias)))
}

func receiptLogicalBytes(repositoryAlias string) (uint64, error) {
	return addHistoryBytes(historyReceiptFixedBytes, uint64(len(repositoryAlias)))
}

func addHistoryBytes(total uint64, values ...uint64) (uint64, error) {
	for _, value := range values {
		if value > math.MaxUint64-total {
			return 0, ErrHistoryBudget
		}
		total += value
	}
	return total, nil
}

func multiplyHistoryBytes(value, count uint64) (uint64, error) {
	if value != 0 && count > math.MaxUint64/value {
		return 0, ErrHistoryBudget
	}
	return value * count, nil
}

func validateRecordLimits(limits HistoryLimits) error {
	if limits.MaxHistoryRows == 0 ||
		limits.MaxHistoryLogicalBytes == 0 ||
		limits.InflightReserveRows == 0 ||
		limits.InflightReserveLogicalBytes == 0 {
		return ErrHistoryBudget
	}
	if limits.InflightReserveRows > limits.MaxHistoryRows ||
		limits.InflightReserveLogicalBytes > limits.MaxHistoryLogicalBytes {
		return ErrHistoryBudget
	}
	return nil
}

func validateOfferEvidence(offer OfferIdentity, evidence OfferEvidence) error {
	if evidence.ObservedAt.IsZero() {
		return ErrReplayEvidence
	}
	switch evidence.Kind {
	case EvidenceCurrentPoll:
		if evidence.MessageID <= 0 || evidence.QueueTime.IsZero() || offer.QueueTime.IsZero() {
			return ErrReplayEvidence
		}
		if !evidence.QueueTime.Equal(offer.QueueTime) {
			return ErrReplayEvidence
		}
	case EvidenceSelectiveReadback:
		// Selective read-back is authenticated by the injected verifier in the
		// controller. The store requires only a positive observation time and
		// records any associated message ID when one exists.
	default:
		return ErrReplayEvidence
	}
	return nil
}
