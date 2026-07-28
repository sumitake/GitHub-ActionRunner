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

// AckState is the closed durable state of one message receipt.
type AckState uint8

const (
	AckPersisted AckState = iota + 1
	AckStarted
	AckRedeliveryProven
	AckConfirmed
)

// MessageReceipt is RecordMessageReceipt's bounded result. Digest is computed
// internally from the complete controller-owned message envelope; callers
// never supply it.
type MessageReceipt struct {
	Digest   [sha256.Size]byte
	State    AckState
	Inserted bool
}

// UncertainMessageReceipt is one protected ack_started receipt required at
// controller restart. The payload itself is never returned.
type UncertainMessageReceipt struct {
	RepositoryAlias string
	MessageID       int
	Digest          [sha256.Size]byte
	StartedAt       time.Time
}

// EffectState is the closed durable state of one idempotent external effect.
type EffectState uint8

const (
	EffectAbsent EffectState = iota + 1
	EffectPending
	EffectCompleted
	EffectFailed
)

// EffectRecord is the bounded, secret-free lookup result for one exact
// assignment/idempotency-key/kind tuple.
type EffectRecord struct {
	State          EffectState
	ResultIdentity string
	ReasonCode     string
}

// HistoryLimits contains every explicit durable-history and maintenance bound.
// Production configuration supplies all values; this package has no defaults.
type HistoryLimits struct {
	MinRetention                 time.Duration `json:"min_retention"`
	MaxHistoryRows               uint64        `json:"max_history_rows"`
	MaxHistoryLogicalBytes       uint64        `json:"max_history_logical_bytes"`
	MaxNetworkLedgerRows         uint64        `json:"max_network_ledger_rows"`
	MaxNetworkLedgerLogicalBytes uint64        `json:"max_network_ledger_logical_bytes"`
	InflightReserveRows          uint64        `json:"inflight_reserve_rows"`
	InflightReserveLogicalBytes  uint64        `json:"inflight_reserve_logical_bytes"`
	GCBatchRows                  uint64        `json:"gc_batch_rows"`
	NetworkGCBatchRows           uint64        `json:"network_gc_batch_rows"`
	VacuumBatchPages             uint64        `json:"vacuum_batch_pages"`
	MaintenanceCadence           time.Duration `json:"maintenance_cadence"`
}

// HistoryMaintenanceResult is the identity-free result of one bounded
// maintenance cycle. CheckpointBusy is observable and nonfatal: a later cycle
// retries without claiming that every WAL page was checkpointed.
type HistoryMaintenanceResult struct {
	ObservedAt              time.Time `json:"observed_at"`
	CompactedTerminalGraphs uint64    `json:"compacted_terminal_graphs"`
	DeletedMessageReceipts  uint64    `json:"deleted_message_receipts"`
	DeletedTombstones       uint64    `json:"deleted_tombstones"`
	DeletedNetworkLedgers   uint64    `json:"deleted_network_ledgers"`
	CheckpointBusy          bool      `json:"checkpoint_busy"`
	CheckpointLogPages      uint64    `json:"checkpoint_log_pages"`
	CheckpointedPages       uint64    `json:"checkpointed_pages"`
	VacuumedPages           uint64    `json:"vacuumed_pages"`
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
	ActivePageBytes           uint64
	FreelistBytes             uint64
	WALBytes                  uint64
	Maintenance               HistoryMaintenanceResult
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
	messageEnvelopeDomain    = "portable-ghar.message-envelope.v2"

	historyStringStructuralBytes = uint64(16)
	historySliceStructuralBytes  = uint64(24)
	historyOfferFixedBytes       = uint64(256)
	historyReceiptFixedBytes     = uint64(128 + sha256.Size)
	historyTombstoneFixedBytes   = uint64(160 + sha256.Size)
	historyRunnerSlotFixedBytes  = uint64(128)
	historyReservationFixedBytes = uint64(96)
	historyEffectFixedBytes      = uint64(160)

	maxEffectIdentityBytes = 4096
	maxEffectReasonBytes   = 128
	maxEffectKindBytes     = 128
	maxIdempotencyKeyBytes = 256
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

// CanonicalMessageEnvelopeDigest binds only fields delivered in the
// controller-owned upstream message projection. RepositoryAlias is an outer
// fleet namespace and is deliberately excluded, as are local clocks, policy,
// pressure, readiness, and routing state.
func CanonicalMessageEnvelopeDigest(envelope controller.MessageEnvelope) [sha256.Size]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(messageEnvelopeDomain))
	writeInt64(h, int64(envelope.MessageID))

	for _, value := range []int{
		envelope.Statistics.TotalAvailableJobs,
		envelope.Statistics.TotalAcquiredJobs,
		envelope.Statistics.TotalAssignedJobs,
		envelope.Statistics.TotalRunningJobs,
		envelope.Statistics.TotalRegisteredRunners,
		envelope.Statistics.TotalBusyRunners,
		envelope.Statistics.TotalIdleRunners,
	} {
		writeInt64(h, int64(value))
	}

	writeUint64(h, uint64(len(envelope.Offers)))
	for _, value := range envelope.Offers {
		writeLengthPrefixed(h, []byte("offer"))
		writeMessageJobRef(h, value.Job)
		writeLengthPrefixed(h, []byte(value.AcquireJobURL))
	}
	writeUint64(h, uint64(len(envelope.Assigned)))
	for _, value := range envelope.Assigned {
		writeLengthPrefixed(h, []byte("assigned"))
		writeMessageJobRef(h, value.Job)
	}
	writeUint64(h, uint64(len(envelope.Started)))
	for _, value := range envelope.Started {
		writeLengthPrefixed(h, []byte("started"))
		writeMessageJobRef(h, value.Job)
		writeInt64(h, value.RunnerID)
		writeLengthPrefixed(h, []byte(value.RunnerName))
	}
	writeUint64(h, uint64(len(envelope.Completed)))
	for _, value := range envelope.Completed {
		writeLengthPrefixed(h, []byte("completed"))
		writeMessageJobRef(h, value.Job)
		writeLengthPrefixed(h, []byte(value.Result))
		writeInt64(h, value.RunnerID)
		writeLengthPrefixed(h, []byte(value.RunnerName))
	}

	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

func writeMessageJobRef(
	h interface{ Write([]byte) (int, error) },
	ref controller.MessageJobRef,
) {
	writeInt64(h, ref.RunnerRequestID)
	for _, value := range []string{
		ref.JobID,
		ref.RepositoryName,
		ref.OwnerName,
		ref.JobWorkflowRef,
		ref.JobDisplayName,
	} {
		writeLengthPrefixed(h, []byte(value))
	}
	writeInt64(h, ref.WorkflowRunID)
	writeLengthPrefixed(h, []byte(ref.EventName))
	writeUint64(h, uint64(len(ref.RequestLabels)))
	for _, label := range ref.RequestLabels {
		writeLengthPrefixed(h, []byte(label))
	}
	for _, value := range []time.Time{
		ref.QueueTime,
		ref.ScaleSetAssignTime,
		ref.RunnerAssignTime,
		ref.FinishTime,
	} {
		writeCanonicalTime(h, value)
	}
}

func writeCanonicalTime(h interface{ Write([]byte) (int, error) }, value time.Time) {
	if value.IsZero() {
		_, _ = h.Write([]byte{0})
		return
	}
	_, _ = h.Write([]byte{1})
	value = value.UTC()
	writeInt64(h, value.Unix())
	writeInt64(h, int64(value.Nanosecond()))
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

// ValidateHistoryLimits rejects every zero, negative-duration, overflowing, or
// internally inconsistent durable-history envelope. Fleet-wide reserve
// multiplication is a runtime-configuration concern because concurrency is
// not state-owned.
func ValidateHistoryLimits(limits HistoryLimits) error {
	if limits.MinRetention <= 0 ||
		limits.MaintenanceCadence <= 0 ||
		limits.MaxHistoryRows == 0 ||
		limits.MaxHistoryLogicalBytes == 0 ||
		limits.MaxNetworkLedgerRows == 0 ||
		limits.MaxNetworkLedgerLogicalBytes == 0 ||
		limits.InflightReserveRows == 0 ||
		limits.InflightReserveLogicalBytes == 0 ||
		limits.GCBatchRows == 0 ||
		limits.NetworkGCBatchRows == 0 ||
		limits.VacuumBatchPages == 0 ||
		limits.VacuumBatchPages > math.MaxInt64 {
		return ErrHistoryBudget
	}
	for _, value := range []uint64{
		limits.MaxHistoryRows,
		limits.MaxHistoryLogicalBytes,
		limits.MaxNetworkLedgerRows,
		limits.MaxNetworkLedgerLogicalBytes,
		limits.InflightReserveRows,
		limits.InflightReserveLogicalBytes,
		limits.GCBatchRows,
		limits.NetworkGCBatchRows,
	} {
		if value > math.MaxInt64 {
			return ErrHistoryBudget
		}
	}
	if limits.InflightReserveRows > limits.MaxHistoryRows ||
		limits.InflightReserveLogicalBytes > limits.MaxHistoryLogicalBytes {
		return ErrHistoryBudget
	}
	return nil
}

func validateRecordLimits(limits HistoryLimits) error {
	return ValidateHistoryLimits(limits)
}

func validateOfferEvidence(offer OfferIdentity, evidence OfferEvidence) error {
	if evidence.ObservedAt.IsZero() {
		return ErrReplayEvidence
	}
	switch evidence.Kind {
	case EvidenceCurrentPoll:
		if evidence.MessageID <= 0 {
			return ErrReplayEvidence
		}
		// The authenticated Poll is the journal authority. QueueTime is
		// copied into the evidence tuple (including its zero value) so the
		// durable payload and observation cannot diverge, but freshness is a
		// later controller eligibility decision rather than an insert gate.
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
