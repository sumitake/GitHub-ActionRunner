package networkjail

import (
	"bytes"
	"context"
	"io"
	"math"
	"os"
	"strconv"
	"strings"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/state"
)

const maximumPermitProcDocumentBytes = int64(64 << 10)

// PermitPeerProcess is a process identity read from /proc.
type PermitPeerProcess struct {
	UID       uint32
	StartTime uint64
}

type boundedProcReader func(path string, maximum int64) ([]byte, error)

// ObservePermitPeerProcess reads /proc/<pid> twice and returns the identity
// only when both reads agree, so a process that exits or is replaced between
// reads is rejected. It fails closed where /proc is unavailable.
func ObservePermitPeerProcess(ctx context.Context, pid int) (PermitPeerProcess, error) {
	return observePermitPeerProcess(ctx, pid, readBoundedProcFile)
}

func observePermitPeerProcess(
	ctx context.Context,
	pid int,
	readFile boundedProcReader,
) (PermitPeerProcess, error) {
	if ctx == nil || ctx.Err() != nil || pid <= 0 || readFile == nil {
		return PermitPeerProcess{}, ErrPermitPeerInvalid
	}
	base := "/proc/" + strconv.Itoa(pid)
	first, err := observePermitPeerProcessOnce(ctx, base, readFile)
	if err != nil {
		return PermitPeerProcess{}, ErrPermitPeerInvalid
	}
	second, err := observePermitPeerProcessOnce(ctx, base, readFile)
	if err != nil || first != second {
		return PermitPeerProcess{}, ErrPermitPeerInvalid
	}
	return second, nil
}

func observePermitPeerProcessOnce(
	ctx context.Context,
	base string,
	readFile boundedProcReader,
) (PermitPeerProcess, error) {
	status, err := readFile(base+"/status", maximumPermitProcDocumentBytes)
	if err != nil || ctx.Err() != nil {
		zeroPermitProcDocument(status)
		return PermitPeerProcess{}, ErrPermitPeerInvalid
	}
	uid, ok := parsePermitProcStatusUID(status)
	zeroPermitProcDocument(status)
	if !ok {
		return PermitPeerProcess{}, ErrPermitPeerInvalid
	}
	stat, err := readFile(base+"/stat", maximumPermitProcDocumentBytes)
	if err != nil || ctx.Err() != nil {
		zeroPermitProcDocument(stat)
		return PermitPeerProcess{}, ErrPermitPeerInvalid
	}
	startTime, err := parsePermitProcStatStartTime(stat)
	zeroPermitProcDocument(stat)
	if err != nil {
		return PermitPeerProcess{}, ErrPermitPeerInvalid
	}
	return PermitPeerProcess{UID: uid, StartTime: startTime}, nil
}

func readBoundedProcFile(path string, maximum int64) ([]byte, error) {
	if path == "" || maximum <= 0 || maximum == math.MaxInt64 {
		return nil, ErrPermitPeerInvalid
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrPermitPeerInvalid
	}
	defer file.Close()
	document, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(document) == 0 || int64(len(document)) > maximum {
		zeroPermitProcDocument(document)
		return nil, ErrPermitPeerInvalid
	}
	return document, nil
}

// parsePermitProcStatusUID returns the UID only when the single Uid line
// carries four identical, canonical values (real, effective, saved, fs).
func parsePermitProcStatusUID(document []byte) (uint32, bool) {
	if len(document) == 0 ||
		len(document) > int(maximumPermitProcDocumentBytes) ||
		document[len(document)-1] != '\n' ||
		bytes.IndexByte(document, 0) >= 0 ||
		bytes.IndexByte(document, '\r') >= 0 {
		return 0, false
	}
	var (
		uid   uint64
		found bool
	)
	for _, line := range strings.Split(string(document[:len(document)-1]), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		if found || !strings.HasPrefix(line, "Uid:\t") {
			return 0, false
		}
		fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
		if len(fields) != 4 {
			return 0, false
		}
		for index, field := range fields {
			value, err := strconv.ParseUint(field, 10, 32)
			if err != nil || strconv.FormatUint(value, 10) != field {
				return 0, false
			}
			if index == 0 {
				uid = value
			} else if value != uid {
				return 0, false
			}
		}
		found = true
	}
	return uint32(uid), found
}

func parsePermitProcStatStartTime(document []byte) (uint64, error) {
	if len(document) == 0 ||
		len(document) > int(maximumPermitProcDocumentBytes) ||
		document[len(document)-1] != '\n' ||
		bytes.Count(document, []byte{'\n'}) != 1 ||
		bytes.IndexByte(document, 0) >= 0 ||
		bytes.IndexByte(document, '\r') >= 0 {
		return 0, ErrPermitPeerInvalid
	}
	startTime, err := hostruntime.ParseLinuxProcStatStartTime(document[:len(document)-1])
	if err != nil {
		return 0, ErrPermitPeerInvalid
	}
	return startTime, nil
}

func zeroPermitProcDocument(document []byte) {
	for index := range document {
		document[index] = 0
	}
}

// ProcPermitPeerValidator is the production PermitPeerValidator. One instance
// serves every slot: it checks the dial class, that the peer runs as the
// broker user, and that /proc still shows that process with the start time
// read at accept. It does not check the slot or generation; the per-slot
// socket server binds each frame to its own slot and generation, and every
// broker shares one user.
type ProcPermitPeerValidator struct {
	brokerUID uint32
	readFile  boundedProcReader
}

func NewProcPermitPeerValidator(brokerUID uint32) (*ProcPermitPeerValidator, error) {
	if brokerUID == 0 {
		return nil, ErrPermitPeerInvalid
	}
	return &ProcPermitPeerValidator{brokerUID: brokerUID, readFile: readBoundedProcFile}, nil
}

func (validator *ProcPermitPeerValidator) ValidatePermitPeer(
	ctx context.Context,
	_ CapacitySlotID,
	_ JobGeneration,
	class DialClass,
	peer PermitPeer,
) error {
	if validator == nil || validator.brokerUID == 0 ||
		(class != DialClassJob && class != DialClassDoH) ||
		!peer.valid() || peer.UID() != validator.brokerUID {
		return ErrPermitPeerInvalid
	}
	observed, err := observePermitPeerProcess(ctx, peer.PID(), validator.readFile)
	if err != nil ||
		observed.UID != validator.brokerUID ||
		observed.StartTime != peer.StartTime() {
		return ErrPermitPeerInvalid
	}
	return nil
}

// RecoverableLister is the part of the controller store the reference guard
// reads.
type RecoverableLister interface {
	ListRecoverable(context.Context) ([]state.RecoverableAssignment, error)
}

// StateLedgerReferenceGuard reports a slot as referenced while any
// recoverable assignment (any state but destroyed) holds it, either as its
// runner slot or, before the runner slot exists, as its admission
// reservation. The permit ledger for that slot is then never collected under
// a live job. Store errors, and an assignment whose two slot identities
// disagree, fail closed.
//
// The answer is a snapshot of the store. PermitAuthority.Collect deletes on
// it, so whatever calls Collect must keep admission from reserving the slot
// until the delete completes. Nothing in production calls Collect yet.
type StateLedgerReferenceGuard struct {
	store RecoverableLister
}

func NewStateLedgerReferenceGuard(store RecoverableLister) (*StateLedgerReferenceGuard, error) {
	if store == nil {
		return nil, ErrPermitAuthorityUnavailable
	}
	return &StateLedgerReferenceGuard{store: store}, nil
}

func (guard *StateLedgerReferenceGuard) HasLedgerReferences(
	ctx context.Context,
	slot CapacitySlotID,
) (bool, error) {
	if guard == nil || guard.store == nil || ctx == nil || ctx.Err() != nil || slot == 0 {
		return false, ErrPermitAuthorityUnavailable
	}
	recoverable, err := guard.store.ListRecoverable(ctx)
	if err != nil {
		return false, ErrPermitAuthorityUnavailable
	}
	referenced := false
	for _, assignment := range recoverable {
		runnerSlot := CapacitySlotID(assignment.Slot.CapacitySlotID)
		admissionSlot := CapacitySlotID(0)
		if assignment.Admission.Valid {
			admissionSlot = CapacitySlotID(assignment.Admission.SlotID)
		}
		if runnerSlot != 0 && admissionSlot != 0 && runnerSlot != admissionSlot {
			return false, ErrPermitAuthorityUnavailable
		}
		if runnerSlot == slot || admissionSlot == slot {
			referenced = true
		}
	}
	return referenced, nil
}

// RejectEmptyConntrackRebase refuses every rebase proof. Production has no
// way to prove an empty conntrack table across a reboot, so a slot whose
// ledger needs a rebase stays blocked until an operator clears it.
type RejectEmptyConntrackRebase struct{}

func (RejectEmptyConntrackRebase) ValidateEmptyConntrack(
	context.Context,
	CapacitySlotID,
	BootID,
	BootID,
	EmptyConntrackProof,
) error {
	return ErrEmptyConntrackProofInvalid
}

var (
	_ PermitPeerValidator     = (*ProcPermitPeerValidator)(nil)
	_ LedgerReferenceGuard    = (*StateLedgerReferenceGuard)(nil)
	_ EmptyConntrackValidator = RejectEmptyConntrackRebase{}
)
