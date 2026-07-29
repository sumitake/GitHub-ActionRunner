package hostruntime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/sumitake/portable-ghar/internal/fleetfence"
)

const (
	maxLifecycleJournalBytes       = 1 << 20
	maxLifecycleReceiptBytes       = 1 << 16
	maxLifecyclePostconditionBytes = 4 << 20
	maxLifecycleReservationBytes   = 4 << 20
)

var (
	ErrLifecycleExecution   = errors.New("hostruntime: lifecycle execution failed")
	ErrLifecycleRecoverable = errors.New("hostruntime: lifecycle execution recoverable")
)

const (
	LifecycleErrorInvalidRequest    = "invalid-request"
	LifecycleErrorIntegrity         = "integrity-failure"
	LifecycleErrorStorageEnvelope   = "storage-envelope"
	LifecycleErrorAmbiguousEffect   = "ambiguous-effect"
	LifecycleErrorEffectFailed      = "effect-failed"
	LifecycleErrorTerminalMismatch  = "terminal-mismatch"
	LifecycleErrorContextCancelled  = "context-cancelled"
	LifecycleErrorCompensationProof = "compensation-proof"
)

type LifecycleEffectState string

const (
	LifecycleEffectAbsent    LifecycleEffectState = "absent"
	LifecycleEffectPresent   LifecycleEffectState = "present"
	LifecycleEffectAmbiguous LifecycleEffectState = "ambiguous"
)

// LifecycleEffectObservation is a closed readback result. Present always
// carries a canonical, binding-scoped target proof. Absent and ambiguous never
// carry target data.
type LifecycleEffectObservation struct {
	State         LifecycleEffectState
	Postcondition *TargetPostcondition
}

// LifecycleEffectAuthority is deliberately phase-scoped. It cannot receive a
// command, argv, environment, path, stdin, or arbitrary operation name.
// Implementations must make Apply idempotent for the binding-derived effect
// key and must derive Observe from target readback rather than local history.
type LifecycleEffectAuthority interface {
	Observe(
		context.Context,
		OperationBinding,
		OperationPhase,
	) (LifecycleEffectObservation, error)
	Apply(
		context.Context,
		OperationBinding,
		OperationPhase,
	) (TargetPostcondition, error)
}

// LifecycleStorageAuthority revalidates the complete, already-bound storage
// reservation. It cannot invent or resize a reservation during execution.
type LifecycleStorageAuthority interface {
	Revalidate(context.Context, StorageReservation) error
}

// LifecycleCompensationAuthority evaluates the closed path predicates against
// one fresh source postcondition. Its authorization is opaque outside this
// package, so callers cannot synthesize a path or source anchor.
type LifecycleCompensationAuthority interface {
	AuthorizeCompensation(
		context.Context,
		OperationBinding,
		OperationJournal,
		TargetPostcondition,
	) (CompensationAuthorization, error)
}

type CompensationAuthorization struct {
	path                CompensationPath
	sourcePhase         OperationPhase
	sourceProofDigest   string
	sourceReceiptDigest string
}

type LifecycleRequest struct {
	Binding        OperationBinding
	PriorManifest  *RuntimeManifest
	TargetManifest *RuntimeManifest
	Reservation    StorageReservation
}

type LifecycleEngine struct {
	Store        *LifecycleStore
	Effects      LifecycleEffectAuthority
	Storage      LifecycleStorageAuthority
	Compensation LifecycleCompensationAuthority
	PollInterval time.Duration
	Now          func() time.Time
}

type lifecyclePrepared struct {
	journal             OperationJournal
	journalDocument     []byte
	journalDigest       string
	reservation         StorageReservation
	reservationDocument []byte
}

type lifecycleEngineError struct {
	class       string
	recoverable bool
	cause       error
}

func (err *lifecycleEngineError) Error() string {
	return "hostruntime: " + err.class
}

func (err *lifecycleEngineError) Unwrap() error {
	return err.cause
}

func (engine LifecycleEngine) Execute(
	ctx context.Context,
	request LifecycleRequest,
) (HostActionResult, error) {
	if ctx == nil ||
		engine.Store == nil ||
		engine.Effects == nil ||
		engine.Storage == nil ||
		engine.PollInterval <= 0 ||
		engine.PollInterval > time.Second {
		return lifecycleFailureResult(request.Binding, LifecycleErrorInvalidRequest),
			ErrLifecycleExecution
	}
	if err := validateLifecycleRequest(request); err != nil {
		return lifecycleFailureResult(request.Binding, LifecycleErrorInvalidRequest),
			ErrLifecycleExecution
	}

	lease, err := engine.Store.Acquire(ctx, engine.PollInterval)
	if err != nil {
		return engine.resultForError(
			request.Binding,
			nil,
			classifyLifecycleError(err),
		), lifecyclePublicError(err)
	}
	defer lease.Close()
	if err := lease.Validate(); err != nil {
		return engine.resultForError(
			request.Binding,
			nil,
			integrityLifecycleError(err),
		), ErrLifecycleExecution
	}

	prepared, err := engine.prepareLocked(ctx, request)
	if err != nil {
		return engine.resultForError(
			request.Binding,
			prepared,
			classifyLifecycleError(err),
		), lifecyclePublicError(err)
	}
	return engine.driveLocked(ctx, request, prepared, lease)
}

// Recover either resumes an already-persisted compensation path or selects
// one path exactly once through the opaque compensation authority. It never
// changes the operation binding, manifest, storage vector, or effect keys.
func (engine LifecycleEngine) Recover(
	ctx context.Context,
	request LifecycleRequest,
) (HostActionResult, error) {
	if ctx == nil ||
		engine.Store == nil ||
		engine.Effects == nil ||
		engine.Storage == nil ||
		engine.Compensation == nil ||
		engine.PollInterval <= 0 ||
		engine.PollInterval > time.Second ||
		validateLifecycleRequest(request) != nil {
		return lifecycleFailureResult(request.Binding, LifecycleErrorInvalidRequest),
			ErrLifecycleExecution
	}
	lease, err := engine.Store.Acquire(ctx, engine.PollInterval)
	if err != nil {
		classified := classifyLifecycleError(err)
		return engine.resultForError(
			request.Binding,
			nil,
			classified,
		), lifecyclePublicError(classified)
	}
	defer lease.Close()
	prepared, err := engine.prepareLocked(ctx, request)
	if err != nil {
		classified := classifyLifecycleError(err)
		return engine.resultForError(
			request.Binding,
			prepared,
			classified,
		), lifecyclePublicError(classified)
	}
	if prepared.journal.CompensationPath == nil {
		source, err := engine.ensurePhaseApplied(ctx, request, prepared)
		if err != nil {
			classified := classifyLifecycleError(err)
			return engine.resultForError(
				request.Binding,
				prepared,
				classified,
			), lifecyclePublicError(classified)
		}
		fresh, err := engine.Effects.Observe(
			ctx,
			request.Binding,
			prepared.journal.Phase,
		)
		if err != nil ||
			validateLifecycleObservation(
				fresh,
				request.Binding,
				prepared.journal.Phase,
			) != nil ||
			fresh.State != LifecycleEffectPresent ||
			!sameTargetState(source, *fresh.Postcondition) {
			classified := recoverableLifecycleError(
				LifecycleErrorCompensationProof,
				err,
			)
			return engine.resultForError(
				request.Binding,
				prepared,
				classified,
			), ErrLifecycleRecoverable
		}
		authorization, err := engine.Compensation.AuthorizeCompensation(
			ctx,
			request.Binding,
			prepared.journal,
			*fresh.Postcondition,
		)
		if err != nil ||
			engine.validateCompensationAuthorization(
				request.Binding,
				prepared.journal,
				source,
				authorization,
			) != nil {
			classified := recoverableLifecycleError(
				LifecycleErrorCompensationProof,
				err,
			)
			return engine.resultForError(
				request.Binding,
				prepared,
				classified,
			), ErrLifecycleRecoverable
		}
		if err := engine.persistCompensationPivot(
			request.Binding,
			prepared,
			authorization,
		); err != nil {
			classified := classifyLifecycleError(err)
			return engine.resultForError(
				request.Binding,
				prepared,
				classified,
			), lifecyclePublicError(classified)
		}
	}
	return engine.driveLocked(ctx, request, prepared, lease)
}

func (engine LifecycleEngine) driveLocked(
	ctx context.Context,
	request LifecycleRequest,
	prepared *lifecyclePrepared,
	lease *LifecycleLease,
) (HostActionResult, error) {
	for {
		if err := ctx.Err(); err != nil {
			engineErr := recoverableLifecycleError(
				LifecycleErrorContextCancelled,
				err,
			)
			return engine.resultForError(
				request.Binding,
				prepared,
				engineErr,
			), ErrLifecycleRecoverable
		}
		if err := lease.Validate(); err != nil {
			return engine.resultForError(
				request.Binding,
				prepared,
				integrityLifecycleError(err),
			), ErrLifecycleExecution
		}
		postcondition, err := engine.ensurePhaseApplied(
			ctx,
			request,
			prepared,
		)
		if err != nil {
			classified := classifyLifecycleError(err)
			return engine.resultForError(
				request.Binding,
				prepared,
				classified,
			), lifecyclePublicError(classified)
		}
		if terminalOperationJournal(prepared.journal) {
			var result HostActionResult
			var err error
			if prepared.journal.CompensationPath == nil {
				result, err = engine.finish(
					ctx,
					request,
					prepared,
					postcondition,
				)
			} else {
				result, err = engine.finishCompensation(
					ctx,
					request,
					prepared,
					postcondition,
				)
			}
			if err != nil {
				classified := classifyLifecycleError(err)
				return engine.resultForError(
					request.Binding,
					prepared,
					classified,
				), lifecyclePublicError(classified)
			}
			return result, nil
		}
		if err := engine.advanceJournal(request.Binding, prepared); err != nil {
			classified := classifyLifecycleError(err)
			return engine.resultForError(
				request.Binding,
				prepared,
				classified,
			), lifecyclePublicError(classified)
		}
	}
}

// prepare is split out for crash-seeding tests. Production callers use
// Execute, which holds one stable lifecycle lease for the full operation.
func (engine LifecycleEngine) prepare(
	ctx context.Context,
	request LifecycleRequest,
) (*lifecyclePrepared, error) {
	if ctx == nil ||
		engine.Store == nil ||
		engine.Storage == nil ||
		engine.PollInterval <= 0 ||
		engine.PollInterval > time.Second ||
		validateLifecycleRequest(request) != nil {
		return nil, ErrLifecycleExecution
	}
	lease, err := engine.Store.Acquire(ctx, engine.PollInterval)
	if err != nil {
		return nil, err
	}
	defer lease.Close()
	return engine.prepareLocked(ctx, request)
}

func (engine LifecycleEngine) prepareLocked(
	ctx context.Context,
	request LifecycleRequest,
) (*lifecyclePrepared, error) {
	_, bindingDigest, _ := MarshalOperationBinding(request.Binding)
	prepared := &lifecyclePrepared{}

	journalName := lifecycleJournalName(request.Binding.OperationID)
	journalDocument, err := engine.Store.ReadCanonical(
		LifecycleJournals,
		journalName,
		maxLifecycleJournalBytes,
	)
	switch {
	case err == nil:
		journal, journalDigest, parseErr := ParseOperationJournal(
			journalDocument,
			maxLifecycleJournalBytes,
		)
		if parseErr != nil ||
			ValidateOperationJournalAgainstBinding(
				journal,
				request.Binding,
			) != nil ||
			!manifestPointersEqual(journal.PriorManifest, request.PriorManifest) ||
			!manifestPointersEqual(journal.TargetManifest, request.TargetManifest) {
			return prepared, integrityLifecycleError(ErrLifecycleIntegrity)
		}
		prepared.journal = journal
		prepared.journalDocument = journalDocument
		prepared.journalDigest = journalDigest
	case errors.Is(err, ErrLifecycleStateAbsent):
		now, timeErr := engine.nextTime(time.Time{})
		if timeErr != nil {
			return prepared, timeErr
		}
		journal := OperationJournal{
			SchemaVersion:      operationJournalSchemaVersion,
			OperationID:        request.Binding.OperationID,
			BindingDigest:      bindingDigest,
			Kind:               request.Binding.Kind,
			Phase:              OperationPhasePrepared,
			CompensationPath:   nil,
			ExpectedGeneration: request.Binding.ExpectedGeneration,
			PriorManifest:      cloneManifestPointer(request.PriorManifest),
			TargetManifest:     cloneManifestPointer(request.TargetManifest),
			TargetFleet:        request.Binding.TargetFleet,
			StartedAt:          now,
			UpdatedAt:          now,
		}
		document, digest, marshalErr := MarshalOperationJournal(journal)
		if marshalErr != nil {
			return prepared, integrityLifecycleError(marshalErr)
		}
		if err := engine.Storage.Revalidate(ctx, request.Reservation); err != nil {
			return prepared, recoverableLifecycleError(
				LifecycleErrorStorageEnvelope,
				err,
			)
		}
		if err := engine.Store.CreateCanonical(
			LifecycleJournals,
			journalName,
			document,
			maxLifecycleJournalBytes,
		); err != nil {
			return prepared, integrityLifecycleError(err)
		}
		prepared.journal = journal
		prepared.journalDocument = document
		prepared.journalDigest = digest
	default:
		return prepared, integrityLifecycleError(err)
	}

	reservationName := lifecycleReservationName(request.Binding.OperationID)
	reservationDocument, err := engine.Store.ReadCanonical(
		LifecycleReservations,
		reservationName,
		maxLifecycleReservationBytes,
	)
	switch {
	case err == nil:
		reservation, _, parseErr := ParseStorageReservation(
			reservationDocument,
			maxLifecycleReservationBytes,
		)
		if parseErr != nil ||
			!reservationMatchesRequest(
				reservation,
				request.Reservation,
				request.Binding,
			) {
			return prepared, integrityLifecycleError(ErrLifecycleIntegrity)
		}
		prepared.reservation = reservation
		prepared.reservationDocument = reservationDocument
	case errors.Is(err, ErrLifecycleStateAbsent):
		if prepared.journal.Phase != OperationPhasePrepared {
			return prepared, integrityLifecycleError(ErrLifecycleIntegrity)
		}
		document, _, marshalErr := MarshalStorageReservation(
			request.Reservation,
		)
		if marshalErr != nil {
			return prepared, integrityLifecycleError(marshalErr)
		}
		if err := engine.Storage.Revalidate(ctx, request.Reservation); err != nil {
			return prepared, recoverableLifecycleError(
				LifecycleErrorStorageEnvelope,
				err,
			)
		}
		if err := engine.Store.CreateCanonical(
			LifecycleReservations,
			reservationName,
			document,
			maxLifecycleReservationBytes,
		); err != nil {
			return prepared, integrityLifecycleError(err)
		}
		prepared.reservation = request.Reservation
		prepared.reservationDocument = document
	default:
		return prepared, integrityLifecycleError(err)
	}
	return prepared, nil
}

func (engine LifecycleEngine) ensurePhaseApplied(
	ctx context.Context,
	request LifecycleRequest,
	prepared *lifecyclePrepared,
) (TargetPostcondition, error) {
	if prepared == nil {
		return TargetPostcondition{}, integrityLifecycleError(
			ErrLifecycleIntegrity,
		)
	}
	if err := engine.Storage.Revalidate(ctx, prepared.reservation); err != nil {
		return TargetPostcondition{}, recoverableLifecycleError(
			LifecycleErrorStorageEnvelope,
			err,
		)
	}
	phase := prepared.journal.Phase
	priorDigest, err := engine.appliedReceiptChain(
		request.Binding,
		prepared.journal,
		false,
	)
	if err != nil {
		return TargetPostcondition{}, err
	}
	effectKey, err := DeriveOperationEffectKey(request.Binding, phase)
	if err != nil {
		return TargetPostcondition{}, integrityLifecycleError(err)
	}
	receiptName := lifecycleReceiptName(effectKey)
	receiptDocument, readErr := engine.Store.ReadCanonical(
		LifecycleReceipts,
		receiptName,
		maxLifecycleReceiptBytes,
	)
	var receipt OperationReceipt
	switch {
	case errors.Is(readErr, ErrLifecycleStateAbsent):
		now, timeErr := engine.nextTime(time.Time{})
		if timeErr != nil {
			return TargetPostcondition{}, timeErr
		}
		_, bindingDigest, _ := MarshalOperationBinding(request.Binding)
		receipt = OperationReceipt{
			SchemaVersion:             operationReceiptSchemaVersion,
			OperationID:               request.Binding.OperationID,
			BindingDigest:             bindingDigest,
			EffectKey:                 effectKey,
			Phase:                     phase,
			State:                     ReceiptStateApplying,
			PriorReceiptDigest:        priorDigest,
			TargetPostconditionDigest: nil,
			CreatedAt:                 now,
			UpdatedAt:                 now,
		}
		receiptDocument, _, err = MarshalOperationReceipt(receipt)
		if err != nil {
			return TargetPostcondition{}, integrityLifecycleError(err)
		}
		if _, postErr := engine.Store.ReadCanonical(
			LifecycleReceipts,
			lifecyclePostconditionName(effectKey),
			maxLifecyclePostconditionBytes,
		); !errors.Is(postErr, ErrLifecycleStateAbsent) {
			return TargetPostcondition{}, integrityLifecycleError(
				ErrLifecycleIntegrity,
			)
		}
		if err := engine.Store.CreateCanonical(
			LifecycleReceipts,
			receiptName,
			receiptDocument,
			maxLifecycleReceiptBytes,
		); err != nil {
			return TargetPostcondition{}, integrityLifecycleError(err)
		}
	case readErr != nil:
		return TargetPostcondition{}, integrityLifecycleError(readErr)
	default:
		parsed, _, parseErr := ParseOperationReceipt(
			receiptDocument,
			maxLifecycleReceiptBytes,
		)
		if parseErr != nil ||
			parsed.OperationID != request.Binding.OperationID ||
			parsed.EffectKey != effectKey ||
			parsed.Phase != phase ||
			parsed.PriorReceiptDigest != priorDigest {
			return TargetPostcondition{}, integrityLifecycleError(
				ErrLifecycleIntegrity,
			)
		}
		receipt = parsed
	}

	if receipt.State == ReceiptStateApplied {
		return engine.validateAppliedPhase(
			request.Binding,
			receipt,
			receiptDocument,
		)
	}
	if receipt.State != ReceiptStateApplying {
		return TargetPostcondition{}, integrityLifecycleError(
			ErrLifecycleIntegrity,
		)
	}
	return engine.resolveApplyingPhase(
		ctx,
		request.Binding,
		receipt,
		receiptDocument,
	)
}

func (engine LifecycleEngine) resolveApplyingPhase(
	ctx context.Context,
	binding OperationBinding,
	applying OperationReceipt,
	applyingDocument []byte,
) (TargetPostcondition, error) {
	postconditionName := lifecyclePostconditionName(applying.EffectKey)
	persistedDocument, persistedErr := engine.Store.ReadCanonical(
		LifecycleReceipts,
		postconditionName,
		maxLifecyclePostconditionBytes,
	)
	var persisted *TargetPostcondition
	if persistedErr == nil {
		parsed, _, err := ParseTargetPostcondition(
			persistedDocument,
			maxLifecyclePostconditionBytes,
		)
		if err != nil ||
			ValidateTargetPostconditionAgainstBinding(
				parsed,
				binding,
				applying.Phase,
			) != nil {
			return TargetPostcondition{}, integrityLifecycleError(
				ErrLifecycleIntegrity,
			)
		}
		persisted = &parsed
	} else if !errors.Is(persistedErr, ErrLifecycleStateAbsent) {
		return TargetPostcondition{}, integrityLifecycleError(persistedErr)
	}

	observation, observeErr := engine.Effects.Observe(
		ctx,
		binding,
		applying.Phase,
	)
	if observeErr != nil {
		return TargetPostcondition{}, recoverableLifecycleError(
			LifecycleErrorEffectFailed,
			observeErr,
		)
	}
	if err := validateLifecycleObservation(
		observation,
		binding,
		applying.Phase,
	); err != nil {
		return TargetPostcondition{}, err
	}
	var postcondition TargetPostcondition
	switch observation.State {
	case LifecycleEffectPresent:
		if persisted != nil {
			if !sameTargetState(*persisted, *observation.Postcondition) {
				return TargetPostcondition{}, recoverableLifecycleError(
					LifecycleErrorAmbiguousEffect,
					ErrLifecycleIntegrity,
				)
			}
			postcondition = *persisted
		} else {
			postcondition = *observation.Postcondition
		}
	case LifecycleEffectAbsent:
		if persisted != nil {
			return TargetPostcondition{}, recoverableLifecycleError(
				LifecycleErrorAmbiguousEffect,
				ErrLifecycleIntegrity,
			)
		}
		applied, applyErr := engine.Effects.Apply(
			ctx,
			binding,
			applying.Phase,
		)
		if applyErr == nil {
			postcondition = applied
			break
		}
		after, observeAfterErr := engine.Effects.Observe(
			ctx,
			binding,
			applying.Phase,
		)
		if observeAfterErr != nil ||
			validateLifecycleObservation(
				after,
				binding,
				applying.Phase,
			) != nil ||
			after.State != LifecycleEffectPresent {
			return TargetPostcondition{}, recoverableLifecycleError(
				LifecycleErrorEffectFailed,
				applyErr,
			)
		}
		postcondition = *after.Postcondition
	case LifecycleEffectAmbiguous:
		return TargetPostcondition{}, recoverableLifecycleError(
			LifecycleErrorAmbiguousEffect,
			ErrLifecycleIntegrity,
		)
	default:
		return TargetPostcondition{}, integrityLifecycleError(
			ErrLifecycleIntegrity,
		)
	}
	if err := ValidateTargetPostconditionAgainstBinding(
		postcondition,
		binding,
		applying.Phase,
	); err != nil {
		return TargetPostcondition{}, integrityLifecycleError(err)
	}
	postconditionDocument, postconditionDigest, err :=
		MarshalTargetPostcondition(postcondition)
	if err != nil {
		return TargetPostcondition{}, integrityLifecycleError(err)
	}
	if persisted == nil {
		if err := engine.Store.CreateCanonical(
			LifecycleReceipts,
			postconditionName,
			postconditionDocument,
			maxLifecyclePostconditionBytes,
		); err != nil {
			return TargetPostcondition{}, integrityLifecycleError(err)
		}
	} else if !bytes.Equal(persistedDocument, postconditionDocument) {
		return TargetPostcondition{}, integrityLifecycleError(
			ErrLifecycleIntegrity,
		)
	}
	applied := applying
	applied.State = ReceiptStateApplied
	applied.TargetPostconditionDigest = &postconditionDigest
	applied.UpdatedAt, err = engine.nextTime(applying.UpdatedAt)
	if err != nil {
		return TargetPostcondition{}, err
	}
	appliedDocument, _, err := MarshalOperationReceipt(applied)
	if err != nil ||
		ValidateAppliedReceipt(
			applying,
			applied,
			postcondition,
			binding,
		) != nil {
		return TargetPostcondition{}, integrityLifecycleError(
			ErrLifecycleIntegrity,
		)
	}
	if err := engine.Store.ReplaceCanonical(
		LifecycleReceipts,
		lifecycleReceiptName(applying.EffectKey),
		applyingDocument,
		appliedDocument,
		maxLifecycleReceiptBytes,
	); err != nil {
		return TargetPostcondition{}, integrityLifecycleError(err)
	}
	return postcondition, nil
}

func (engine LifecycleEngine) validateAppliedPhase(
	binding OperationBinding,
	applied OperationReceipt,
	appliedDocument []byte,
) (TargetPostcondition, error) {
	postconditionDocument, err := engine.Store.ReadCanonical(
		LifecycleReceipts,
		lifecyclePostconditionName(applied.EffectKey),
		maxLifecyclePostconditionBytes,
	)
	if err != nil {
		return TargetPostcondition{}, integrityLifecycleError(err)
	}
	postcondition, _, err := ParseTargetPostcondition(
		postconditionDocument,
		maxLifecyclePostconditionBytes,
	)
	if err != nil {
		return TargetPostcondition{}, integrityLifecycleError(err)
	}
	applying := applied
	applying.State = ReceiptStateApplying
	applying.TargetPostconditionDigest = nil
	applying.UpdatedAt = applying.CreatedAt
	if ValidateAppliedReceipt(
		applying,
		applied,
		postcondition,
		binding,
	) != nil {
		return TargetPostcondition{}, integrityLifecycleError(
			ErrLifecycleIntegrity,
		)
	}
	canonicalApplied, _, err := MarshalOperationReceipt(applied)
	if err != nil || !bytes.Equal(canonicalApplied, appliedDocument) {
		return TargetPostcondition{}, integrityLifecycleError(
			ErrLifecycleIntegrity,
		)
	}
	return postcondition, nil
}

func (engine LifecycleEngine) appliedReceiptChain(
	binding OperationBinding,
	journal OperationJournal,
	includeCurrent bool,
) (string, error) {
	sequence, ok := activePhaseSequence(binding, journal)
	if !ok {
		return "", integrityLifecycleError(ErrLifecycleIntegrity)
	}
	currentIndex := phaseIndex(sequence, journal.Phase)
	if currentIndex < 0 {
		return "", integrityLifecycleError(ErrLifecycleIntegrity)
	}
	limit := currentIndex
	if includeCurrent {
		limit++
	}
	priorDigest := strings.Repeat("0", 64)
	if journal.CompensationPath != nil {
		var err error
		priorDigest, _, err = engine.compensationSourceAnchor(
			binding,
			*journal.CompensationPath,
		)
		if err != nil {
			return "", err
		}
	}
	for index := 0; index < limit; index++ {
		phase := sequence[index]
		effectKey, err := DeriveOperationEffectKey(binding, phase)
		if err != nil {
			return "", integrityLifecycleError(err)
		}
		document, err := engine.Store.ReadCanonical(
			LifecycleReceipts,
			lifecycleReceiptName(effectKey),
			maxLifecycleReceiptBytes,
		)
		if err != nil {
			return "", integrityLifecycleError(err)
		}
		receipt, digest, err := ParseOperationReceipt(
			document,
			maxLifecycleReceiptBytes,
		)
		if err != nil ||
			receipt.State != ReceiptStateApplied ||
			receipt.OperationID != binding.OperationID ||
			receipt.EffectKey != effectKey ||
			receipt.Phase != phase ||
			receipt.PriorReceiptDigest != priorDigest {
			return "", integrityLifecycleError(ErrLifecycleIntegrity)
		}
		if _, err := engine.validateAppliedPhase(
			binding,
			receipt,
			document,
		); err != nil {
			return "", err
		}
		priorDigest = digest
	}
	return priorDigest, nil
}

func (engine LifecycleEngine) compensationSourceAnchor(
	binding OperationBinding,
	path CompensationPath,
) (string, OperationPhase, error) {
	normal, ok := normalPhaseSequence(binding)
	if !ok {
		return "", "", integrityLifecycleError(ErrLifecycleIntegrity)
	}
	priorDigest := strings.Repeat("0", 64)
	var source OperationPhase
	foundGap := false
	for _, phase := range normal {
		effectKey, err := DeriveOperationEffectKey(binding, phase)
		if err != nil {
			return "", "", integrityLifecycleError(err)
		}
		document, readErr := engine.Store.ReadCanonical(
			LifecycleReceipts,
			lifecycleReceiptName(effectKey),
			maxLifecycleReceiptBytes,
		)
		if errors.Is(readErr, ErrLifecycleStateAbsent) {
			foundGap = true
			continue
		}
		if readErr != nil || foundGap {
			return "", "", integrityLifecycleError(ErrLifecycleIntegrity)
		}
		receipt, digest, parseErr := ParseOperationReceipt(
			document,
			maxLifecycleReceiptBytes,
		)
		if parseErr != nil ||
			receipt.State != ReceiptStateApplied ||
			receipt.OperationID != binding.OperationID ||
			receipt.EffectKey != effectKey ||
			receipt.Phase != phase ||
			receipt.PriorReceiptDigest != priorDigest {
			return "", "", integrityLifecycleError(
				ErrLifecycleIntegrity,
			)
		}
		if _, err := engine.validateAppliedPhase(
			binding,
			receipt,
			document,
		); err != nil {
			return "", "", err
		}
		priorDigest = digest
		source = phase
	}
	if source == "" || !sourcePhaseAllowed(path, source) {
		return "", "", integrityLifecycleError(ErrLifecycleIntegrity)
	}
	return priorDigest, source, nil
}

func (engine LifecycleEngine) advanceJournal(
	binding OperationBinding,
	prepared *lifecyclePrepared,
) error {
	sequence, ok := activePhaseSequence(binding, prepared.journal)
	if !ok {
		return integrityLifecycleError(ErrLifecycleIntegrity)
	}
	index := phaseIndex(sequence, prepared.journal.Phase)
	if index < 0 || index+1 >= len(sequence) {
		return integrityLifecycleError(ErrLifecycleIntegrity)
	}
	next := prepared.journal
	next.Phase = sequence[index+1]
	next.UpdatedAt, _ = engine.nextTime(prepared.journal.UpdatedAt)
	if err := ValidateOperationJournalTransition(
		prepared.journal,
		next,
		binding,
		nil,
	); err != nil {
		return integrityLifecycleError(err)
	}
	document, digest, err := MarshalOperationJournal(next)
	if err != nil {
		return integrityLifecycleError(err)
	}
	if err := engine.Store.ReplaceCanonical(
		LifecycleJournals,
		lifecycleJournalName(binding.OperationID),
		prepared.journalDocument,
		document,
		maxLifecycleJournalBytes,
	); err != nil {
		return integrityLifecycleError(err)
	}
	prepared.journal = next
	prepared.journalDocument = document
	prepared.journalDigest = digest
	return nil
}

func (engine LifecycleEngine) validateCompensationAuthorization(
	binding OperationBinding,
	journal OperationJournal,
	source TargetPostcondition,
	authorization CompensationAuthorization,
) error {
	if journal.CompensationPath != nil ||
		!compensationAllowedForBinding(authorization.path, binding) ||
		!sourcePhaseAllowed(authorization.path, journal.Phase) ||
		authorization.sourcePhase != journal.Phase {
		return ErrLifecycleIntegrity
	}
	sourceDocument, sourceDigest, err := MarshalTargetPostcondition(source)
	if err != nil ||
		len(sourceDocument) == 0 ||
		authorization.sourceProofDigest != sourceDigest {
		return ErrLifecycleIntegrity
	}
	receiptDigest, sourcePhase, err := engine.compensationSourceAnchor(
		binding,
		authorization.path,
	)
	if err != nil ||
		sourcePhase != journal.Phase ||
		authorization.sourceReceiptDigest != receiptDigest {
		return ErrLifecycleIntegrity
	}
	sequence := compensationPhaseSequences[authorization.path]
	if len(sequence) == 0 {
		return ErrLifecycleIntegrity
	}
	return nil
}

func (engine LifecycleEngine) persistCompensationPivot(
	binding OperationBinding,
	prepared *lifecyclePrepared,
	authorization CompensationAuthorization,
) error {
	sequence := compensationPhaseSequences[authorization.path]
	if len(sequence) == 0 {
		return integrityLifecycleError(ErrLifecycleIntegrity)
	}
	next := prepared.journal
	next.CompensationPath = &authorization.path
	next.Phase = sequence[0]
	var err error
	next.UpdatedAt, err = engine.nextTime(prepared.journal.UpdatedAt)
	if err != nil {
		return err
	}
	path := authorization.path
	if ValidateOperationJournalTransition(
		prepared.journal,
		next,
		binding,
		&path,
	) != nil {
		return integrityLifecycleError(ErrLifecycleIntegrity)
	}
	document, digest, err := MarshalOperationJournal(next)
	if err != nil {
		return integrityLifecycleError(err)
	}
	if err := engine.Store.ReplaceCanonical(
		LifecycleJournals,
		lifecycleJournalName(binding.OperationID),
		prepared.journalDocument,
		document,
		maxLifecycleJournalBytes,
	); err != nil {
		return integrityLifecycleError(err)
	}
	prepared.journal = next
	prepared.journalDocument = document
	prepared.journalDigest = digest
	return nil
}

func (engine LifecycleEngine) finish(
	ctx context.Context,
	request LifecycleRequest,
	prepared *lifecyclePrepared,
	persisted TargetPostcondition,
) (HostActionResult, error) {
	observation, err := engine.Effects.Observe(
		ctx,
		request.Binding,
		OperationPhaseComplete,
	)
	if err != nil ||
		validateLifecycleObservation(
			observation,
			request.Binding,
			OperationPhaseComplete,
		) != nil ||
		observation.State != LifecycleEffectPresent ||
		!sameTargetState(persisted, *observation.Postcondition) {
		return HostActionResult{}, recoverableLifecycleError(
			LifecycleErrorTerminalMismatch,
			err,
		)
	}
	if err := engine.Storage.Revalidate(ctx, prepared.reservation); err != nil {
		return HostActionResult{}, recoverableLifecycleError(
			LifecycleErrorStorageEnvelope,
			err,
		)
	}
	_, targetProofDigest, err := MarshalTargetPostcondition(persisted)
	if err != nil {
		return HostActionResult{}, integrityLifecycleError(err)
	}
	switch prepared.reservation.State {
	case ReservationStateActive:
		committed := prepared.reservation
		committed.State = ReservationStateCommitted
		committed.CommittedTargetProofDigest = &targetProofDigest
		committed.UpdatedAt, err = engine.nextTime(
			prepared.reservation.UpdatedAt,
		)
		if err != nil ||
			ValidateStorageReservationTransition(
				prepared.reservation,
				committed,
			) != nil {
			return HostActionResult{}, integrityLifecycleError(
				ErrLifecycleIntegrity,
			)
		}
		document, _, marshalErr := MarshalStorageReservation(committed)
		if marshalErr != nil {
			return HostActionResult{}, integrityLifecycleError(marshalErr)
		}
		if err := engine.Store.ReplaceCanonical(
			LifecycleReservations,
			lifecycleReservationName(request.Binding.OperationID),
			prepared.reservationDocument,
			document,
			maxLifecycleReservationBytes,
		); err != nil {
			return HostActionResult{}, integrityLifecycleError(err)
		}
		prepared.reservation = committed
		prepared.reservationDocument = document
	case ReservationStateCommitted:
		if prepared.reservation.CommittedTargetProofDigest == nil ||
			*prepared.reservation.CommittedTargetProofDigest !=
				targetProofDigest {
			return HostActionResult{}, integrityLifecycleError(
				ErrLifecycleIntegrity,
			)
		}
	default:
		return HostActionResult{}, integrityLifecycleError(
			ErrLifecycleIntegrity,
		)
	}
	result := HostActionResult{
		SchemaVersion:     hostActionResultSchemaVersion,
		Status:            HostActionComplete,
		OperationID:       request.Binding.OperationID,
		JournalDigest:     prepared.journalDigest,
		TargetProofDigest: &targetProofDigest,
		FenceGeneration:   persisted.FenceGeneration,
		ActiveFleet:       persisted.ActiveFleet,
		ErrorClass:        "",
	}
	if _, _, err := MarshalHostActionResult(result); err != nil {
		return HostActionResult{}, integrityLifecycleError(err)
	}
	return result, nil
}

func (engine LifecycleEngine) finishCompensation(
	ctx context.Context,
	request LifecycleRequest,
	prepared *lifecyclePrepared,
	persisted TargetPostcondition,
) (HostActionResult, error) {
	if prepared.journal.CompensationPath == nil {
		return HostActionResult{}, integrityLifecycleError(
			ErrLifecycleIntegrity,
		)
	}
	observation, err := engine.Effects.Observe(
		ctx,
		request.Binding,
		prepared.journal.Phase,
	)
	if err != nil ||
		validateLifecycleObservation(
			observation,
			request.Binding,
			prepared.journal.Phase,
		) != nil ||
		observation.State != LifecycleEffectPresent ||
		!sameTargetState(persisted, *observation.Postcondition) {
		return HostActionResult{}, recoverableLifecycleError(
			LifecycleErrorTerminalMismatch,
			err,
		)
	}
	_, absenceProofDigest, err := MarshalTargetPostcondition(persisted)
	if err != nil {
		return HostActionResult{}, integrityLifecycleError(err)
	}
	switch prepared.reservation.State {
	case ReservationStateActive:
		released := prepared.reservation
		released.State = ReservationStateReleased
		released.ReleasedAbsenceProofDigest = &absenceProofDigest
		released.UpdatedAt, err = engine.nextTime(
			prepared.reservation.UpdatedAt,
		)
		if err != nil ||
			ValidateStorageReservationTransition(
				prepared.reservation,
				released,
			) != nil {
			return HostActionResult{}, integrityLifecycleError(
				ErrLifecycleIntegrity,
			)
		}
		document, _, err := MarshalStorageReservation(released)
		if err != nil {
			return HostActionResult{}, integrityLifecycleError(err)
		}
		if err := engine.Store.ReplaceCanonical(
			LifecycleReservations,
			lifecycleReservationName(request.Binding.OperationID),
			prepared.reservationDocument,
			document,
			maxLifecycleReservationBytes,
		); err != nil {
			return HostActionResult{}, integrityLifecycleError(err)
		}
		prepared.reservation = released
		prepared.reservationDocument = document
	case ReservationStateReleased:
		if prepared.reservation.ReleasedAbsenceProofDigest == nil ||
			*prepared.reservation.ReleasedAbsenceProofDigest !=
				absenceProofDigest {
			return HostActionResult{}, integrityLifecycleError(
				ErrLifecycleIntegrity,
			)
		}
	default:
		return HostActionResult{}, integrityLifecycleError(
			ErrLifecycleIntegrity,
		)
	}
	result := HostActionResult{
		SchemaVersion:     hostActionResultSchemaVersion,
		Status:            HostActionCompensated,
		OperationID:       request.Binding.OperationID,
		JournalDigest:     prepared.journalDigest,
		TargetProofDigest: nil,
		FenceGeneration:   persisted.FenceGeneration,
		ActiveFleet:       persisted.ActiveFleet,
		ErrorClass:        "compensated",
	}
	if _, _, err := MarshalHostActionResult(result); err != nil {
		return HostActionResult{}, integrityLifecycleError(err)
	}
	return result, nil
}

func (engine LifecycleEngine) resultForError(
	binding OperationBinding,
	prepared *lifecyclePrepared,
	classified *lifecycleEngineError,
) HostActionResult {
	status := HostActionFailed
	if classified != nil && classified.recoverable {
		status = HostActionRecoverable
	}
	errorClass := LifecycleErrorIntegrity
	if classified != nil && validLifecycleScalar(classified.class) {
		errorClass = classified.class
	}
	result := lifecycleFailureResult(binding, errorClass)
	result.Status = status
	if prepared != nil && isLowerHex64(prepared.journalDigest) {
		result.JournalDigest = prepared.journalDigest
	}
	if prepared != nil {
		if proof, err := engine.latestAppliedPostcondition(
			binding,
			prepared.journal,
		); err == nil {
			result.FenceGeneration = proof.FenceGeneration
			result.ActiveFleet = proof.ActiveFleet
		}
	}
	if _, _, err := MarshalHostActionResult(result); err != nil {
		return lifecycleFailureResult(binding, LifecycleErrorIntegrity)
	}
	return result
}

func (engine LifecycleEngine) latestAppliedPostcondition(
	binding OperationBinding,
	journal OperationJournal,
) (TargetPostcondition, error) {
	sequence, ok := activePhaseSequence(binding, journal)
	if !ok {
		return TargetPostcondition{}, ErrLifecycleIntegrity
	}
	for index := phaseIndex(sequence, journal.Phase); index >= 0; index-- {
		effectKey, err := DeriveOperationEffectKey(binding, sequence[index])
		if err != nil {
			continue
		}
		document, err := engine.Store.ReadCanonical(
			LifecycleReceipts,
			lifecyclePostconditionName(effectKey),
			maxLifecyclePostconditionBytes,
		)
		if err != nil {
			continue
		}
		postcondition, _, err := ParseTargetPostcondition(
			document,
			maxLifecyclePostconditionBytes,
		)
		if err == nil {
			return postcondition, nil
		}
	}
	return TargetPostcondition{}, ErrLifecycleStateAbsent
}

func validateLifecycleRequest(request LifecycleRequest) error {
	if validateOperationBinding(request.Binding) != nil ||
		!manifestPointerMatchesDigest(
			request.PriorManifest,
			request.Binding.PriorManifestDigest,
		) ||
		!manifestPointerMatchesDigest(
			request.TargetManifest,
			request.Binding.TargetManifestDigest,
		) ||
		validateStorageReservation(request.Reservation) != nil {
		return ErrLifecycleExecution
	}
	_, bindingDigest, _ := MarshalOperationBinding(request.Binding)
	if request.Reservation.OperationID != request.Binding.OperationID ||
		request.Reservation.BindingDigest != bindingDigest ||
		request.Reservation.State != ReservationStateActive ||
		!reflect.DeepEqual(
			request.Reservation.TargetManifestDigest,
			request.Binding.TargetManifestDigest,
		) {
		return ErrLifecycleExecution
	}
	return nil
}

func validateLifecycleObservation(
	observation LifecycleEffectObservation,
	binding OperationBinding,
	phase OperationPhase,
) error {
	switch observation.State {
	case LifecycleEffectPresent:
		if observation.Postcondition == nil ||
			ValidateTargetPostconditionAgainstBinding(
				*observation.Postcondition,
				binding,
				phase,
			) != nil {
			return integrityLifecycleError(ErrLifecycleIntegrity)
		}
	case LifecycleEffectAbsent, LifecycleEffectAmbiguous:
		if observation.Postcondition != nil {
			return integrityLifecycleError(ErrLifecycleIntegrity)
		}
	default:
		return integrityLifecycleError(ErrLifecycleIntegrity)
	}
	return nil
}

func reservationMatchesRequest(
	persisted StorageReservation,
	request StorageReservation,
	binding OperationBinding,
) bool {
	_, bindingDigest, err := MarshalOperationBinding(binding)
	return err == nil &&
		persisted.OperationID == binding.OperationID &&
		persisted.BindingDigest == bindingDigest &&
		sameStorageReservationIdentity(persisted, request) &&
		(persisted.State == ReservationStateActive ||
			persisted.State == ReservationStateCommitted ||
			persisted.State == ReservationStateReleased)
}

func activePhaseSequence(
	binding OperationBinding,
	journal OperationJournal,
) ([]OperationPhase, bool) {
	if journal.CompensationPath == nil {
		return normalPhaseSequence(binding)
	}
	sequence, ok := compensationPhaseSequences[*journal.CompensationPath]
	return sequence, ok
}

func lifecycleJournalName(operationID string) string {
	return operationID + ".journal.json"
}

func lifecycleReservationName(operationID string) string {
	return operationID + ".reservation.json"
}

func lifecycleReceiptName(effectKey string) string {
	return effectKey + ".receipt.json"
}

func lifecyclePostconditionName(effectKey string) string {
	return effectKey + ".postcondition.json"
}

func (engine LifecycleEngine) nextTime(after time.Time) (time.Time, error) {
	var now time.Time
	if engine.Now == nil {
		now = time.Now().UTC()
	} else {
		now = engine.Now()
	}
	if now.IsZero() {
		return time.Time{}, integrityLifecycleError(ErrLifecycleIntegrity)
	}
	now = now.UTC()
	if !after.IsZero() && !now.After(after) {
		now = after.Add(time.Nanosecond)
	}
	return now, nil
}

func sameTargetState(left, right TargetPostcondition) bool {
	left.ObservedAt = time.Time{}
	right.ObservedAt = time.Time{}
	return reflect.DeepEqual(left, right)
}

func manifestPointersEqual(left, right *RuntimeManifest) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	leftDocument, leftDigest, leftErr := MarshalRuntimeManifest(*left)
	rightDocument, rightDigest, rightErr := MarshalRuntimeManifest(*right)
	return leftErr == nil &&
		rightErr == nil &&
		leftDigest == rightDigest &&
		bytes.Equal(leftDocument, rightDocument)
}

func cloneManifestPointer(manifest *RuntimeManifest) *RuntimeManifest {
	if manifest == nil {
		return nil
	}
	copy := *manifest
	return &copy
}

func lifecycleFailureResult(
	binding OperationBinding,
	errorClass string,
) HostActionResult {
	operationID := binding.OperationID
	if !isLowerHex64(operationID) {
		operationID = strings.Repeat("0", 64)
	}
	fleet := binding.TargetFleet
	if !validFleet(fleet) {
		fleet = fleetfence.FleetNone
	}
	if !validLifecycleScalar(errorClass) {
		errorClass = LifecycleErrorIntegrity
	}
	return HostActionResult{
		SchemaVersion:     hostActionResultSchemaVersion,
		Status:            HostActionFailed,
		OperationID:       operationID,
		JournalDigest:     strings.Repeat("0", 64),
		TargetProofDigest: nil,
		FenceGeneration:   binding.ExpectedGeneration,
		ActiveFleet:       fleet,
		ErrorClass:        errorClass,
	}
}

func recoverableLifecycleError(
	class string,
	cause error,
) *lifecycleEngineError {
	return &lifecycleEngineError{
		class:       class,
		recoverable: true,
		cause:       cause,
	}
}

func integrityLifecycleError(cause error) *lifecycleEngineError {
	return &lifecycleEngineError{
		class: LifecycleErrorIntegrity,
		cause: cause,
	}
}

func classifyLifecycleError(err error) *lifecycleEngineError {
	if err == nil {
		return integrityLifecycleError(ErrLifecycleIntegrity)
	}
	var classified *lifecycleEngineError
	if errors.As(err, &classified) {
		return classified
	}
	if errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return recoverableLifecycleError(
			LifecycleErrorContextCancelled,
			err,
		)
	}
	return integrityLifecycleError(err)
}

func lifecyclePublicError(err error) error {
	var classified *lifecycleEngineError
	if errors.As(err, &classified) && classified.recoverable {
		return ErrLifecycleRecoverable
	}
	return ErrLifecycleExecution
}

func (err *lifecycleEngineError) Format(
	state fmt.State,
	verb rune,
) {
	_, _ = fmt.Fprint(state, err.Error())
}
