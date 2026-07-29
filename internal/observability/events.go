// Package observability defines closed, identity-free runtime events. It is a
// dependency leaf and accepts only the aggregate health document shared with
// publishers.
package observability

import (
	"errors"

	"github.com/sumitake/portable-ghar/internal/health"
)

var ErrInvalidEvent = errors.New("observability: invalid closed event")

// EventKind is a closed event classification.
type EventKind uint8

const (
	EventHistoryPressureEvaluated EventKind = iota + 1
)

// PressureReason is a closed bit set identifying which aggregate budget
// caused a warning or stop. Multiple independently crossed budgets are
// preserved without carrying an open text field.
type PressureReason uint16

const (
	PressureReasonNone        PressureReason = 0
	PressureReasonHistoryRows PressureReason = 1 << iota
	PressureReasonHistoryBytes
	PressureReasonNetworkLedgerRows
	PressureReasonNetworkLedgerBytes
	PressureReasonArithmeticOverflow
)

const pressureReasonAll = PressureReasonHistoryRows |
	PressureReasonHistoryBytes |
	PressureReasonNetworkLedgerRows |
	PressureReasonNetworkLedgerBytes |
	PressureReasonArithmeticOverflow

// Event is the complete sanitized observability boundary for a history
// pressure evaluation.
type Event struct {
	Kind     EventKind
	Reasons  PressureReason
	Snapshot health.HistorySnapshot
}

// Validate enforces the closed kind/reason grammar and the embedded aggregate
// snapshot contract.
func (e Event) Validate() error {
	if e.Kind != EventHistoryPressureEvaluated ||
		e.Reasons&^pressureReasonAll != 0 ||
		e.Snapshot.Validate() != nil {
		return ErrInvalidEvent
	}
	switch e.Snapshot.Pressure {
	case health.PressureNormal:
		if e.Reasons != PressureReasonNone {
			return ErrInvalidEvent
		}
	case health.PressureWarning, health.PressureStop:
		if e.Reasons == PressureReasonNone {
			return ErrInvalidEvent
		}
	default:
		return ErrInvalidEvent
	}
	return nil
}
