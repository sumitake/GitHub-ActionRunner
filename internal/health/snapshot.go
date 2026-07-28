// Package health defines identity-free aggregate health documents. It is a
// dependency leaf: runtime packages may publish these values, while health
// never imports controller, state, admission, or host implementations.
package health

import (
	"errors"
	"time"
)

var ErrInvalidSnapshot = errors.New("health: invalid aggregate snapshot")

// Readiness is a closed service-readiness state.
type Readiness uint8

const (
	ReadinessReady Readiness = iota + 1
	ReadinessNotReady
)

// Pressure is a closed bounded-history pressure state.
type Pressure uint8

const (
	PressureNormal Pressure = iota + 1
	PressureWarning
	PressureStop
)

// Snapshot contains only aggregate counts, byte totals, ages, closed states,
// and the persisted policy epoch/capacity. It deliberately has no string or
// assignment-bearing field.
type Snapshot struct {
	ObservedAt                time.Time
	Readiness                 Readiness
	Pressure                  Pressure
	HistoryRows               uint64
	HistoryLogicalBytes       uint64
	NetworkLedgerRows         uint64
	NetworkLedgerLogicalBytes uint64
	InflightWork              uint64
	UncertainAcknowledgements uint64
	OldestRetainedAge         time.Duration
	EffectiveCapacity         uint64
	PolicyEpoch               uint64
}

// Validate rejects open or structurally ambiguous snapshots before a
// publisher can expose them.
func (s Snapshot) Validate() error {
	if s.ObservedAt.IsZero() ||
		(s.Readiness != ReadinessReady && s.Readiness != ReadinessNotReady) ||
		(s.Pressure != PressureNormal &&
			s.Pressure != PressureWarning &&
			s.Pressure != PressureStop) ||
		s.OldestRetainedAge < 0 {
		return ErrInvalidSnapshot
	}
	return nil
}
