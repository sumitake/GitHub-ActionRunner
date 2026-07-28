package networkjail

import "context"

const permitLedgerVersion = 1

type permitClassLedger struct {
	TokenUnits        uint64
	LastRefillNanos   uint64
	ReservedHighWater uint64
	IssuedHighWater   uint64
	ReservedSequence  PermitSequence
	IssuedSequence    PermitSequence
}

type permitLedger struct {
	Version             uint8
	SlotID              CapacitySlotID
	BootID              BootID
	LastRebaseBootID    BootID
	Revision            uint64
	ActiveJobGeneration JobGeneration
	LastMonotonicNanos  uint64
	RetainedUntilNanos  uint64
	Job                 permitClassLedger
	DoH                 permitClassLedger
}

type permitStore interface {
	load(context.Context, CapacitySlotID) (permitLedger, bool, error)
	compareAndSwap(context.Context, CapacitySlotID, uint64, permitLedger) error
	delete(context.Context, CapacitySlotID, uint64) error
}
