package networkjail

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
)

const nanosPerSecond = uint64(1_000_000_000)

type BootID [16]byte

func ParseBootID(value string) (BootID, error) {
	if len(value) != 36 ||
		value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' ||
		value != strings.ToLower(value) {
		return BootID{}, errors.New("networkjail: boot identity invalid")
	}
	compact := strings.NewReplacer("-", "").Replace(value)
	decoded, err := hex.DecodeString(compact)
	if err != nil || len(decoded) != len(BootID{}) {
		return BootID{}, errors.New("networkjail: boot identity invalid")
	}
	var result BootID
	copy(result[:], decoded)
	if result == (BootID{}) {
		return BootID{}, errors.New("networkjail: boot identity invalid")
	}
	return result, nil
}

func (id BootID) String() string {
	raw := hex.EncodeToString(id[:])
	if len(raw) != 32 {
		return ""
	}
	return raw[0:8] + "-" + raw[8:12] + "-" + raw[12:16] + "-" +
		raw[16:20] + "-" + raw[20:32]
}

type ClockObservation struct {
	BootID         BootID
	MonotonicNanos uint64
}

func (observation ClockObservation) validate() error {
	if observation.BootID == (BootID{}) || observation.MonotonicNanos == 0 {
		return errors.New("networkjail: monotonic clock unavailable")
	}
	return nil
}

type MonotonicClock interface {
	Observe(context.Context) (ClockObservation, error)
}
