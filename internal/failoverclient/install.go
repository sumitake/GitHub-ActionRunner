package failoverclient

import (
	"encoding/json"
	"fmt"
	"time"
)

func InstallHeartbeatLease(
	cache *LeaseCache,
	raw []byte,
	fence uint64,
	sendAnchor time.Time,
	margin time.Duration,
) error {
	if cache == nil || len(raw) == 0 || fence == 0 {
		return fmt.Errorf("%w: install", ErrLeaseCache)
	}
	var envelope struct {
		Lease    json.RawMessage `json:"lease"`
		Sequence uint64          `json:"sequence"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil ||
		len(envelope.Lease) == 0 ||
		string(envelope.Lease) == "null" {
		return fmt.Errorf("%w: heartbeat lease", ErrLease)
	}
	var lease AcquisitionLeaseV1
	if err := json.Unmarshal(envelope.Lease, &lease); err != nil {
		return fmt.Errorf("%w: heartbeat lease", ErrLease)
	}
	if err := lease.validate(); err != nil {
		return err
	}
	key, err := lease.AdmissionAuthorityKey()
	if err != nil {
		return err
	}
	deadline, err := LocalLeaseDeadline(
		sendAnchor,
		time.Duration(lease.DurationMs)*time.Millisecond,
		margin,
	)
	if err != nil {
		return err
	}
	return cache.Install(CachedLease{
		Lease:         lease,
		Key:           key,
		Sequence:      envelope.Sequence,
		Fence:         fence,
		LocalDeadline: deadline,
		SendAnchor:    sendAnchor,
	})
}
