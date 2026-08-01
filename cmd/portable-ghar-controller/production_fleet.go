package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync/atomic"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/fleetfence"
)

const localFleetProofDomain = "portable-ghar-local-fleet-proof-v1\x00"

type productionFleetAuthorityConfig struct {
	Inspector    fleetfence.Inspector
	Transitions  observerTransitioner
	Fleet        fleetfence.Fleet
	Generation   uint64
	OwnerID      string
	PID          int
	GuardFailure <-chan error
	Timeout      time.Duration
	Now          func() time.Time
}

type productionFleetAuthority struct {
	inspector    fleetfence.Inspector
	transitions  observerTransitioner
	fleet        fleetfence.Fleet
	generation   uint64
	ownerID      string
	pid          int
	guardFailure <-chan error
	timeout      time.Duration
	now          func() time.Time
	sequence     atomic.Uint64
}

var _ fleetAuthority = (*productionFleetAuthority)(nil)

func newProductionFleetAuthority(
	config productionFleetAuthorityConfig,
) (*productionFleetAuthority, error) {
	if config.Inspector == nil ||
		config.Transitions == nil ||
		config.Generation == 0 ||
		config.Timeout <= 0 ||
		config.Now == nil {
		return nil, errDisabledFleetAuthority
	}
	switch config.Fleet {
	case fleetfence.FleetPortable:
		if !validLocalScalar(config.OwnerID) ||
			config.PID <= 0 ||
			config.GuardFailure == nil {
			return nil, errDisabledFleetAuthority
		}
	case fleetfence.FleetLegacy:
		if config.OwnerID != "" ||
			config.PID != 0 ||
			config.GuardFailure != nil {
			return nil, errDisabledFleetAuthority
		}
	default:
		return nil, errDisabledFleetAuthority
	}
	return &productionFleetAuthority{
		inspector:    config.Inspector,
		transitions:  config.Transitions,
		fleet:        config.Fleet,
		generation:   config.Generation,
		ownerID:      config.OwnerID,
		pid:          config.PID,
		guardFailure: config.GuardFailure,
		timeout:      config.Timeout,
		now:          config.Now,
	}, nil
}

func (authority *productionFleetAuthority) Observe(
	ctx context.Context,
) (fleetAuthorityProof, error) {
	if authority == nil || ctx == nil || ctx.Err() != nil {
		return fleetAuthorityProof{}, errDisabledFleetAuthority
	}
	if authority.guardFailure != nil {
		select {
		case err, ok := <-authority.guardFailure:
			if !ok || err != nil {
				return fleetAuthorityProof{}, errors.Join(
					errDisabledFleetAuthority,
					err,
				)
			}
			return fleetAuthorityProof{}, errDisabledFleetAuthority
		default:
		}
	}
	callCtx, cancel := context.WithTimeout(ctx, authority.timeout)
	defer cancel()
	snapshot, err := authority.inspector.Inspect(callCtx)
	if err != nil ||
		snapshot.Header.ActiveFleet != authority.fleet ||
		snapshot.Header.Generation != authority.generation {
		return fleetAuthorityProof{}, errors.Join(
			errDisabledFleetAuthority,
			err,
		)
	}
	at := authority.now()
	if at.IsZero() {
		return fleetAuthorityProof{}, errDisabledFleetAuthority
	}
	sequence, ok := nextObservationSequence(&authority.sequence)
	if !ok {
		return fleetAuthorityProof{}, errDisabledFleetAuthority
	}
	proof := fleetAuthorityProof{
		Sequence:   sequence,
		ObservedAt: at,
		Fleet:      authority.fleet,
		Generation: authority.generation,
	}
	switch authority.fleet {
	case fleetfence.FleetPortable:
		if len(snapshot.Holders) != 1 {
			return fleetAuthorityProof{}, errDisabledFleetAuthority
		}
		holder := snapshot.Holders[0]
		if holder.Generation != authority.generation ||
			holder.Fleet != fleetfence.FleetPortable ||
			holder.OwnerID != authority.ownerID ||
			holder.PID != authority.pid ||
			!validLocalScalar(holder.BootID) ||
			!validLocalScalar(holder.ProcessStartID) {
			return fleetAuthorityProof{}, errDisabledFleetAuthority
		}
		token, err := localFleetProofToken(holder)
		if err != nil {
			return fleetAuthorityProof{}, errDisabledFleetAuthority
		}
		proof.SelfGuardToken = token
	case fleetfence.FleetLegacy:
		if len(snapshot.Holders) != 0 {
			return fleetAuthorityProof{}, errDisabledFleetAuthority
		}
		policy, err := authority.transitions.Snapshot(callCtx)
		if err != nil {
			return fleetAuthorityProof{}, errors.Join(
				errDisabledFleetAuthority,
				err,
			)
		}
		policy, err = controller.CanonicalizeAcquisitionPolicy(policy)
		if err != nil ||
			policy.Mode != controller.AcquisitionDisabled ||
			policy.MaxCapacity != 0 ||
			len(policy.EligibleScaleSets) != 0 ||
			policy.Epoch == 0 ||
			policy.RepositoryPolicyRevision == 0 ||
			len(policy.RepositoryPolicies) == 0 {
			return fleetAuthorityProof{}, errDisabledFleetAuthority
		}
		digest, err := controller.AcquisitionPolicyDigest(policy)
		if err != nil {
			return fleetAuthorityProof{}, errDisabledFleetAuthority
		}
		proof.LegacyProof = &fleetfence.LegacyObserverProof{
			FleetGeneration: authority.generation,
			PolicyEpoch:     policy.Epoch,
			PolicyDigest:    hex.EncodeToString(digest[:]),
		}
	default:
		return fleetAuthorityProof{}, errDisabledFleetAuthority
	}
	return proof, nil
}

func localFleetProofToken(
	holder fleetfence.HolderIdentity,
) (string, error) {
	document, err := json.Marshal(holder)
	if err != nil {
		return "", errDisabledFleetAuthority
	}
	sum := sha256.Sum256(append([]byte(localFleetProofDomain), document...))
	return hex.EncodeToString(sum[:]), nil
}
