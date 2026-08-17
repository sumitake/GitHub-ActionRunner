package main

import (
	"context"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/failoverclient"
	"github.com/sumitake/portable-ghar/internal/fleetfence"
	"github.com/sumitake/portable-ghar/internal/githubscale"
	"github.com/sumitake/portable-ghar/internal/health"
)

type productionExternalGraphConfig struct {
	Fleet  fleetfence.Fleet
	Holder failoverclient.LeaseHolder
	Fence  uint64
	Clock  failoverclient.AuthorityClock
	Cache  *failoverclient.LeaseCache
}

type productionExternalGraph struct {
	holder  failoverclient.LeaseHolder
	permits failoverclient.CachedLeasePermitProvider
}

var _ disabledExternalGraph = (*productionExternalGraph)(nil)

func newProductionExternalGraph(
	config productionExternalGraphConfig,
) (*productionExternalGraph, error) {
	holder := config.Holder
	if holder == "" {
		if config.Fleet == fleetfence.FleetLegacy {
			holder = failoverclient.HolderLegacy
		} else {
			holder = failoverclient.HolderPortable
		}
	}
	clock := config.Clock
	if clock == nil {
		productionClock, err := failoverclient.NewProductionAuthorityClock()
		if err != nil {
			return nil, err
		}
		clock = productionClock
	}
	cache := config.Cache
	if cache == nil {
		cache = &failoverclient.LeaseCache{}
	}
	if config.Fence == 0 || (holder != failoverclient.HolderPortable &&
		holder != failoverclient.HolderLegacy) {
		return nil, errDisabledExternalUnavailable
	}
	return &productionExternalGraph{
		holder: holder,
		permits: failoverclient.CachedLeasePermitProvider{
			Cache:  cache,
			Clock:  clock,
			Holder: holder,
			Fence:  config.Fence,
		},
	}, nil
}

func (graph *productionExternalGraph) Holder() failoverclient.LeaseHolder {
	if graph == nil {
		return ""
	}
	return graph.holder
}

func (graph *productionExternalGraph) InstallLease(
	entry failoverclient.CachedLease,
) error {
	if graph == nil || graph.permits.Cache == nil {
		return errDisabledExternalUnavailable
	}
	return graph.permits.Cache.Install(entry)
}

func (graph *productionExternalGraph) Acquire(
	ctx context.Context,
	request controller.AcquisitionPermitRequest,
) (controller.AcquisitionGuard, error) {
	if graph == nil {
		return nil, errDisabledExternalUnavailable
	}
	return graph.permits.Acquire(ctx, request)
}

func (*productionExternalGraph) VerifyCurrentOffer(
	context.Context,
	githubscale.Fleet,
	githubscale.Offer,
) (controller.ReplayVerification, error) {
	return 0, errDisabledExternalUnavailable
}

func (*productionExternalGraph) Readiness(
	context.Context,
	string,
	uint64,
) (controller.HostedReadinessProof, error) {
	return controller.HostedReadinessProof{}, errDisabledExternalUnavailable
}

func (*productionExternalGraph) RouteHosted(
	context.Context,
	controller.AssignmentKey,
	string,
	controller.HostedReason,
) (string, error) {
	return "", errDisabledExternalUnavailable
}

func (*productionExternalGraph) Publish(
	context.Context,
	health.Snapshot,
) error {
	return errDisabledExternalUnavailable
}

func (*productionExternalGraph) PollTargets() []controller.PollTarget {
	return nil
}
