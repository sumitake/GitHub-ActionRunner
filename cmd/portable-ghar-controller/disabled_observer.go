package main

import (
	"context"
	"errors"

	"github.com/sumitake/portable-ghar/internal/controller"
)

var errDisabledObserverInvalid = errors.New(
	"portable-ghar-controller: disabled observer invalid",
)

type observerTransitioner interface {
	Snapshot(context.Context) (controller.AcquisitionPolicy, error)
	Transition(
		context.Context,
		uint64,
		controller.AcquisitionPolicy,
	) (controller.AcquisitionPolicy, error)
}

func sameObserverPolicy(
	actual controller.AcquisitionPolicy,
	desired controller.AcquisitionPolicy,
) bool {
	actual.Epoch = 0
	canonical, err := controller.CanonicalizeAcquisitionPolicy(actual)
	if err != nil {
		return false
	}
	canonical.Epoch = 0
	if canonical.Mode != desired.Mode ||
		canonical.MaxCapacity != desired.MaxCapacity ||
		canonical.RepositoryPolicyRevision !=
			desired.RepositoryPolicyRevision ||
		len(canonical.EligibleScaleSets) !=
			len(desired.EligibleScaleSets) ||
		len(canonical.RepositoryPolicies) !=
			len(desired.RepositoryPolicies) {
		return false
	}
	for index := range canonical.EligibleScaleSets {
		if canonical.EligibleScaleSets[index] !=
			desired.EligibleScaleSets[index] {
			return false
		}
	}
	for index := range canonical.RepositoryPolicies {
		if canonical.RepositoryPolicies[index] !=
			desired.RepositoryPolicies[index] {
			return false
		}
	}
	return true
}

func cloneObserverDesired(
	policy controller.AcquisitionPolicy,
) controller.AcquisitionPolicy {
	policy.EligibleScaleSets = append(
		[]string(nil),
		policy.EligibleScaleSets...,
	)
	policy.RepositoryPolicies = append(
		[]controller.RepositoryPolicySummary(nil),
		policy.RepositoryPolicies...,
	)
	return policy
}
