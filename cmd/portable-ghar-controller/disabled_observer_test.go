package main

import (
	"context"
	"errors"
	"sync"

	"github.com/sumitake/portable-ghar/internal/controller"
)

func disabledObserverPolicy() controller.AcquisitionPolicy {
	return controller.AcquisitionPolicy{
		Mode:                     controller.AcquisitionDisabled,
		EligibleScaleSets:        nil,
		MaxCapacity:              0,
		RepositoryPolicyRevision: 7,
		RepositoryPolicies: []controller.RepositoryPolicySummary{{
			Alias:          "repo-a",
			MaxConcurrency: 2,
			Eligibility:    "active",
		}},
	}
}

type observerTransitionFixture struct {
	mu          sync.Mutex
	policy      controller.AcquisitionPolicy
	transitions int
}

func (fixture *observerTransitionFixture) Snapshot(
	context.Context,
) (controller.AcquisitionPolicy, error) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return cloneObserverPolicy(fixture.policy), nil
}

func (fixture *observerTransitionFixture) Transition(
	_ context.Context,
	expected uint64,
	next controller.AcquisitionPolicy,
) (controller.AcquisitionPolicy, error) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.policy.Epoch != expected {
		return controller.AcquisitionPolicy{}, errors.New("epoch conflict")
	}
	fixture.transitions++
	next = cloneObserverPolicy(next)
	next.Epoch = expected + 1
	fixture.policy = next
	return cloneObserverPolicy(next), nil
}

func (fixture *observerTransitionFixture) TransitionCount() int {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return fixture.transitions
}

func cloneObserverPolicy(
	policy controller.AcquisitionPolicy,
) controller.AcquisitionPolicy {
	policy.EligibleScaleSets = append([]string(nil), policy.EligibleScaleSets...)
	policy.RepositoryPolicies = append(
		[]controller.RepositoryPolicySummary(nil),
		policy.RepositoryPolicies...,
	)
	return policy
}
