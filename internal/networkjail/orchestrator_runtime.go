package networkjail

import (
	"context"
	"errors"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/redaction"
)

type adapterRuntimeRef struct {
	handle hostruntime.AdapterHandle
	id     string
	valid  bool
}

type brokerRuntimeRef struct {
	handle hostruntime.BrokerHandle
	id     string
	valid  bool
}

type runnerRuntimeRef struct {
	handle hostruntime.RunnerHandle
	id     string
	valid  bool
}

type brokerPeerRuntimeRef struct {
	proof hostruntime.BrokerPeerProof
	valid bool
}

type namespaceRuntimeRef struct {
	proof hostruntime.NetworkNamespaceProof
	valid bool
}

type heldRunnerAuditRuntimeRef struct {
	proof  hostruntime.HeldRunnerAudit
	digest string
	valid  bool
}

type releaseAuthorizationRuntimeRef struct {
	proof hostruntime.ReleaseAuthorization
	valid bool
}

type brokerAuditRuntimeRef struct {
	proof  hostruntime.BrokerAudit
	digest string
	valid  bool
}

// setupRuntime is deliberately private. The production adapter below is the
// only external-engine bridge; package tests can inject a typed fake without
// weakening hostruntime's opaque handle constructors.
type setupRuntime interface {
	CreateAdapter(context.Context, hostruntime.AdapterSpec) (adapterRuntimeRef, error)
	CreateBroker(context.Context, adapterRuntimeRef, hostruntime.BrokerSpec) (brokerRuntimeRef, error)
	ApplyPolicy(context.Context, brokerRuntimeRef, hostruntime.PolicyArtifact) error
	BindAuthority(context.Context, brokerRuntimeRef, authorityLease) error
	ReleaseBroker(context.Context, brokerRuntimeRef) (brokerPeerRuntimeRef, error)
	BindBrokerPeer(context.Context, adapterRuntimeRef, brokerPeerRuntimeRef) error
	AuditBroker(context.Context, brokerRuntimeRef) (brokerAuditRuntimeRef, error)
	CreateRunner(context.Context, adapterRuntimeRef, hostruntime.RunnerSpec) (runnerRuntimeRef, error)
	HydrateSeeds(context.Context, runnerRuntimeRef, []string) error
	ProbeNamespace(context.Context, runnerRuntimeRef, hostruntime.GateOperation) (namespaceRuntimeRef, error)
	ArmRunner(context.Context, runnerRuntimeRef) error
	AuditHeldRunner(context.Context, runnerRuntimeRef) (heldRunnerAuditRuntimeRef, error)
	AuthorizeRelease(context.Context, runnerRuntimeRef, namespaceRuntimeRef, namespaceRuntimeRef) (releaseAuthorizationRuntimeRef, error)
	ReleaseRunner(context.Context, runnerRuntimeRef, releaseAuthorizationRuntimeRef, *redaction.Secret) error
	RemoveRunner(context.Context, runnerRuntimeRef) error
	RemoveBroker(context.Context, brokerRuntimeRef) error
	RemoveAdapter(context.Context, adapterRuntimeRef) error
}

type hostSetupRuntime struct {
	engine hostruntime.Engine
}

func newHostSetupRuntime(engine hostruntime.Engine) (*hostSetupRuntime, error) {
	if engine == nil {
		return nil, errors.New("networkjail: host runtime required")
	}
	return &hostSetupRuntime{engine: engine}, nil
}

func (r *hostSetupRuntime) CreateAdapter(
	ctx context.Context,
	spec hostruntime.AdapterSpec,
) (adapterRuntimeRef, error) {
	handle, err := r.engine.CreateNetworkAdapter(ctx, spec)
	return adapterRuntimeRef{handle: handle, id: handle.ID(), valid: err == nil && handle.ID() != ""}, err
}

func (r *hostSetupRuntime) CreateBroker(
	ctx context.Context,
	adapter adapterRuntimeRef,
	spec hostruntime.BrokerSpec,
) (brokerRuntimeRef, error) {
	if !adapter.valid {
		return brokerRuntimeRef{}, errors.New("networkjail: adapter reference invalid")
	}
	spec.Adapter = adapter.handle
	handle, err := r.engine.CreateNetworkBrokerHeld(ctx, spec)
	return brokerRuntimeRef{handle: handle, id: handle.ID(), valid: handle.ID() != ""}, err
}

func (r *hostSetupRuntime) ApplyPolicy(
	ctx context.Context,
	broker brokerRuntimeRef,
	policy hostruntime.PolicyArtifact,
) error {
	if !broker.valid {
		return errors.New("networkjail: broker reference invalid")
	}
	return r.engine.ApplyNetworkPolicy(ctx, broker.handle, policy)
}

func (r *hostSetupRuntime) BindAuthority(
	ctx context.Context,
	broker brokerRuntimeRef,
	lease authorityLease,
) error {
	if !broker.valid || !lease.valid {
		return errors.New("networkjail: authority binding invalid")
	}
	return r.engine.BindDialAuthority(ctx, broker.handle, lease.proof)
}

func (r *hostSetupRuntime) ReleaseBroker(
	ctx context.Context,
	broker brokerRuntimeRef,
) (brokerPeerRuntimeRef, error) {
	if !broker.valid {
		return brokerPeerRuntimeRef{}, errors.New("networkjail: broker reference invalid")
	}
	proof, err := r.engine.ReleaseNetworkBroker(ctx, broker.handle)
	return brokerPeerRuntimeRef{proof: proof, valid: err == nil}, err
}

func (r *hostSetupRuntime) BindBrokerPeer(
	ctx context.Context,
	adapter adapterRuntimeRef,
	peer brokerPeerRuntimeRef,
) error {
	if !adapter.valid || !peer.valid {
		return errors.New("networkjail: broker peer reference invalid")
	}
	return r.engine.BindBrokerPeer(ctx, adapter.handle, peer.proof)
}

func (r *hostSetupRuntime) AuditBroker(
	ctx context.Context,
	broker brokerRuntimeRef,
) (brokerAuditRuntimeRef, error) {
	if !broker.valid {
		return brokerAuditRuntimeRef{}, errors.New("networkjail: broker reference invalid")
	}
	audit, err := r.engine.AuditNetworkBroker(ctx, broker.handle)
	return brokerAuditRuntimeRef{
		proof: audit, digest: audit.Digest(),
		valid: err == nil && audit.Digest() != "",
	}, err
}

func (r *hostSetupRuntime) CreateRunner(
	ctx context.Context,
	adapter adapterRuntimeRef,
	spec hostruntime.RunnerSpec,
) (runnerRuntimeRef, error) {
	if !adapter.valid {
		return runnerRuntimeRef{}, errors.New("networkjail: adapter reference invalid")
	}
	spec.Adapter = adapter.handle
	handle, err := r.engine.CreateRunner(ctx, spec)
	return runnerRuntimeRef{handle: handle, id: handle.ID(), valid: err == nil && handle.ID() != ""}, err
}

func (r *hostSetupRuntime) HydrateSeeds(
	ctx context.Context,
	runner runnerRuntimeRef,
	ids []string,
) error {
	if !runner.valid {
		return errors.New("networkjail: runner reference invalid")
	}
	return r.engine.HydrateSeeds(ctx, runner.handle, ids)
}

func (r *hostSetupRuntime) ProbeNamespace(
	ctx context.Context,
	runner runnerRuntimeRef,
	operation hostruntime.GateOperation,
) (namespaceRuntimeRef, error) {
	if !runner.valid {
		return namespaceRuntimeRef{}, errors.New("networkjail: runner reference invalid")
	}
	proof, err := r.engine.ProbeRunnerNetworkNamespace(ctx, runner.handle, operation)
	return namespaceRuntimeRef{proof: proof, valid: err == nil}, err
}

func (r *hostSetupRuntime) ArmRunner(
	ctx context.Context,
	runner runnerRuntimeRef,
) error {
	if !runner.valid {
		return errors.New("networkjail: runner reference invalid")
	}
	return r.engine.ArmRunner(ctx, runner.handle)
}

func (r *hostSetupRuntime) AuditHeldRunner(
	ctx context.Context,
	runner runnerRuntimeRef,
) (heldRunnerAuditRuntimeRef, error) {
	if !runner.valid {
		return heldRunnerAuditRuntimeRef{}, errors.New("networkjail: runner reference invalid")
	}
	proof, err := r.engine.AuditHeldRunner(ctx, runner.handle)
	return heldRunnerAuditRuntimeRef{
		proof: proof, digest: proof.Digest(),
		valid: err == nil && proof.Digest() != "",
	}, err
}

func (r *hostSetupRuntime) AuthorizeRelease(
	ctx context.Context,
	runner runnerRuntimeRef,
	pre, final namespaceRuntimeRef,
) (releaseAuthorizationRuntimeRef, error) {
	if !runner.valid || !pre.valid || !final.valid {
		return releaseAuthorizationRuntimeRef{}, errors.New("networkjail: namespace proof invalid")
	}
	proof, err := r.engine.AuthorizeRelease(
		ctx,
		runner.handle,
		pre.proof,
		final.proof,
	)
	return releaseAuthorizationRuntimeRef{proof: proof, valid: err == nil}, err
}

func (r *hostSetupRuntime) ReleaseRunner(
	ctx context.Context,
	runner runnerRuntimeRef,
	authorization releaseAuthorizationRuntimeRef,
	jit *redaction.Secret,
) error {
	if !runner.valid || !authorization.valid {
		if jit != nil {
			jit.Destroy()
		}
		return errors.New("networkjail: runner release authority invalid")
	}
	return r.engine.ReleaseRunner(ctx, runner.handle, authorization.proof, jit)
}

func (r *hostSetupRuntime) RemoveRunner(
	ctx context.Context,
	runner runnerRuntimeRef,
) error {
	if !runner.valid {
		return nil
	}
	return r.engine.RemoveRunner(ctx, runner.handle)
}

func (r *hostSetupRuntime) RemoveBroker(
	ctx context.Context,
	broker brokerRuntimeRef,
) error {
	if !broker.valid {
		return nil
	}
	return r.engine.RemoveNetworkBroker(ctx, broker.handle)
}

func (r *hostSetupRuntime) RemoveAdapter(
	ctx context.Context,
	adapter adapterRuntimeRef,
) error {
	if !adapter.valid {
		return nil
	}
	return r.engine.RemoveNetworkAdapter(ctx, adapter.handle)
}
