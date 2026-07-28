//go:build linux || darwin

package networkjail

import "github.com/sumitake/portable-ghar/internal/hostruntime"

// NewOrchestrator constructs the production network-jail transaction from the
// closed host runtime, durable journal, and Unix dial-authority manager.
func NewOrchestrator(
	engine hostruntime.Engine,
	journal LifecycleJournal,
	authority *UnixAuthorityManager,
) (*Orchestrator, error) {
	runtime, err := newHostSetupRuntime(engine)
	if err != nil {
		return nil, err
	}
	verifier, err := newHostSetupVerifier(engine)
	if err != nil {
		return nil, err
	}
	return newOrchestrator(runtime, journal, authority, verifier)
}
