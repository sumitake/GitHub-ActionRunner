package testenv

import (
	"context"
	"crypto/sha256"
	"sync"
)

type task11RuntimeSessionSource struct {
	composition fixtureRuntimeComposition
	prepared    task11PreparedRuntimeSource

	mu             sync.Mutex
	closedStarted  bool
	closedReady    bool
	captureStarted bool
	failed         bool
	primary        fixtureRuntimeObservation
	flood          fixtureFloodObservation
	closed         closedDenialsSessionObservation
	network        *networkSession
}

func newTask11RuntimeSessionSource(
	composition fixtureRuntimeComposition,
	prepared task11PreparedRuntimeSource,
) (*task11RuntimeSessionSource, error) {
	if prepared == nil ||
		composition.ClosedSurface == nil ||
		composition.OneShotRecorder == nil ||
		composition.OneShotLeases == nil ||
		composition.Request.Graph.Digest().String() == "" ||
		composition.Request.Verifier.Image == "" ||
		composition.Request.Verifier.User == "" ||
		composition.RunnerUser == "" ||
		composition.MaximumEvidence == 0 ||
		!validMatrixEvidenceBinding(composition.MatrixBinding) ||
		composition.MatrixBinding.GraphDigest !=
			composition.Request.Graph.Digest().String() {
		return nil, ErrFixtureStart
	}
	return &task11RuntimeSessionSource{
		composition: composition,
		prepared:    prepared,
	}, nil
}

func (s *task11RuntimeSessionSource) ObserveClosedDenials(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
) (closedDenialsSessionObservation, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return closedDenialsSessionObservation{}, ErrFixtureStart
	}
	s.mu.Lock()
	if s.closedStarted || s.closedReady || s.failed {
		s.mu.Unlock()
		return closedDenialsSessionObservation{}, ErrFixtureStart
	}
	s.closedStarted = true
	s.mu.Unlock()

	flood, err := s.prepared.SnapshotPreparedEvidence(ctx, prepared)
	if err != nil ||
		!validFixtureRuntimeObservation(prepared) ||
		!validFixtureFloodObservation(
			flood,
			s.composition.FloodAttempts,
		) ||
		!s.matchesPrepared(prepared) {
		s.markFailed()
		return closedDenialsSessionObservation{}, ErrFixtureStart
	}
	binding := networkSessionBinding{
		Adapter:            prepared.Adapter,
		Broker:             prepared.Broker,
		RunDigest:          s.composition.MatrixBinding.RunID,
		BuildID:            s.composition.MatrixBinding.BuildID,
		FleetGeneration:    s.composition.MatrixBinding.FleetGeneration,
		SlotIdentity:       s.composition.MatrixBinding.SlotIdentity,
		VerifierImage:      s.composition.Request.Verifier.Image,
		VerifierUser:       s.composition.Request.Verifier.User,
		VerifierSeccomp:    s.composition.Request.Verifier.Seccomp,
		VerifierLimits:     s.composition.Request.Verifier.Limits,
		VerifierSpecDigest: prepared.VerifierSpecDigest,
		Graph:              s.composition.Request.Graph,
	}
	network, err := newNetworkSession(
		s.composition.ClosedSurface,
		binding,
		s.composition.OneShotLeases,
	)
	if err != nil {
		s.markFailed()
		return closedDenialsSessionObservation{}, ErrFixtureStart
	}
	observation, err := network.ObserveClosedDenials(ctx)
	if err != nil ||
		!validClosedDenialsSessionObservation(
			observation,
			binding.Graph,
		) {
		s.markFailed()
		return closedDenialsSessionObservation{}, ErrFixtureStart
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed || s.closedReady || s.captureStarted {
		s.failed = true
		return closedDenialsSessionObservation{}, ErrFixtureStart
	}
	s.primary = prepared
	s.flood = flood
	s.closed = observation
	s.network = network
	s.closedReady = true
	return observation, nil
}

func (s *task11RuntimeSessionSource) CaptureCaseFour(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
	flood fixtureFloodObservation,
	closed closedDenialsSessionObservation,
) (task11CaseFourRuntimeCapture, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return task11CaseFourRuntimeCapture{}, ErrFixtureStart
	}
	s.mu.Lock()
	if s.failed ||
		!s.closedReady ||
		s.captureStarted ||
		s.network == nil ||
		prepared != s.primary ||
		flood != s.flood ||
		closed != s.closed {
		s.failed = true
		s.mu.Unlock()
		return task11CaseFourRuntimeCapture{}, ErrFixtureStart
	}
	s.captureStarted = true
	network := s.network
	s.mu.Unlock()

	recheckedFlood, err := s.prepared.SnapshotPreparedEvidence(
		ctx,
		prepared,
	)
	if err != nil || recheckedFlood != flood ||
		!s.matchesPrepared(prepared) {
		s.markFailed()
		return task11CaseFourRuntimeCapture{}, ErrFixtureStart
	}
	runner, err := newRunnerSession(
		s.composition.ClosedSurface,
		runnerSessionBinding{
			Runner: prepared.Runner,
			User:   s.composition.RunnerUser,
		},
	)
	if err != nil {
		s.markFailed()
		return task11CaseFourRuntimeCapture{}, ErrFixtureStart
	}
	matrix, err := newMatrixScannerCaptureSource(
		s.composition.MatrixBinding,
	)
	if err != nil {
		s.markFailed()
		return task11CaseFourRuntimeCapture{}, ErrFixtureStart
	}
	scanner, err := newClosedRuntimeSurfaceScanner(
		s.composition.MaximumEvidence,
	)
	if err != nil {
		s.markFailed()
		return task11CaseFourRuntimeCapture{}, ErrFixtureStart
	}
	bound, err := newBoundTask11CaseFourRuntimeScanner(
		network,
		runner,
		s.composition.OneShotRecorder,
		matrix,
		scanner,
		prepared,
		flood,
		closed,
	)
	if err != nil {
		s.markFailed()
		return task11CaseFourRuntimeCapture{}, ErrFixtureStart
	}
	capture, err := bound.CaptureCaseFour(
		ctx,
		prepared,
		flood,
		closed,
	)
	if err != nil {
		s.markFailed()
		return task11CaseFourRuntimeCapture{}, ErrFixtureStart
	}
	return capture, nil
}

func (s *task11RuntimeSessionSource) matchesPrepared(
	prepared fixtureRuntimeObservation,
) bool {
	if s == nil || !validFixtureRuntimeObservation(prepared) {
		return false
	}
	request := s.composition.Request
	matrix := s.composition.MatrixBinding
	return prepared.PolicyDigest == request.Graph.Digest().String() &&
		prepared.VerifierSpecDigest != "" &&
		isLowerHex(prepared.VerifierSpecDigest, sha256.Size*2) &&
		matrix.RunID != "" &&
		matrix.BuildID == request.Adapter.BuildID &&
		matrix.BuildID == request.Broker.BuildID &&
		matrix.BuildID == request.Runner.BuildID &&
		matrix.BuildID == request.Verifier.BuildID &&
		matrix.FleetGeneration == request.Adapter.FleetGeneration &&
		matrix.FleetGeneration == request.Broker.FleetGeneration &&
		matrix.FleetGeneration == request.Runner.FleetGeneration &&
		matrix.FleetGeneration == request.Verifier.FleetGeneration &&
		matrix.SlotIdentity == request.Adapter.SlotIdentity &&
		matrix.SlotIdentity == request.Broker.SlotIdentity &&
		matrix.SlotIdentity == request.Runner.SlotIdentity &&
		matrix.SlotIdentity == request.Verifier.SlotIdentity
}

func (s *task11RuntimeSessionSource) markFailed() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.failed = true
	s.mu.Unlock()
}

var (
	_ task11ClosedDenialsSource   = (*task11RuntimeSessionSource)(nil)
	_ task11CaseFourCaptureSource = (*task11RuntimeSessionSource)(nil)
)
