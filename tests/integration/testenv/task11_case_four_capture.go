package testenv

import (
	"context"
	"sync"
)

type boundTask11CaseFourRuntimeScanner struct {
	network  *networkSession
	runner   *runnerSession
	oneShots *task11OneShotRecorder
	matrix   *matrixScannerCaptureSource
	scanner  *closedRuntimeSurfaceScanner

	prepared    fixtureRuntimeObservation
	flood       fixtureFloodObservation
	closed      closedDenialsSessionObservation
	primarySeal string

	mu      sync.Mutex
	started bool
}

func newBoundTask11CaseFourRuntimeScanner(
	network *networkSession,
	runner *runnerSession,
	oneShots *task11OneShotRecorder,
	matrix *matrixScannerCaptureSource,
	scanner *closedRuntimeSurfaceScanner,
	prepared fixtureRuntimeObservation,
	flood fixtureFloodObservation,
	closed closedDenialsSessionObservation,
) (*boundTask11CaseFourRuntimeScanner, error) {
	if network == nil ||
		runner == nil ||
		network.surface == nil ||
		runner.surface != network.surface ||
		oneShots == nil ||
		matrix == nil ||
		scanner == nil ||
		scanner.maximumSurfaceBytes == 0 ||
		network.binding.Adapter != prepared.Adapter ||
		network.binding.Broker != prepared.Broker ||
		network.binding.VerifierSpecDigest !=
			prepared.VerifierSpecDigest ||
		network.binding.Graph.Digest().String() !=
			prepared.PolicyDigest ||
		runner.binding.Runner != prepared.Runner ||
		matrix.binding.RunID != network.binding.RunDigest ||
		matrix.binding.BuildID != network.binding.BuildID ||
		matrix.binding.FleetGeneration !=
			network.binding.FleetGeneration ||
		matrix.binding.SlotIdentity !=
			network.binding.SlotIdentity ||
		matrix.binding.GraphDigest != prepared.PolicyDigest ||
		!validClosedDenialsSessionObservation(
			closed,
			network.binding.Graph,
		) ||
		network.name != closed.Name ||
		network.cleanup != closed.Cleanup ||
		!task11OneShotBindingMatchesNetwork(
			oneShots.binding,
			network.binding,
			network.surface.config.DockerPath,
		) {
		return nil, ErrFixtureStart
	}
	primarySeal, err := task11PreparedObservationSeal(
		prepared,
		flood,
	)
	if err != nil {
		return nil, ErrFixtureStart
	}
	return &boundTask11CaseFourRuntimeScanner{
		network:     network,
		runner:      runner,
		oneShots:    oneShots,
		matrix:      matrix,
		scanner:     scanner,
		prepared:    prepared,
		flood:       flood,
		closed:      closed,
		primarySeal: primarySeal,
	}, nil
}

func (s *boundTask11CaseFourRuntimeScanner) CaptureCaseFour(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
	flood fixtureFloodObservation,
	closed closedDenialsSessionObservation,
) (task11CaseFourRuntimeCapture, error) {
	if s == nil {
		return task11CaseFourRuntimeCapture{}, ErrFixtureStart
	}
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return task11CaseFourRuntimeCapture{}, ErrFixtureStart
	}
	s.started = true
	s.mu.Unlock()

	seal, err := task11PreparedObservationSeal(prepared, flood)
	if ctx == nil ||
		ctx.Err() != nil ||
		err != nil ||
		seal != s.primarySeal ||
		!sameTask11PreparedObservation(
			prepared,
			s.prepared,
			flood,
		) ||
		flood != s.flood ||
		closed != s.closed ||
		!task11OneShotRecorderMatchesPrepared(
			s.oneShots,
			prepared,
		) {
		return task11CaseFourRuntimeCapture{}, ErrFixtureStart
	}

	runnerObservation, err := s.runner.Observe(ctx)
	if err != nil ||
		!validRunnerSessionObservation(
			runnerObservation,
			s.runner.binding.User,
		) {
		return task11CaseFourRuntimeCapture{}, ErrFixtureStart
	}
	session, err := newScannerSession(
		s.network.surface,
		scannerSessionBinding{
			Adapter: prepared.Adapter,
			Broker:  prepared.Broker,
			Runner:  prepared.Runner,
		},
		s.runner,
	)
	if err != nil {
		return task11CaseFourRuntimeCapture{}, ErrFixtureStart
	}
	commandCapture, err := session.Capture(ctx)
	if err != nil {
		return task11CaseFourRuntimeCapture{}, ErrFixtureStart
	}
	closedDocument, err := s.network.takeScannerDocument()
	if err != nil {
		destroyScannerCapture(&commandCapture)
		return task11CaseFourRuntimeCapture{}, ErrFixtureStart
	}
	oneShotCapture, err := s.oneShots.Take()
	if err != nil {
		destroyScannerCapture(&commandCapture)
		zeroClosedBytes(closedDocument)
		return task11CaseFourRuntimeCapture{}, ErrFixtureStart
	}
	matrixCapture, err := s.matrix.Take()
	if err != nil {
		destroyScannerCapture(&commandCapture)
		zeroClosedBytes(closedDocument)
		destroyClosedRuntimeSurfaces(oneShotCapture.surfaces)
		return task11CaseFourRuntimeCapture{}, ErrFixtureStart
	}
	commandDigest := oneShotCapture.commandDigest
	mountAbsenceDigest := oneShotCapture.mountAbsenceDigest
	supplements := scannerSupplementInput{
		Prepared:          prepared,
		Flood:             flood,
		Graph:             s.network.binding.Graph,
		ClosedDenials:     closed,
		ClosedDocument:    closedDocument,
		RunnerConformance: runnerObservation.Conformance,
		OneShots:          oneShotCapture,
		MatrixDocuments:   matrixCapture,
	}
	scan, err := s.scanner.ScanCompleteCapture(
		&commandCapture,
		&supplements,
	)
	if err != nil ||
		scan.Version != 1 ||
		scan.SurfaceCount != completeRuntimeSurfaceCount ||
		!scan.Clean {
		return task11CaseFourRuntimeCapture{}, ErrFixtureStart
	}
	capture := task11CaseFourRuntimeCapture{
		RunnerUser:                s.runner.binding.User,
		Runner:                    runnerObservation,
		Scan:                      scan,
		OneShotCommandDigest:      commandDigest,
		OneShotMountAbsenceDigest: mountAbsenceDigest,
	}
	if !validTask11CaseFourRuntimeCapture(
		capture,
		s.runner.binding.User,
	) {
		return task11CaseFourRuntimeCapture{}, ErrFixtureStart
	}
	return capture, nil
}

func task11OneShotBindingMatchesNetwork(
	oneShots task11OneShotRecorderBinding,
	network networkSessionBinding,
	dockerPath string,
) bool {
	return validTask11OneShotRecorderBinding(oneShots) &&
		oneShots.DockerPath == dockerPath &&
		oneShots.Verifier.Image == network.VerifierImage &&
		oneShots.Verifier.BuildID == network.BuildID &&
		oneShots.Verifier.FleetGeneration ==
			network.FleetGeneration &&
		oneShots.Verifier.SlotIdentity ==
			network.SlotIdentity &&
		oneShots.Verifier.User == network.VerifierUser &&
		oneShots.Verifier.SeccompPath ==
			network.VerifierSeccomp.Path &&
		oneShots.Verifier.Limits == network.VerifierLimits
}

func task11OneShotRecorderMatchesPrepared(
	recorder *task11OneShotRecorder,
	prepared fixtureRuntimeObservation,
) bool {
	if recorder == nil {
		return false
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return !recorder.failed &&
		!recorder.taken &&
		recorder.step == len(oneShotRuntimeSurfaceOrder()) &&
		recorder.repeatedBrokerAudit &&
		recorder.adapterID == prepared.Adapter.id &&
		recorder.brokerID == prepared.Broker.id &&
		recorder.runnerID == prepared.Runner.id
}

var _ task11CaseFourCaptureSource = (*boundTask11CaseFourRuntimeScanner)(nil)
