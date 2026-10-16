package main

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
)

var (
	errAcquisitionFatal     = errors.New("portable-ghar-controller: fatal state persisted")
	errAcquisitionFenceLost = errors.New("portable-ghar-controller: portable fence guard lost")
	errAcquisitionServer    = errors.New("portable-ghar-controller: local server failed")
	errAcquisitionOwnership = errors.New("portable-ghar-controller: database ownership lost")
)

// acquisitionService is what the process needs from controller.Service.
type acquisitionService interface {
	controller.LiveAdmin
	Run(context.Context) error
	Ready() bool
}

type acquisitionProcessConfig struct {
	WorkerLeaseGeneration func() uint64
	Service               acquisitionService
	FenceLost             <-chan struct{}
	// CloseSessions closes the GitHub sessions the service owns. The process
	// calls it on every path out of Run; closing an already closed session
	// does nothing.
	CloseSessions    func() error
	Resources        io.Closer
	Ownership        controllerOwnershipLease
	AdminSocketPath  string
	HealthSocketPath string
	ExpectedUID      uint32
	AdmissionLimit   int
	OperationTimeout time.Duration
	// OwnershipCheck is how often the run re-validates the database
	// ownership lock, so a replaced lock stops it before a second controller
	// can open the same database.
	OwnershipCheck  time.Duration
	DrainTimeout    time.Duration
	ShutdownTimeout time.Duration
}

// acquisitionControllerProcess runs the acquiring service and serves the same
// admin and health sockets as the disabled observer. Service.Run owns the
// service lifecycle, including startup recovery and the disabled epoch it
// records on the way out. The process stops it on a signal, a lost fence
// guard, a persisted fatal state, or a local server failure, and only the
// signal is a clean exit.
type acquisitionControllerProcess struct {
	config acquisitionProcessConfig

	mu          sync.Mutex
	runCancel   context.CancelFunc
	stopReason  error
	started     bool
	safeToClose bool
	closed      bool
}

var _ controllerProcess = (*acquisitionControllerProcess)(nil)

func (process *acquisitionControllerProcess) init(config acquisitionProcessConfig) error {
	if config.Service == nil ||
		config.CloseSessions == nil ||
		config.Resources == nil ||
		config.Ownership == nil ||
		config.AdminSocketPath == config.HealthSocketPath ||
		config.AdmissionLimit <= 0 ||
		config.OperationTimeout <= 0 ||
		config.OwnershipCheck <= 0 ||
		config.DrainTimeout <= 0 ||
		config.ShutdownTimeout <= 0 {
		return errCommandUnavailable
	}
	process.config = config
	return nil
}

// stop records the first reason the run must end and cancels it.
func (process *acquisitionControllerProcess) stop(reason error) {
	process.mu.Lock()
	if process.stopReason == nil {
		process.stopReason = reason
	}
	cancel := process.runCancel
	process.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (process *acquisitionControllerProcess) Run(parent context.Context) error {
	if process == nil || process.config.Service == nil || parent == nil {
		return errCommandUnavailable
	}
	process.mu.Lock()
	if process.started || process.closed {
		process.mu.Unlock()
		return errCommandUnavailable
	}
	process.started = true
	if parent.Err() != nil {
		// A signal before startup is the same clean stop as one after it:
		// nothing is serving, so only the sessions need closing before Close
		// releases the rest.
		process.safeToClose = true
		process.mu.Unlock()
		return process.config.CloseSessions()
	}
	runCtx, runCancel := context.WithCancel(parent)
	process.runCancel = runCancel
	process.mu.Unlock()
	defer runCancel()

	serviceDone := make(chan error, 1)
	go func() { serviceDone <- process.config.Service.Run(runCtx) }()
	go process.watch(runCtx)
	admin, health, serverErr := process.startServers(runCtx)
	if serverErr != nil && !errors.Is(serverErr, context.Canceled) {
		process.stop(errAcquisitionServer)
	}
	runErr := <-serviceDone
	runCancel()
	sessionErr := process.config.CloseSessions()

	shutdownCtx, shutdownCancel := context.WithTimeout(
		context.Background(),
		process.config.ShutdownTimeout,
	)
	defer shutdownCancel()
	var closeErr error
	for _, server := range []*localServer{admin, health} {
		if server != nil {
			closeErr = errors.Join(closeErr, server.Close(shutdownCtx))
		}
	}
	process.mu.Lock()
	reason := process.stopReason
	// Service.Run reports ErrRuntimeShutdown when its loops missed the join
	// deadline, and also when a later shutdown step failed. A loop that has
	// not joined may still hold the store or a fence view, so Close keeps
	// every resource and the process exits holding them: the kernel then
	// drops the fence and ownership locks, as for any crash.
	process.safeToClose = closeErr == nil &&
		!errors.Is(runErr, controller.ErrRuntimeShutdown)
	process.mu.Unlock()
	// A signal that lands while the service or the servers are still
	// starting is the same clean stop as one after startup, provided nothing
	// else stopped the run, cleanup succeeded, and every remaining error is
	// that cancellation. Any other error keeps the exit non-zero.
	if parent.Err() != nil && reason == nil && sessionErr == nil && closeErr == nil &&
		onlyCancelled(serverErr) && onlyCancelled(runErr) {
		return nil
	}
	return errors.Join(reason, serverErr, runErr, sessionErr, closeErr)
}

func onlyCancelled(err error) bool {
	return err == nil || errors.Is(err, context.Canceled)
}

// watch stops the run when the fence guard is lost or the ownership lock no
// longer validates.
func (process *acquisitionControllerProcess) watch(ctx context.Context) {
	ticker := time.NewTicker(process.config.OwnershipCheck)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-process.config.FenceLost:
			process.stop(errAcquisitionFenceLost)
			return
		case <-ticker.C:
			if err := process.config.Ownership.Validate(); err != nil {
				process.stop(errors.Join(errAcquisitionOwnership, err))
				return
			}
		}
	}
}

// Close releases the store, fence guard, Worker session, and ownership only
// after Run has closed both servers, so no handler can still reach them.
func (process *acquisitionControllerProcess) Close() error {
	if process == nil {
		return nil
	}
	process.mu.Lock()
	if process.closed {
		process.mu.Unlock()
		return nil
	}
	if !process.safeToClose {
		process.mu.Unlock()
		return controller.ErrRuntimeShutdown
	}
	process.closed = true
	process.mu.Unlock()
	return errors.Join(
		process.config.Resources.Close(),
		process.config.Ownership.Close(),
	)
}

func (process *acquisitionControllerProcess) startServers(
	ctx context.Context,
) (*localServer, *localServer, error) {
	config := process.config
	if config.Ownership.Validate() != nil {
		return nil, nil, errLocalProtocol
	}
	if err := recoverOwnedLocalSockets(
		[]string{config.AdminSocketPath, config.HealthSocketPath},
		config.ExpectedUID,
	); err != nil {
		return nil, nil, err
	}
	admission := make(chan struct{}, config.AdmissionLimit)
	handler := func(ctx context.Context, request localRequest) localResponse {
		response := handleLocalAdmin(ctx, config.Service, process.health, request)
		if request.Method == localMethodProbe && response.Policy != nil && config.WorkerLeaseGeneration != nil {
			response.Policy.WorkerLeaseGeneration = config.WorkerLeaseGeneration()
		}
		return response
	}
	fatal := func() { process.stop(errAcquisitionServer) }
	admin, err := newLocalServer(localServerConfig{
		Path:        config.AdminSocketPath,
		ExpectedUID: config.ExpectedUID,
		AllowedMethods: []localMethod{
			localMethodProbe,
			localMethodReconcileOnce,
			localMethodDrain,
			localMethodSetAcquisition,
		},
		Admission:        admission,
		IOTimeout:        config.OperationTimeout,
		OperationTimeout: config.OperationTimeout,
		DrainTimeout:     config.DrainTimeout,
		Handler:          handler,
		Fatal:            fatal,
	})
	if err != nil {
		return nil, nil, err
	}
	health, err := newLocalServer(localServerConfig{
		Path:             config.HealthSocketPath,
		ExpectedUID:      config.ExpectedUID,
		AllowedMethods:   []localMethod{localMethodHealth},
		Admission:        admission,
		IOTimeout:        config.OperationTimeout,
		OperationTimeout: config.OperationTimeout,
		DrainTimeout:     config.DrainTimeout,
		Handler:          handler,
		Fatal:            fatal,
	})
	if err != nil {
		return admin, nil, err
	}
	for _, server := range []*localServer{admin, health} {
		if err := server.Start(ctx); err != nil {
			// Start refuses a cancelled context; report the cancellation
			// itself so Run can tell it from a server failure.
			return admin, health, errors.Join(err, ctx.Err())
		}
	}
	return admin, health, nil
}

// health reports ready only while the service is: after startup recovery
// and before shutdown.
func (process *acquisitionControllerProcess) health(context.Context) error {
	if !process.config.Service.Ready() {
		return controller.ErrServiceNotReady
	}
	return nil
}
