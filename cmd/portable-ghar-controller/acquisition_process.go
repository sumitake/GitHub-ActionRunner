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
)

// acquisitionService is what the process needs from controller.Service.
type acquisitionService interface {
	controller.LiveAdmin
	Run(context.Context) error
	Ready() bool
}

type acquisitionProcessConfig struct {
	Service          acquisitionService
	GuardFailure     <-chan error
	Resources        io.Closer
	Ownership        controllerOwnershipLease
	AdminSocketPath  string
	HealthSocketPath string
	ExpectedUID      uint32
	AdmissionLimit   int
	OperationTimeout time.Duration
	DrainTimeout     time.Duration
	ShutdownTimeout  time.Duration
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
		config.Resources == nil ||
		config.Ownership == nil ||
		config.AdminSocketPath == config.HealthSocketPath ||
		config.AdmissionLimit <= 0 ||
		config.OperationTimeout <= 0 ||
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
	if process == nil || process.config.Service == nil || parent == nil || parent.Err() != nil {
		return errCommandUnavailable
	}
	process.mu.Lock()
	if process.started || process.closed {
		process.mu.Unlock()
		return errCommandUnavailable
	}
	process.started = true
	runCtx, runCancel := context.WithCancel(parent)
	process.runCancel = runCancel
	process.mu.Unlock()
	defer runCancel()

	serviceDone := make(chan error, 1)
	go func() { serviceDone <- process.config.Service.Run(runCtx) }()
	if guardFailure := process.config.GuardFailure; guardFailure != nil {
		go func() {
			select {
			case err := <-guardFailure:
				process.stop(errors.Join(errAcquisitionFenceLost, err))
			case <-runCtx.Done():
			}
		}()
	}
	admin, health, serverErr := process.startServers(runCtx)
	if serverErr != nil {
		process.stop(errAcquisitionServer)
	}
	runErr := <-serviceDone
	runCancel()

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
	process.safeToClose = closeErr == nil
	process.mu.Unlock()
	return errors.Join(reason, serverErr, runErr, closeErr)
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
		return handleLocalAdmin(ctx, config.Service, process.health, request)
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
	if err := admin.Start(ctx); err != nil {
		return admin, health, err
	}
	if err := health.Start(ctx); err != nil {
		return admin, health, err
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
