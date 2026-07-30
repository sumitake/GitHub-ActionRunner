package main

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
)

type disabledControllerProcessConfig struct {
	Admin                 disabledAdminConfig
	StoreCloser           io.Closer
	AdminSocketPath       string
	HealthSocketPath      string
	ExpectedUID           uint32
	AdmissionLimit        int
	IOTimeout             time.Duration
	OperationTimeout      time.Duration
	DrainTimeout          time.Duration
	ReconciliationCadence time.Duration
	ShutdownTimeout       time.Duration
}

type disabledControllerProcess struct {
	mu                    sync.Mutex
	service               *disabledAdminService
	adminServer           *localServer
	healthServer          *localServer
	storeCloser           io.Closer
	ownership             controllerOwnershipLease
	adminSocketPath       string
	healthSocketPath      string
	expectedUID           uint32
	admissionLimit        int
	ioTimeout             time.Duration
	operationTimeout      time.Duration
	drainTimeout          time.Duration
	reconciliationCadence time.Duration
	shutdownTimeout       time.Duration
	runCancel             context.CancelFunc
	started               bool
	safeToClose           bool
	closed                bool
}

var _ controllerProcess = (*disabledControllerProcess)(nil)

func newDisabledControllerProcess(
	config disabledControllerProcessConfig,
) (*disabledControllerProcess, error) {
	if config.Admin.SocketProof != nil ||
		config.StoreCloser == nil ||
		config.Admin.Ownership == nil ||
		config.AdminSocketPath == config.HealthSocketPath ||
		config.AdmissionLimit <= 0 ||
		config.IOTimeout <= 0 ||
		config.OperationTimeout <= 0 ||
		config.DrainTimeout <= 0 ||
		config.ReconciliationCadence <= 0 ||
		config.ShutdownTimeout <= 0 {
		return nil, errDisabledObserverInvalid
	}
	process := &disabledControllerProcess{
		storeCloser:           config.StoreCloser,
		ownership:             config.Admin.Ownership,
		adminSocketPath:       config.AdminSocketPath,
		healthSocketPath:      config.HealthSocketPath,
		expectedUID:           config.ExpectedUID,
		admissionLimit:        config.AdmissionLimit,
		ioTimeout:             config.IOTimeout,
		operationTimeout:      config.OperationTimeout,
		drainTimeout:          config.DrainTimeout,
		reconciliationCadence: config.ReconciliationCadence,
		shutdownTimeout:       config.ShutdownTimeout,
	}
	adminConfig := config.Admin
	adminConfig.SocketProof = process.validateSocketIdentities
	service, err := newDisabledAdminService(adminConfig)
	if err != nil {
		return nil, err
	}
	process.service = service
	return process, nil
}

func (process *disabledControllerProcess) Run(parent context.Context) error {
	if process == nil || parent == nil || parent.Err() != nil {
		return errDisabledObserverInvalid
	}
	process.mu.Lock()
	if process.started || process.closed {
		process.mu.Unlock()
		return errDisabledObserverInvalid
	}
	process.started = true
	runCtx, runCancel := context.WithCancel(parent)
	process.runCancel = runCancel
	process.mu.Unlock()
	defer runCancel()

	var runErr error
	if err := process.service.Prepare(runCtx); err != nil {
		runErr = err
	}
	if runErr == nil {
		if err := process.recoverServerSockets(); err != nil {
			runErr = err
		}
	}
	if runErr == nil {
		if err := process.openServers(); err != nil {
			runErr = err
		}
	}
	if runErr == nil {
		if err := process.adminServer.Start(runCtx); err != nil {
			runErr = err
		}
	}
	if runErr == nil {
		if err := process.healthServer.Start(runCtx); err != nil {
			runErr = err
		}
	}
	if runErr == nil {
		if err := process.service.Activate(runCtx); err != nil {
			runErr = err
		}
	}
	if runErr == nil {
		ticker := time.NewTicker(process.reconciliationCadence)
		defer ticker.Stop()
	runLoop:
		for {
			select {
			case <-parent.Done():
				break runLoop
			case <-runCtx.Done():
				if parent.Err() == nil {
					runErr = controller.ErrRuntimeUnavailable
				}
				break runLoop
			case <-ticker.C:
				callCtx, cancel := context.WithTimeout(
					runCtx,
					process.operationTimeout,
				)
				_, err := process.service.ReconcileOnce(callCtx)
				cancel()
				if err != nil {
					process.tripFatal()
					runErr = err
					break runLoop
				}
			}
		}
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(
		context.Background(),
		process.shutdownTimeout,
	)
	defer shutdownCancel()
	beginErr := process.service.BeginShutdown()
	if process.adminServer != nil {
		process.adminServer.BeginClose()
	}
	if process.healthServer != nil {
		process.healthServer.BeginClose()
	}
	var finishErr error
	if beginErr == nil {
		finishErr = process.service.FinishShutdownWithJoin(
			shutdownCtx,
			process.waitForServers,
		)
	}
	if beginErr == nil && finishErr == nil {
		process.mu.Lock()
		process.safeToClose = true
		process.mu.Unlock()
	}
	return errors.Join(runErr, beginErr, finishErr)
}

func (process *disabledControllerProcess) Close() error {
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
	storeCloser := process.storeCloser
	ownership := process.ownership
	process.mu.Unlock()
	return errors.Join(storeCloser.Close(), ownership.Close())
}

func (process *disabledControllerProcess) openServers() error {
	admission := make(chan struct{}, process.admissionLimit)
	adminServer, err := newLocalServer(localServerConfig{
		Path:        process.adminSocketPath,
		ExpectedUID: process.expectedUID,
		AllowedMethods: []localMethod{
			localMethodProbe,
			localMethodReconcileOnce,
			localMethodDrain,
			localMethodSetAcquisition,
		},
		Admission:        admission,
		IOTimeout:        process.ioTimeout,
		OperationTimeout: process.operationTimeout,
		DrainTimeout:     process.drainTimeout,
		Handler:          process.service.HandleLocal,
		Fatal:            process.tripFatal,
	})
	if err != nil {
		return err
	}
	process.adminServer = adminServer
	healthServer, err := newLocalServer(localServerConfig{
		Path:             process.healthSocketPath,
		ExpectedUID:      process.expectedUID,
		AllowedMethods:   []localMethod{localMethodHealth},
		Admission:        admission,
		IOTimeout:        process.ioTimeout,
		OperationTimeout: process.operationTimeout,
		DrainTimeout:     process.drainTimeout,
		Handler:          process.service.HandleLocal,
		Fatal:            process.tripFatal,
	})
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(
			context.Background(),
			process.shutdownTimeout,
		)
		defer cancel()
		return errors.Join(err, adminServer.Close(cleanupCtx))
	}
	process.healthServer = healthServer
	return nil
}

func (process *disabledControllerProcess) recoverServerSockets() error {
	if process == nil || process.ownership == nil ||
		process.ownership.Validate() != nil {
		return errLocalProtocol
	}
	return recoverOwnedLocalSockets(
		[]string{process.adminSocketPath, process.healthSocketPath},
		process.expectedUID,
	)
}

func (process *disabledControllerProcess) validateSocketIdentities() error {
	if process == nil ||
		process.adminServer == nil ||
		process.healthServer == nil {
		return errLocalProtocol
	}
	if process.adminServer.socketGuard == nil ||
		process.adminServer.socketGuard.Verify() != nil {
		return errLocalProtocol
	}
	if process.healthServer.socketGuard == nil ||
		process.healthServer.socketGuard.Verify() != nil {
		return errLocalProtocol
	}
	return nil
}

func (process *disabledControllerProcess) waitForServers(
	ctx context.Context,
) error {
	if process == nil || ctx == nil {
		return controller.ErrRuntimeShutdown
	}
	var adminErr error
	if process.adminServer != nil {
		adminErr = process.adminServer.WaitClosed(ctx)
	}
	var healthErr error
	if process.healthServer != nil {
		healthErr = process.healthServer.WaitClosed(ctx)
	}
	return errors.Join(adminErr, healthErr)
}

func (process *disabledControllerProcess) tripFatal() {
	if process == nil {
		return
	}
	if process.service != nil {
		process.service.markFatal()
	}
	process.mu.Lock()
	cancel := process.runCancel
	process.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}
