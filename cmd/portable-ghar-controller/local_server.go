package main

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type localServerConfig struct {
	Path             string
	ExpectedUID      uint32
	AllowedMethods   []localMethod
	Admission        chan struct{}
	IOTimeout        time.Duration
	OperationTimeout time.Duration
	DrainTimeout     time.Duration
	Handler          func(context.Context, localRequest) localResponse
	Fatal            func()
}

type localServer struct {
	mu               sync.Mutex
	path             string
	expectedUID      uint32
	identity         localSocketIdentity
	listener         *net.UnixListener
	allowed          map[localMethod]struct{}
	admission        chan struct{}
	ioTimeout        time.Duration
	operationTimeout time.Duration
	drainTimeout     time.Duration
	handler          func(context.Context, localRequest) localResponse
	fatal            func()
	runCtx           context.Context
	runCancel        context.CancelFunc
	started          bool
	closing          bool
	connections      map[*net.UnixConn]struct{}
	handlers         sync.WaitGroup
	acceptDone       chan struct{}
	acceptDoneOnce   sync.Once
	acceptErr        error
	closeOnce        sync.Once
	closeStarted     chan struct{}
	closeDone        chan struct{}
	closeErr         error
}

func newLocalServer(config localServerConfig) (*localServer, error) {
	if !canonicalAbsolutePath(config.Path) ||
		len(config.AllowedMethods) == 0 ||
		config.Admission == nil ||
		cap(config.Admission) <= 0 ||
		config.IOTimeout <= 0 ||
		config.OperationTimeout <= 0 ||
		config.DrainTimeout <= 0 ||
		config.Handler == nil {
		return nil, errLocalProtocol
	}
	allowed := make(map[localMethod]struct{}, len(config.AllowedMethods))
	for _, method := range config.AllowedMethods {
		if !validLocalMethod(method) {
			return nil, errLocalProtocol
		}
		if _, duplicate := allowed[method]; duplicate {
			return nil, errLocalProtocol
		}
		allowed[method] = struct{}{}
	}
	if err := validateLocalSocketParent(
		config.Path,
		config.ExpectedUID,
	); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(config.Path); err == nil ||
		!errors.Is(err, os.ErrNotExist) {
		return nil, errLocalProtocol
	}
	listener, err := net.ListenUnix(
		"unix",
		&net.UnixAddr{Name: config.Path, Net: "unix"},
	)
	if err != nil {
		return nil, errLocalProtocol
	}
	listener.SetUnlinkOnClose(false)
	cleanup := func() {
		_ = listener.Close()
		_ = os.Remove(config.Path)
	}
	if err := os.Chmod(config.Path, 0o600); err != nil {
		cleanup()
		return nil, errLocalProtocol
	}
	identity, err := observeLocalSocketIdentity(
		config.Path,
		config.ExpectedUID,
	)
	if err != nil {
		cleanup()
		return nil, errLocalProtocol
	}
	fatal := config.Fatal
	if fatal == nil {
		fatal = func() {}
	}
	return &localServer{
		path:             config.Path,
		expectedUID:      config.ExpectedUID,
		identity:         identity,
		listener:         listener,
		allowed:          allowed,
		admission:        config.Admission,
		ioTimeout:        config.IOTimeout,
		operationTimeout: config.OperationTimeout,
		drainTimeout:     config.DrainTimeout,
		handler:          config.Handler,
		fatal:            fatal,
		connections:      make(map[*net.UnixConn]struct{}),
		acceptDone:       make(chan struct{}),
		closeStarted:     make(chan struct{}),
		closeDone:        make(chan struct{}),
	}, nil
}

func (server *localServer) Start(parent context.Context) error {
	if server == nil || parent == nil || parent.Err() != nil {
		return errLocalProtocol
	}
	server.mu.Lock()
	if server.started || server.closing || server.listener == nil {
		server.mu.Unlock()
		return errLocalProtocol
	}
	server.started = true
	server.runCtx, server.runCancel = context.WithCancel(parent)
	runCtx := server.runCtx
	listener := server.listener
	server.mu.Unlock()

	go func() {
		<-runCtx.Done()
		_ = listener.Close()
	}()
	go server.serve()
	return nil
}

func (server *localServer) serve() {
	defer server.acceptDoneOnce.Do(func() {
		close(server.acceptDone)
	})
	for {
		connection, err := server.listener.AcceptUnix()
		if err != nil {
			server.mu.Lock()
			if server.runCtx == nil || server.runCtx.Err() == nil {
				server.acceptErr = err
			}
			server.mu.Unlock()
			return
		}
		if err := requireLocalSocketIdentity(
			server.path,
			server.expectedUID,
			server.identity,
		); err != nil {
			_ = connection.Close()
			server.tripFatal()
			return
		}
		if err := requireLocalUnixPeerUID(
			connection,
			server.expectedUID,
		); err != nil {
			_ = connection.Close()
			continue
		}
		select {
		case server.admission <- struct{}{}:
		default:
			_ = connection.Close()
			continue
		}
		server.mu.Lock()
		if server.closing || server.runCtx == nil ||
			server.runCtx.Err() != nil {
			server.mu.Unlock()
			<-server.admission
			_ = connection.Close()
			continue
		}
		server.connections[connection] = struct{}{}
		server.handlers.Add(1)
		server.mu.Unlock()
		go server.serveConnection(connection)
	}
}

func (server *localServer) serveConnection(connection *net.UnixConn) {
	defer func() {
		if recover() != nil {
			server.tripFatal()
		}
		server.mu.Lock()
		delete(server.connections, connection)
		server.mu.Unlock()
		_ = connection.Close()
		<-server.admission
		server.handlers.Done()
	}()

	server.mu.Lock()
	runCtx := server.runCtx
	server.mu.Unlock()
	if runCtx == nil || runCtx.Err() != nil {
		return
	}
	readDeadline := time.Now().Add(server.ioTimeout)
	if err := connection.SetReadDeadline(readDeadline); err != nil {
		return
	}
	document, err := io.ReadAll(
		io.LimitReader(connection, maxLocalRequestBytes+1),
	)
	if err != nil || len(document) > maxLocalRequestBytes {
		return
	}
	request, err := parseLocalRequest(document)
	if err != nil {
		return
	}
	if _, ok := server.allowed[request.Method]; !ok {
		return
	}
	if err := requireLocalSocketIdentity(
		server.path,
		server.expectedUID,
		server.identity,
	); err != nil {
		server.tripFatal()
		return
	}
	requestDeadline := time.Unix(0, request.DeadlineUnixNano)
	methodTimeout := server.operationTimeout
	if request.Method == localMethodDrain {
		methodTimeout = server.drainTimeout
	}
	serverDeadline := time.Now().Add(methodTimeout)
	if requestDeadline.Before(serverDeadline) {
		serverDeadline = requestDeadline
	}
	if !serverDeadline.After(time.Now()) {
		server.writeFailure(
			connection,
			request.Method,
			localReasonDeadlineExceeded,
		)
		return
	}
	methodCtx, cancel := context.WithDeadline(runCtx, serverDeadline)
	response := server.handler(methodCtx, request)
	methodErr := methodCtx.Err()
	cancel()
	if methodErr != nil && response.Status == localStatusOK {
		response = localResponse{
			SchemaVersion: localProtocolSchemaVersion,
			Status:        localStatusUnavailable,
			Reason:        localReasonDeadlineExceeded,
		}
	}
	responseDocument, err := marshalLocalResponse(request.Method, response)
	if err != nil {
		server.tripFatal()
		return
	}
	if err := requireLocalSocketIdentity(
		server.path,
		server.expectedUID,
		server.identity,
	); err != nil {
		server.tripFatal()
		return
	}
	if err := connection.SetWriteDeadline(
		time.Now().Add(server.ioTimeout),
	); err != nil {
		return
	}
	_ = writeAll(connection, responseDocument)
	_ = connection.CloseWrite()
}

func (server *localServer) writeFailure(
	connection *net.UnixConn,
	method localMethod,
	reason localReason,
) {
	document, err := marshalLocalResponse(method, localResponse{
		SchemaVersion: localProtocolSchemaVersion,
		Status:        localStatusUnavailable,
		Reason:        reason,
	})
	if err != nil {
		return
	}
	if err := connection.SetWriteDeadline(
		time.Now().Add(server.ioTimeout),
	); err != nil {
		return
	}
	_ = writeAll(connection, document)
	_ = connection.CloseWrite()
}

func (server *localServer) tripFatal() {
	server.fatal()
	server.mu.Lock()
	cancel := server.runCancel
	server.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (server *localServer) Close(ctx context.Context) error {
	if server == nil || ctx == nil {
		return errLocalProtocol
	}
	server.BeginClose()
	return server.WaitClosed(ctx)
}

func (server *localServer) BeginClose() {
	if server == nil {
		return
	}
	server.closeOnce.Do(func() {
		go server.closeAsync()
	})
	<-server.closeStarted
}

func (server *localServer) WaitClosed(ctx context.Context) error {
	if server == nil || ctx == nil {
		return errLocalProtocol
	}
	select {
	case <-server.closeDone:
		server.mu.Lock()
		err := server.closeErr
		server.mu.Unlock()
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (server *localServer) closeAsync() {
	server.mu.Lock()
	server.closing = true
	started := server.started
	cancel := server.runCancel
	listener := server.listener
	connections := make([]*net.UnixConn, 0, len(server.connections))
	for connection := range server.connections {
		connections = append(connections, connection)
	}
	server.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	var closeErr error
	if listener != nil {
		if err := listener.Close(); err != nil &&
			!errors.Is(err, net.ErrClosed) {
			closeErr = errors.Join(closeErr, err)
		}
	}
	for _, connection := range connections {
		if err := connection.Close(); err != nil &&
			!errors.Is(err, net.ErrClosed) {
			closeErr = errors.Join(closeErr, err)
		}
	}
	close(server.closeStarted)
	if !started {
		server.acceptDoneOnce.Do(func() {
			close(server.acceptDone)
		})
	}
	<-server.acceptDone
	server.handlers.Wait()
	server.mu.Lock()
	closeErr = errors.Join(closeErr, server.acceptErr)
	server.mu.Unlock()
	closeErr = errors.Join(
		closeErr,
		removeOwnedLocalSocket(
			server.path,
			server.expectedUID,
			server.identity,
		),
	)
	server.mu.Lock()
	server.closeErr = closeErr
	server.mu.Unlock()
	close(server.closeDone)
}

func validateLocalSocketParent(path string, expectedUID uint32) error {
	parent := filepath.Dir(path)
	var stat unix.Stat_t
	if err := unix.Lstat(parent, &stat); err != nil ||
		uint32(stat.Mode)&unix.S_IFMT != unix.S_IFDIR ||
		uint32(stat.Mode)&0o777 != 0o700 ||
		stat.Uid != expectedUID {
		return errLocalProtocol
	}
	return nil
}

func removeOwnedLocalSocket(
	path string,
	expectedUID uint32,
	identity localSocketIdentity,
) error {
	if err := requireLocalSocketIdentity(
		path,
		expectedUID,
		identity,
	); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return errLocalProtocol
	}
	if err := os.Remove(path); err != nil {
		return errLocalProtocol
	}
	return nil
}
