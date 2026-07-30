package main

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
)

func TestLocalServerServesExactAdminMethod(t *testing.T) {
	var calls atomic.Int32
	server, path, cancel := newStartedLocalTestServer(
		t,
		[]localMethod{localMethodProbe},
		func(_ context.Context, request localRequest) localResponse {
			calls.Add(1)
			return localResponse{
				SchemaVersion: localProtocolSchemaVersion,
				Status:        localStatusOK,
				Reason:        localReasonNone,
				Policy: &localPolicyStatus{
					Mode:     controller.AcquisitionDisabled,
					Epoch:    15,
					Digest:   strings.Repeat("c", 64),
					Capacity: 0,
				},
			}
		},
		nil,
	)
	defer cancel()
	client, err := newLocalAdminClient(
		path,
		uint32(os.Geteuid()),
		time.Second,
	)
	if err != nil {
		t.Fatalf("newLocalAdminClient() error = %v", err)
	}
	status, err := client.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if status.Epoch != 15 || calls.Load() != 1 {
		t.Fatalf("Probe() = %#v, calls=%d", status, calls.Load())
	}
	closeCtx, closeCancel := context.WithTimeout(
		context.Background(),
		time.Second,
	)
	defer closeCancel()
	if err := server.Close(closeCtx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestLocalServerRejectsWrongSocketMethodBeforeHandler(t *testing.T) {
	var calls atomic.Int32
	server, path, cancel := newStartedLocalTestServer(
		t,
		[]localMethod{localMethodProbe},
		func(context.Context, localRequest) localResponse {
			calls.Add(1)
			return localResponse{}
		},
		nil,
	)
	defer cancel()
	request := localRequest{
		SchemaVersion:    localProtocolSchemaVersion,
		Method:           localMethodHealth,
		DeadlineUnixNano: time.Now().Add(time.Second).UnixNano(),
	}
	document, err := marshalLocalRequest(request)
	if err != nil {
		t.Fatalf("marshalLocalRequest() error = %v", err)
	}
	if response := rawLocalExchange(t, path, document); len(response) != 0 {
		t.Fatalf("wrong-method response = %q, want closed connection", response)
	}
	if calls.Load() != 0 {
		t.Fatalf("handler calls = %d, want 0", calls.Load())
	}
	closeCtx, closeCancel := context.WithTimeout(
		context.Background(),
		time.Second,
	)
	defer closeCancel()
	if err := server.Close(closeCtx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestLocalServerAdmissionSaturatesBeforeSecondRequestRead(t *testing.T) {
	admission := make(chan struct{}, 1)
	var calls atomic.Int32
	server, path, cancel := newStartedLocalTestServerWithAdmission(
		t,
		[]localMethod{localMethodProbe},
		func(context.Context, localRequest) localResponse {
			calls.Add(1)
			return localResponse{}
		},
		nil,
		admission,
		40*time.Millisecond,
	)
	defer cancel()
	first, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial first slowloris: %v", err)
	}
	defer first.Close()
	waitForAdmissionCount(t, admission, 1)

	request, err := marshalLocalRequest(localRequest{
		SchemaVersion:    localProtocolSchemaVersion,
		Method:           localMethodProbe,
		DeadlineUnixNano: time.Now().Add(time.Second).UnixNano(),
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	second, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial second: %v", err)
	}
	var response []byte
	written, writeErr := second.Write(request)
	switch {
	case writeErr == nil:
		if written != len(request) {
			_ = second.Close()
			t.Fatalf("write second request = %d bytes, want %d", written, len(request))
		}
		if unixSecond, ok := second.(*net.UnixConn); ok {
			_ = unixSecond.CloseWrite()
		}
		_ = second.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		response, _ = io.ReadAll(second)
	case errors.Is(writeErr, syscall.EPIPE):
		// Linux may close the saturated connection before this write reaches
		// the server. EPIPE is the exact early-rejection shape.
	default:
		_ = second.Close()
		t.Fatalf("write second request: %v", writeErr)
	}
	_ = second.Close()
	if len(response) != 0 {
		t.Fatalf("saturated response = %q, want no response", response)
	}
	if calls.Load() != 0 {
		t.Fatalf("handler calls while saturated = %d", calls.Load())
	}
	waitForAdmissionCount(t, admission, 0)

	closeCtx, closeCancel := context.WithTimeout(
		context.Background(),
		time.Second,
	)
	defer closeCancel()
	if err := server.Close(closeCtx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestLocalServerPanicTripsFatalAndReturnsNoSuccess(t *testing.T) {
	fatal := make(chan struct{}, 1)
	server, path, cancel := newStartedLocalTestServer(
		t,
		[]localMethod{localMethodProbe},
		func(context.Context, localRequest) localResponse {
			panic("test panic")
		},
		func() {
			select {
			case fatal <- struct{}{}:
			default:
			}
		},
	)
	defer cancel()
	request, err := marshalLocalRequest(localRequest{
		SchemaVersion:    localProtocolSchemaVersion,
		Method:           localMethodProbe,
		DeadlineUnixNano: time.Now().Add(time.Second).UnixNano(),
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	if response := rawLocalExchange(t, path, request); len(response) != 0 {
		t.Fatalf("panic response = %q, want none", response)
	}
	select {
	case <-fatal:
	case <-time.After(time.Second):
		t.Fatal("fatal callback was not invoked")
	}
	closeCtx, closeCancel := context.WithTimeout(
		context.Background(),
		time.Second,
	)
	defer closeCancel()
	if err := server.Close(closeCtx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestLocalServerBeginCloseStopsAdmissionBeforeHandlerJoin(
	t *testing.T,
) {
	entered := make(chan struct{})
	release := make(chan struct{})
	server, path, cancel := newStartedLocalTestServer(
		t,
		[]localMethod{localMethodProbe},
		func(context.Context, localRequest) localResponse {
			close(entered)
			<-release
			return localResponse{
				SchemaVersion: localProtocolSchemaVersion,
				Status:        localStatusUnavailable,
				Reason:        localReasonNotReady,
			}
		},
		nil,
	)
	defer cancel()
	connection, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("dial blocking handler: %v", err)
	}
	defer connection.Close()
	request, err := marshalLocalRequest(localRequest{
		SchemaVersion:    localProtocolSchemaVersion,
		Method:           localMethodProbe,
		DeadlineUnixNano: time.Now().Add(time.Second).UnixNano(),
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	if err := writeAll(connection, request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if unixConnection, ok := connection.(*net.UnixConn); ok {
		if err := unixConnection.CloseWrite(); err != nil {
			t.Fatalf("close write: %v", err)
		}
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("handler did not enter")
	}

	started := time.Now()
	server.BeginClose()
	if elapsed := time.Since(started); elapsed > 50*time.Millisecond {
		t.Fatalf("BeginClose() waited for handler: %s", elapsed)
	}
	if replacement, err := net.DialTimeout(
		"unix",
		path,
		30*time.Millisecond,
	); err == nil {
		_ = replacement.Close()
		t.Fatal("new connection admitted after BeginClose")
	}
	shortCtx, shortCancel := context.WithTimeout(
		context.Background(),
		30*time.Millisecond,
	)
	defer shortCancel()
	if err := server.WaitClosed(shortCtx); !errors.Is(
		err,
		context.DeadlineExceeded,
	) {
		t.Fatalf("WaitClosed(live handler) error = %v", err)
	}

	close(release)
	closeCtx, closeCancel := context.WithTimeout(
		context.Background(),
		time.Second,
	)
	defer closeCancel()
	if err := server.WaitClosed(closeCtx); err != nil {
		t.Fatalf("WaitClosed(after release) error = %v", err)
	}
}

func TestLocalServerCloseNeverRemovesReplacementSocket(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	server, path, cancel := newStartedLocalTestServer(
		t,
		[]localMethod{localMethodProbe},
		func(context.Context, localRequest) localResponse {
			close(entered)
			<-release
			return localResponse{
				SchemaVersion: localProtocolSchemaVersion,
				Status:        localStatusUnavailable,
				Reason:        localReasonNotReady,
			}
		},
		nil,
	)
	defer cancel()
	connection, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("dial blocking handler: %v", err)
	}
	defer connection.Close()
	request, err := marshalLocalRequest(localRequest{
		SchemaVersion:    localProtocolSchemaVersion,
		Method:           localMethodProbe,
		DeadlineUnixNano: time.Now().Add(time.Second).UnixNano(),
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	if err := writeAll(connection, request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if unixConnection, ok := connection.(*net.UnixConn); ok {
		if err := unixConnection.CloseWrite(); err != nil {
			t.Fatalf("close write: %v", err)
		}
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("handler did not enter")
	}
	server.BeginClose()
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove original socket path: %v", err)
	}
	replacement, err := net.ListenUnix(
		"unix",
		&net.UnixAddr{Name: path, Net: "unix"},
	)
	if err != nil {
		t.Fatalf("create replacement socket: %v", err)
	}
	defer replacement.Close()
	replacement.SetUnlinkOnClose(false)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod replacement socket: %v", err)
	}

	close(release)
	closeCtx, closeCancel := context.WithTimeout(
		context.Background(),
		time.Second,
	)
	defer closeCancel()
	if err := server.WaitClosed(closeCtx); !errors.Is(
		err,
		errLocalProtocol,
	) {
		t.Fatalf("WaitClosed(replacement) error = %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("replacement socket was removed: (%v, %v)", info, err)
	}
}

func newStartedLocalTestServer(
	t *testing.T,
	methods []localMethod,
	handler func(context.Context, localRequest) localResponse,
	fatal func(),
) (*localServer, string, context.CancelFunc) {
	t.Helper()
	return newStartedLocalTestServerWithAdmission(
		t,
		methods,
		handler,
		fatal,
		make(chan struct{}, 2),
		time.Second,
	)
}

func newStartedLocalTestServerWithAdmission(
	t *testing.T,
	methods []localMethod,
	handler func(context.Context, localRequest) localResponse,
	fatal func(),
	admission chan struct{},
	ioTimeout time.Duration,
) (*localServer, string, context.CancelFunc) {
	t.Helper()
	root, err := os.MkdirTemp(shortTestTempRoot(), "pgh-server-")
	if err != nil {
		t.Fatalf("make socket root: %v", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("chmod socket root: %v", err)
	}
	path := filepath.Join(root, "admin.sock")
	server, err := newLocalServer(localServerConfig{
		Path:             path,
		ExpectedUID:      uint32(os.Geteuid()),
		AllowedMethods:   methods,
		Admission:        admission,
		IOTimeout:        ioTimeout,
		OperationTimeout: time.Second,
		DrainTimeout:     time.Second,
		Handler:          handler,
		Fatal:            fatal,
	})
	if err != nil {
		t.Fatalf("newLocalServer() error = %v", err)
	}
	runCtx, cancel := context.WithCancel(context.Background())
	if err := server.Start(runCtx); err != nil {
		cancel()
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() {
		cancel()
		closeCtx, closeCancel := context.WithTimeout(
			context.Background(),
			time.Second,
		)
		defer closeCancel()
		_ = server.Close(closeCtx)
		if err := os.RemoveAll(root); err != nil {
			t.Errorf("remove socket root: %v", err)
		}
	})
	return server, path, cancel
}

func rawLocalExchange(t *testing.T, path string, request []byte) []byte {
	t.Helper()
	connection, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("dial local server: %v", err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if err := writeAll(connection, request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if unixConnection, ok := connection.(*net.UnixConn); ok {
		if err := unixConnection.CloseWrite(); err != nil {
			t.Fatalf("close write: %v", err)
		}
	}
	response, err := io.ReadAll(connection)
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read response: %v", err)
	}
	return response
}

func waitForAdmissionCount(
	t *testing.T,
	admission chan struct{},
	want int,
) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(admission) == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("admission count = %d, want %d", len(admission), want)
}
