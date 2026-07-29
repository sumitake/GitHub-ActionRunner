package main

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
)

func TestLocalAdminClientProbeBindsDeadlineAndExactResponse(t *testing.T) {
	requests := make(chan localRequest, 1)
	path := startLocalTestServer(
		t,
		func(request localRequest) ([]byte, error) {
			requests <- request
			return marshalLocalResponse(
				request.Method,
				localResponse{
					SchemaVersion: localProtocolSchemaVersion,
					Status:        localStatusOK,
					Reason:        localReasonNone,
					Policy: &localPolicyStatus{
						Mode:     controller.AcquisitionDisabled,
						Epoch:    11,
						Digest:   strings.Repeat("a", 64),
						Capacity: 0,
					},
				},
			)
		},
	)
	client, err := newLocalAdminClient(
		path,
		uint32(os.Geteuid()),
		time.Second,
	)
	if err != nil {
		t.Fatalf("newLocalAdminClient() error = %v", err)
	}
	deadline := time.Now().Add(750 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	status, err := client.Probe(ctx)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if status.Mode != controller.AcquisitionDisabled ||
		status.Epoch != 11 ||
		status.Digest != strings.Repeat("a", 64) ||
		status.Capacity != 0 {
		t.Fatalf("Probe() = %#v", status)
	}
	request := <-requests
	if request.Method != localMethodProbe ||
		request.DeadlineUnixNano <= time.Now().UnixNano() ||
		request.DeadlineUnixNano > deadline.UnixNano() {
		t.Fatalf("request deadline binding = %#v", request)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := client.Probe(context.Background()); err == nil {
		t.Fatal("Probe() after Close() succeeded")
	}
}

func TestLocalAdminClientMapsClosedFailureStatuses(t *testing.T) {
	tests := []struct {
		name   string
		status localStatus
		reason localReason
		want   error
	}{
		{
			name:   "unavailable",
			status: localStatusUnavailable,
			reason: localReasonNotReady,
			want:   controller.ErrRuntimeUnavailable,
		},
		{
			name:   "conflict",
			status: localStatusConflict,
			reason: localReasonPolicyDrift,
			want:   controller.ErrAdminConflict,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			path := startLocalTestServer(
				t,
				func(request localRequest) ([]byte, error) {
					return marshalLocalResponse(
						request.Method,
						localResponse{
							SchemaVersion: localProtocolSchemaVersion,
							Status:        test.status,
							Reason:        test.reason,
						},
					)
				},
			)
			client, err := newLocalAdminClient(
				path,
				uint32(os.Geteuid()),
				time.Second,
			)
			if err != nil {
				t.Fatalf("newLocalAdminClient() error = %v", err)
			}
			if _, err := client.Probe(context.Background()); !errors.Is(
				err,
				test.want,
			) {
				t.Fatalf("Probe() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestLocalAdminClientRejectsMalformedResponseAndSocketReplacement(
	t *testing.T,
) {
	t.Run("malformed response", func(t *testing.T) {
		path := startLocalTestServer(
			t,
			func(localRequest) ([]byte, error) {
				return []byte(`{"status":"ok"}`), nil
			},
		)
		client, err := newLocalAdminClient(
			path,
			uint32(os.Geteuid()),
			time.Second,
		)
		if err != nil {
			t.Fatalf("newLocalAdminClient() error = %v", err)
		}
		if _, err := client.Probe(context.Background()); err == nil {
			t.Fatal("Probe() accepted malformed response")
		}
	})

	t.Run("socket replacement", func(t *testing.T) {
		var replacement net.Listener
		var path string
		path = startLocalTestServer(
			t,
			func(request localRequest) ([]byte, error) {
				old := path + ".old"
				if err := os.Rename(path, old); err != nil {
					return nil, err
				}
				listener, err := net.Listen("unix", path)
				if err != nil {
					return nil, err
				}
				replacement = listener
				if err := os.Chmod(path, 0o600); err != nil {
					_ = listener.Close()
					return nil, err
				}
				return marshalLocalResponse(
					request.Method,
					localResponse{
						SchemaVersion: localProtocolSchemaVersion,
						Status:        localStatusOK,
						Reason:        localReasonNone,
						Policy: &localPolicyStatus{
							Mode:     controller.AcquisitionDisabled,
							Epoch:    12,
							Digest:   strings.Repeat("b", 64),
							Capacity: 0,
						},
					},
				)
			},
		)
		t.Cleanup(func() {
			if replacement != nil {
				_ = replacement.Close()
			}
		})
		client, err := newLocalAdminClient(
			path,
			uint32(os.Geteuid()),
			time.Second,
		)
		if err != nil {
			t.Fatalf("newLocalAdminClient() error = %v", err)
		}
		if _, err := client.Probe(context.Background()); err == nil {
			t.Fatal("Probe() accepted replaced socket path")
		}
	})
}

func TestLocalAdminClientRejectsUntrustedSocketPath(t *testing.T) {
	t.Run("wrong socket mode", func(t *testing.T) {
		path := startLocalTestServer(
			t,
			func(localRequest) ([]byte, error) {
				return nil, errors.New("unused")
			},
		)
		if err := os.Chmod(path, 0o660); err != nil {
			t.Fatalf("chmod socket: %v", err)
		}
		if _, err := newLocalAdminClient(
			path,
			uint32(os.Geteuid()),
			time.Second,
		); err == nil {
			t.Fatal("newLocalAdminClient() accepted wrong socket mode")
		}
	})

	t.Run("wrong parent mode", func(t *testing.T) {
		path := startLocalTestServer(
			t,
			func(localRequest) ([]byte, error) {
				return nil, errors.New("unused")
			},
		)
		if err := os.Chmod(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("chmod parent: %v", err)
		}
		if _, err := newLocalAdminClient(
			path,
			uint32(os.Geteuid()),
			time.Second,
		); err == nil {
			t.Fatal("newLocalAdminClient() accepted wrong parent mode")
		}
	})
}

func TestLocalUnixPeerCredentialRequiresExactUID(t *testing.T) {
	path := startLocalTestServer(
		t,
		func(localRequest) ([]byte, error) {
			return nil, errors.New("unused")
		},
	)
	connection, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("dial unix peer: %v", err)
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		_ = connection.Close()
		t.Fatal("dial did not return UnixConn")
	}
	if err := requireLocalUnixPeerUID(
		unixConnection,
		uint32(os.Geteuid()),
	); err != nil {
		_ = connection.Close()
		t.Fatalf("requireLocalUnixPeerUID(current) error = %v", err)
	}
	if err := requireLocalUnixPeerUID(
		unixConnection,
		uint32(os.Geteuid())+1,
	); !errors.Is(err, errLocalProtocol) {
		_ = connection.Close()
		t.Fatalf("requireLocalUnixPeerUID(wrong) error = %v", err)
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("close unix peer: %v", err)
	}
}

func startLocalTestServer(
	t *testing.T,
	respond func(localRequest) ([]byte, error),
) string {
	t.Helper()
	root, err := os.MkdirTemp("/private/tmp", "pgh-ipc-")
	if err != nil {
		t.Fatalf("make short socket root: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Errorf("remove socket root: %v", err)
		}
	})
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("chmod socket root: %v", err)
	}
	path := filepath.Join(root, "admin.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		t.Fatalf("chmod unix socket: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		document, err := io.ReadAll(
			io.LimitReader(connection, maxLocalRequestBytes+1),
		)
		if err != nil {
			return
		}
		request, err := parseLocalRequest(document)
		if err != nil {
			return
		}
		response, err := respond(request)
		if err != nil {
			return
		}
		_, _ = connection.Write(response)
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("local test server did not stop")
		}
	})
	return path
}
