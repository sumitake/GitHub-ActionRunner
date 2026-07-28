//go:build linux || darwin

package networkjail

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	maxPermitUnixTimeout = 30 * time.Second
	permitUnixOOBBytes   = 4096
)

// UnixPermitClient obtains one already-durable permit for each literal dial.
// The fixed stream frame carries no time, refill, or budget input.
type UnixPermitClient struct {
	path    string
	timeout time.Duration
}

func NewUnixPermitClient(path string, timeout time.Duration) (*UnixPermitClient, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		filepath.Base(path) != "dial-authority.sock" ||
		timeout <= 0 || timeout > maxPermitUnixTimeout {
		return nil, ErrPermitAuthorityUnavailable
	}
	return &UnixPermitClient{path: path, timeout: timeout}, nil
}

func (client *UnixPermitClient) Request(
	ctx context.Context,
	request DialPermitRequest,
) (Permit, error) {
	if client == nil || ctx == nil {
		return Permit{}, ErrPermitAuthorityUnavailable
	}
	frame, err := request.MarshalBinary()
	if err != nil {
		return Permit{}, err
	}
	deadline := time.Now().Add(client.timeout)
	if bounded, found := ctx.Deadline(); found && bounded.Before(deadline) {
		deadline = bounded
	}
	dialer := net.Dialer{Deadline: deadline}
	connection, err := dialer.DialContext(ctx, "unix", client.path)
	if err != nil {
		return Permit{}, ErrPermitAuthorityUnavailable
	}
	defer connection.Close()
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return Permit{}, ErrPermitAuthorityUnavailable
	}
	if err := unixConnection.SetDeadline(deadline); err != nil {
		return Permit{}, ErrPermitAuthorityUnavailable
	}
	if err := writeExactUnixFrame(unixConnection, frame); err != nil {
		return Permit{}, ErrPermitAuthorityUnavailable
	}
	if err := unixConnection.CloseWrite(); err != nil {
		return Permit{}, ErrPermitAuthorityUnavailable
	}
	response, err := readExactUnixFrame(
		unixConnection,
		dialPermitResponseFrameBytes,
	)
	if err != nil {
		return Permit{}, ErrPermitAuthorityUnavailable
	}
	permit, err := parseDialPermitResponse(response, request)
	if err != nil {
		return Permit{}, ErrPermitAuthorityUnavailable
	}
	return permit, nil
}

type unixPermitServer struct {
	authority *PermitAuthority
	listener  *net.UnixListener
	timeout   time.Duration
	slots     chan struct{}
	cancel    context.CancelFunc
	done      chan struct{}
	closeOnce sync.Once
	workers   sync.WaitGroup
}

func newUnixPermitServer(
	authority *PermitAuthority,
	listener *net.UnixListener,
	maxClients uint32,
	timeout time.Duration,
) (*unixPermitServer, error) {
	if authority == nil || listener == nil || maxClients == 0 ||
		timeout <= 0 || timeout > maxPermitUnixTimeout {
		return nil, ErrPermitAuthorityUnavailable
	}
	return &unixPermitServer{
		authority: authority,
		listener:  listener,
		timeout:   timeout,
		slots:     make(chan struct{}, maxClients),
		done:      make(chan struct{}),
	}, nil
}

func (server *unixPermitServer) start(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	server.cancel = cancel
	go server.serve(ctx)
}

func (server *unixPermitServer) serve(ctx context.Context) {
	defer close(server.done)
	for {
		connection, err := server.listener.AcceptUnix()
		if err != nil {
			return
		}
		select {
		case server.slots <- struct{}{}:
			server.workers.Add(1)
			go func() {
				defer server.workers.Done()
				defer func() { <-server.slots }()
				server.serveConnection(ctx, connection)
			}()
		default:
			_ = connection.Close()
		}
	}
}

func (server *unixPermitServer) serveConnection(
	ctx context.Context,
	connection *net.UnixConn,
) {
	defer connection.Close()
	deadline := time.Now().Add(server.timeout)
	if bounded, found := ctx.Deadline(); found && bounded.Before(deadline) {
		deadline = bounded
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return
	}
	requestFrame, err := readExactUnixFrame(
		connection,
		dialPermitRequestFrameBytes,
	)
	if err != nil {
		return
	}
	request, err := ParseDialPermitRequest(requestFrame)
	if err != nil {
		return
	}
	peer, err := observeUnixPermitPeer(connection)
	if err != nil {
		return
	}
	permit, err := server.authority.Consume(ctx, request, peer)
	if err != nil {
		return
	}
	response, err := marshalDialPermitResponse(request, permit)
	if err != nil {
		return
	}
	if err := writeExactUnixFrame(connection, response); err != nil {
		return
	}
	if err := connection.CloseWrite(); err != nil {
		return
	}
}

func (server *unixPermitServer) close() error {
	if server == nil {
		return nil
	}
	var closeErr error
	server.closeOnce.Do(func() {
		if server.cancel != nil {
			server.cancel()
		}
		closeErr = server.listener.Close()
		<-server.done
		server.workers.Wait()
	})
	if closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
		return ErrPermitAuthorityUnavailable
	}
	return nil
}

func readExactUnixFrame(
	connection *net.UnixConn,
	size int,
) ([]byte, error) {
	if connection == nil || size <= 0 {
		return nil, ErrPermitAuthorityUnavailable
	}
	frame := make([]byte, size)
	oob := make([]byte, permitUnixOOBBytes)
	offset := 0
	for offset < len(frame) {
		read, oobRead, flags, address, err := connection.ReadMsgUnix(
			frame[offset:],
			oob,
		)
		if oobRead > 0 {
			closeReceivedUnixRights(oob[:oobRead])
		}
		if err != nil || address != nil || oobRead != 0 ||
			flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 || read <= 0 {
			return nil, ErrPermitAuthorityUnavailable
		}
		offset += read
	}
	extra := make([]byte, 1)
	read, oobRead, flags, address, err := connection.ReadMsgUnix(extra, oob)
	if oobRead > 0 {
		closeReceivedUnixRights(oob[:oobRead])
	}
	if read != 0 || !errors.Is(err, io.EOF) || address != nil ||
		oobRead != 0 || flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 {
		return nil, ErrPermitAuthorityUnavailable
	}
	return frame, nil
}

func writeExactUnixFrame(
	connection *net.UnixConn,
	frame []byte,
) error {
	if connection == nil || len(frame) == 0 {
		return ErrPermitAuthorityUnavailable
	}
	for len(frame) > 0 {
		written, err := connection.Write(frame)
		if err != nil || written <= 0 {
			return ErrPermitAuthorityUnavailable
		}
		frame = frame[written:]
	}
	return nil
}
