//go:build linux || darwin

package networkjail

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

type UnixAuthorityManager struct {
	mu         sync.Mutex
	authority  *PermitAuthority
	maxClients uint32
	timeout    time.Duration
	active     map[string]*managedUnixAuthority
}

type managedUnixAuthority struct {
	mu            sync.Mutex
	server        *unixPermitServer
	socketPath    string
	socket        hostruntime.SocketIdentity
	slot          CapacitySlotID
	generation    JobGeneration
	closed        bool
	socketRemoved bool
	deactivated   bool
}

func NewUnixAuthorityManager(
	authority *PermitAuthority,
	maxClients uint32,
	timeout time.Duration,
) (*UnixAuthorityManager, error) {
	if authority == nil || maxClients == 0 ||
		timeout <= 0 || timeout > maxPermitUnixTimeout {
		return nil, ErrPermitAuthorityUnavailable
	}
	return &UnixAuthorityManager{
		authority:  authority,
		maxClients: maxClients,
		timeout:    timeout,
		active:     make(map[string]*managedUnixAuthority),
	}, nil
}

func (manager *UnixAuthorityManager) Start(
	ctx context.Context,
	request authorityRequest,
) (authorityLease, error) {
	if manager == nil || ctx == nil || request.slotID == 0 ||
		request.jobGeneration == 0 ||
		!filepath.IsAbs(request.directory) ||
		filepath.Clean(request.directory) != request.directory {
		return authorityLease{}, ErrPermitAuthorityUnavailable
	}
	uid, gid, err := parseAuthorityUser(request.user)
	if err != nil {
		return authorityLease{}, ErrPermitAuthorityUnavailable
	}
	entries, err := os.ReadDir(request.directory)
	if err != nil || len(entries) != 0 {
		return authorityLease{}, ErrPermitAuthorityUnavailable
	}
	directory, _, err := readAuthorityPathIdentity(request.directory, false)
	if err != nil || directory.UID != uid || directory.GID != gid {
		return authorityLease{}, ErrPermitAuthorityUnavailable
	}
	socketPath := filepath.Join(request.directory, "dial-authority.sock")
	if filepath.Dir(socketPath) != request.directory {
		return authorityLease{}, ErrPermitAuthorityUnavailable
	}

	manager.mu.Lock()
	if _, exists := manager.active[socketPath]; exists {
		manager.mu.Unlock()
		return authorityLease{}, ErrPermitAuthorityUnavailable
	}
	manager.active[socketPath] = nil
	manager.mu.Unlock()
	reserved := true
	defer func() {
		if reserved {
			manager.mu.Lock()
			if manager.active[socketPath] == nil {
				delete(manager.active, socketPath)
			}
			manager.mu.Unlock()
		}
	}()

	slot := CapacitySlotID(request.slotID)
	generation := JobGeneration(request.jobGeneration)
	if err := manager.authority.Activate(ctx, slot, generation); err != nil {
		return authorityLease{}, ErrPermitAuthorityUnavailable
	}
	activated := true
	defer func() {
		if activated {
			recoveryCtx, cancel := setupRecoveryContext(ctx)
			_ = manager.authority.Deactivate(recoveryCtx, slot, generation)
			cancel()
		}
	}()
	revision, err := manager.authority.ActiveRevision(ctx, slot, generation)
	if err != nil {
		return authorityLease{}, ErrPermitAuthorityUnavailable
	}
	listener, err := net.ListenUnix(
		"unix",
		&net.UnixAddr{Name: socketPath, Net: "unix"},
	)
	if err != nil {
		return authorityLease{}, ErrPermitAuthorityUnavailable
	}
	listener.SetUnlinkOnClose(false)
	listenerOpen := true
	defer func() {
		if listenerOpen {
			_ = listener.Close()
			_ = os.Remove(socketPath)
		}
	}()
	if err := os.Chmod(socketPath, 0o600); err != nil {
		return authorityLease{}, ErrPermitAuthorityUnavailable
	}
	_, socket, err := readAuthorityPathIdentity(socketPath, true)
	if err == nil && (socket.UID != uid || socket.GID != gid) {
		if err := os.Chown(socketPath, int(uid), int(gid)); err != nil {
			return authorityLease{}, ErrPermitAuthorityUnavailable
		}
		_, socket, err = readAuthorityPathIdentity(socketPath, true)
	}
	if err != nil ||
		socket.Device != directory.Device ||
		socket.UID != uid ||
		socket.GID != gid {
		return authorityLease{}, ErrPermitAuthorityUnavailable
	}
	peer, err := currentAuthorityProcessIdentity()
	if err != nil {
		return authorityLease{}, ErrPermitAuthorityUnavailable
	}
	proof, err := hostruntime.NewAuthorityProof(hostruntime.AuthorityBinding{
		Version:        1,
		CapacitySlotID: request.slotID,
		JobGeneration:  request.jobGeneration,
		LedgerRevision: revision,
		Directory:      directory,
		Socket:         socket,
		Peer:           peer,
	})
	if err != nil {
		return authorityLease{}, ErrPermitAuthorityUnavailable
	}
	server, err := newUnixPermitServer(
		manager.authority,
		listener,
		manager.maxClients,
		manager.timeout,
	)
	if err != nil {
		return authorityLease{}, ErrPermitAuthorityUnavailable
	}
	endpoint := &managedUnixAuthority{
		server:     server,
		socketPath: socketPath,
		socket:     socket,
		slot:       slot,
		generation: generation,
	}
	server.start(context.Background())

	manager.mu.Lock()
	if manager.active[socketPath] != nil {
		manager.mu.Unlock()
		_ = endpoint.close()
		return authorityLease{}, ErrPermitAuthorityUnavailable
	}
	manager.active[socketPath] = endpoint
	manager.mu.Unlock()

	reserved = false
	activated = false
	listenerOpen = false
	return authorityLease{
		proof:         proof,
		slotID:        request.slotID,
		jobGeneration: request.jobGeneration,
		socketPath:    socketPath,
		socket:        socket,
		endpoint:      endpoint,
		valid:         true,
	}, nil
}

func (manager *UnixAuthorityManager) Stop(
	ctx context.Context,
	lease authorityLease,
) error {
	if manager == nil || ctx == nil || !lease.valid ||
		lease.socketPath == "" || lease.endpoint == nil {
		return ErrPermitAuthorityUnavailable
	}
	endpoint, ok := lease.endpoint.(*managedUnixAuthority)
	if !ok || endpoint.socketPath != lease.socketPath ||
		endpoint.socket != lease.socket {
		return ErrPermitAuthorityUnavailable
	}
	manager.mu.Lock()
	current, found := manager.active[lease.socketPath]
	manager.mu.Unlock()
	if !found {
		endpoint.mu.Lock()
		stopped := endpoint.closed &&
			endpoint.socketRemoved &&
			endpoint.deactivated
		endpoint.mu.Unlock()
		if stopped {
			return nil
		}
		return ErrPermitAuthorityUnavailable
	}
	if current != endpoint {
		return ErrPermitAuthorityUnavailable
	}

	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	if !endpoint.closed {
		if err := endpoint.server.close(); err != nil {
			return ErrPermitAuthorityUnavailable
		}
		endpoint.closed = true
	}
	if !endpoint.socketRemoved {
		_, currentSocket, err := readAuthorityPathIdentity(
			endpoint.socketPath,
			true,
		)
		if err != nil || currentSocket != endpoint.socket ||
			os.Remove(endpoint.socketPath) != nil {
			return ErrPermitAuthorityUnavailable
		}
		if _, err := os.Lstat(endpoint.socketPath); !errors.Is(err, os.ErrNotExist) {
			return ErrPermitAuthorityUnavailable
		}
		endpoint.socketRemoved = true
	}
	if !endpoint.deactivated {
		if err := manager.authority.Deactivate(
			ctx,
			endpoint.slot,
			endpoint.generation,
		); err != nil {
			return ErrPermitAuthorityUnavailable
		}
		endpoint.deactivated = true
	}
	manager.mu.Lock()
	if manager.active[lease.socketPath] == endpoint {
		delete(manager.active, lease.socketPath)
	}
	manager.mu.Unlock()
	return nil
}

func (endpoint *managedUnixAuthority) close() error {
	if endpoint == nil || endpoint.server == nil {
		return nil
	}
	return endpoint.server.close()
}

func parseAuthorityUser(value string) (uint32, uint32, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return 0, 0, ErrPermitAuthorityUnavailable
	}
	uid, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil || strconv.FormatUint(uid, 10) != parts[0] {
		return 0, 0, ErrPermitAuthorityUnavailable
	}
	gid, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil || strconv.FormatUint(gid, 10) != parts[1] {
		return 0, 0, ErrPermitAuthorityUnavailable
	}
	return uint32(uid), uint32(gid), nil
}

var _ authorityManager = (*UnixAuthorityManager)(nil)
