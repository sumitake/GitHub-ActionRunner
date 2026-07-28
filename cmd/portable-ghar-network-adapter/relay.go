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

	"github.com/sumitake/portable-ghar/internal/relaycontract"
	"golang.org/x/sys/unix"
)

const relayBufferBytes = 32 << 10

type relayEndpoint struct {
	LoopbackAddress string
	SocketName      string
}

type brokerObjectIdentity struct {
	socketPath string
	device     uint64
	inode      uint64
	uid        uint32
	gid        uint32
}

type peerVerifier func(*net.UnixConn, relaycontract.Binding) error

type relayHandler func(context.Context, *net.TCPConn) error

type relayMachine struct {
	brokerDirectory string
	binding         relaycontract.Binding
	ioTimeout       time.Duration
	verifyPeer      peerVerifier
}

type terminalRelayError struct{ cause error }

func (e terminalRelayError) Error() string { return "network-adapter: broker identity unavailable" }
func (e terminalRelayError) Unwrap() error { return e.cause }

func validateRelayEndpoints(endpoints []relayEndpoint) error {
	if len(endpoints) != 1 ||
		endpoints[0].LoopbackAddress != "127.0.0.1:18080" ||
		endpoints[0].SocketName != relaycontract.HTTPSProxySocket {
		return errors.New("network-adapter: relay endpoint table invalid")
	}
	host, port, err := net.SplitHostPort(endpoints[0].LoopbackAddress)
	if err != nil || host != "127.0.0.1" || port != "18080" {
		return errors.New("network-adapter: relay endpoint invalid")
	}
	return nil
}

func verifyBrokerObjects(directory string, binding relaycontract.Binding) (brokerObjectIdentity, error) {
	if !canonicalAbsolute(directory) || relaycontract.Validate(binding) != nil ||
		binding.Socket.Name != relaycontract.HTTPSProxySocket {
		return brokerObjectIdentity{}, errors.New("network-adapter: broker binding invalid")
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != directory {
		return brokerObjectIdentity{}, errors.New("network-adapter: broker directory indirect")
	}
	var directoryStat unix.Stat_t
	if unix.Lstat(directory, &directoryStat) != nil ||
		uint32(directoryStat.Mode)&unix.S_IFMT != unix.S_IFDIR ||
		uint32(directoryStat.Mode)&0o777 != binding.Directory.Mode ||
		uint64(directoryStat.Dev) != binding.Directory.Device ||
		directoryStat.Ino != binding.Directory.Inode ||
		directoryStat.Uid != binding.Directory.UID ||
		directoryStat.Gid != binding.Directory.GID ||
		directoryStat.Uid != uint32(os.Geteuid()) {
		return brokerObjectIdentity{}, errors.New("network-adapter: broker directory identity changed")
	}
	socketPath := filepath.Join(directory, binding.Socket.Name)
	if filepath.Dir(socketPath) != directory {
		return brokerObjectIdentity{}, errors.New("network-adapter: broker socket path escaped")
	}
	var socketStat unix.Stat_t
	if unix.Lstat(socketPath, &socketStat) != nil ||
		uint32(socketStat.Mode)&unix.S_IFMT != unix.S_IFSOCK ||
		uint32(socketStat.Mode)&0o777 != binding.Socket.Mode ||
		uint64(socketStat.Dev) != binding.Socket.Device ||
		socketStat.Ino != binding.Socket.Inode ||
		socketStat.Uid != binding.Socket.UID ||
		socketStat.Gid != binding.Socket.GID ||
		socketStat.Nlink != 1 {
		return brokerObjectIdentity{}, errors.New("network-adapter: broker socket identity changed")
	}
	return brokerObjectIdentity{
		socketPath: socketPath,
		device:     uint64(socketStat.Dev),
		inode:      socketStat.Ino,
		uid:        socketStat.Uid,
		gid:        socketStat.Gid,
	}, nil
}

func (machine relayMachine) relayOne(ctx context.Context, client *net.TCPConn) error {
	if ctx == nil || client == nil || machine.ioTimeout <= 0 || machine.verifyPeer == nil {
		if client != nil {
			client.Close()
		}
		return errors.New("network-adapter: relay inputs invalid")
	}
	defer client.Close()
	before, err := verifyBrokerObjects(machine.brokerDirectory, machine.binding)
	if err != nil {
		return terminalRelayError{cause: err}
	}
	dialer := net.Dialer{Timeout: machine.ioTimeout}
	rawBroker, err := dialer.DialContext(ctx, "unix", before.socketPath)
	if err != nil {
		return terminalRelayError{cause: err}
	}
	broker, ok := rawBroker.(*net.UnixConn)
	if !ok {
		rawBroker.Close()
		return terminalRelayError{cause: errors.New("network-adapter: broker transport invalid")}
	}
	defer broker.Close()
	after, err := verifyBrokerObjects(machine.brokerDirectory, machine.binding)
	if err != nil || before != after {
		if err == nil {
			err = errors.New("network-adapter: broker identity changed during connect")
		}
		return terminalRelayError{cause: err}
	}
	if err := machine.verifyPeer(broker, machine.binding); err != nil {
		return terminalRelayError{cause: err}
	}
	stopCancel := context.AfterFunc(ctx, func() {
		_ = client.Close()
		_ = broker.Close()
	})
	defer stopCancel()
	return relayDuplex(client, broker, machine.ioTimeout)
}

func relayDuplex(left, right net.Conn, timeout time.Duration) error {
	if left == nil || right == nil || timeout <= 0 {
		return errors.New("network-adapter: duplex inputs invalid")
	}
	results := make(chan error, 2)
	go func() { results <- copyHalf(right, left, timeout) }()
	go func() { results <- copyHalf(left, right, timeout) }()
	first := <-results
	if first != nil {
		_ = left.Close()
		_ = right.Close()
	}
	second := <-results
	if first != nil {
		return errors.New("network-adapter: relay stream failed")
	}
	if second != nil {
		return errors.New("network-adapter: relay stream failed")
	}
	return nil
}

func copyHalf(destination, source net.Conn, timeout time.Duration) error {
	buffer := make([]byte, relayBufferBytes)
	for {
		if err := source.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
		count, readErr := source.Read(buffer)
		if count > 0 {
			if err := destination.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
				return err
			}
			written := 0
			for written < count {
				next, err := destination.Write(buffer[written:count])
				if err != nil || next <= 0 {
					return errors.New("network-adapter: relay write failed")
				}
				written += next
			}
		}
		if readErr == io.EOF {
			if closer, ok := destination.(interface{ CloseWrite() error }); ok {
				return closer.CloseWrite()
			}
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

func openRelayListeners(endpoints []relayEndpoint) ([]*net.TCPListener, error) {
	if err := validateRelayEndpoints(endpoints); err != nil {
		return nil, err
	}
	listeners := make([]*net.TCPListener, 0, len(endpoints))
	for _, endpoint := range endpoints {
		address, err := net.ResolveTCPAddr("tcp4", endpoint.LoopbackAddress)
		if err != nil {
			closeRelayListeners(listeners)
			return nil, errors.New("network-adapter: loopback address invalid")
		}
		listener, err := net.ListenTCP("tcp4", address)
		if err != nil {
			closeRelayListeners(listeners)
			return nil, errors.New("network-adapter: loopback listen failed")
		}
		listeners = append(listeners, listener)
	}
	return listeners, nil
}

func closeRelayListeners(listeners []*net.TCPListener) {
	for _, listener := range listeners {
		if listener != nil {
			_ = listener.Close()
		}
	}
}

func serveRelayListeners(
	ctx context.Context,
	listeners []*net.TCPListener,
	machine relayMachine,
	maxConnections int,
) error {
	return serveRelayListenersWith(ctx, listeners, maxConnections, machine.relayOne)
}

func serveRelayListenersWith(
	ctx context.Context,
	listeners []*net.TCPListener,
	maxConnections int,
	handle relayHandler,
) error {
	if ctx == nil || len(listeners) == 0 || maxConnections <= 0 {
		return errors.New("network-adapter: relay server inputs invalid")
	}
	if handle == nil {
		return errors.New("network-adapter: relay handler invalid")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	terminal := make(chan error, len(listeners)+1)
	permits := make(chan struct{}, maxConnections)
	var workers sync.WaitGroup
	for _, listener := range listeners {
		if listener == nil {
			return errors.New("network-adapter: relay listener invalid")
		}
		workers.Add(1)
		go func(current *net.TCPListener) {
			defer workers.Done()
			for {
				connection, err := current.AcceptTCP()
				if err != nil {
					if ctx.Err() == nil {
						select {
						case terminal <- errors.New("network-adapter: relay accept failed"):
						default:
						}
					}
					return
				}
				select {
				case permits <- struct{}{}:
					workers.Add(1)
					go func() {
						defer workers.Done()
						defer func() { <-permits }()
						err := handle(ctx, connection)
						var terminalError terminalRelayError
						if errors.As(err, &terminalError) {
							select {
							case terminal <- err:
							default:
							}
						}
					}()
				default:
					_ = connection.SetLinger(0)
					_ = connection.Close()
				}
			}
		}(listener)
	}
	select {
	case err := <-terminal:
		cancel()
		closeRelayListeners(listeners)
		workers.Wait()
		return err
	case <-ctx.Done():
		closeRelayListeners(listeners)
		workers.Wait()
		return errors.New("network-adapter: relay canceled")
	}
}
