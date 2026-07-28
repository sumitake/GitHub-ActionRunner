package networkjail

import (
	"context"
	"errors"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

type BrokerControlConfig struct {
	HandshakeTimeout time.Duration
	RelayTimeout     time.Duration
	MaxClients       uint32
}

type BrokerControlServer struct {
	dialer *BrokerDialer
	config BrokerControlConfig
	slots  chan struct{}
}

func NewBrokerControlServer(
	dialer *BrokerDialer,
	config BrokerControlConfig,
) (*BrokerControlServer, error) {
	if dialer == nil ||
		config.HandshakeTimeout <= 0 ||
		config.HandshakeTimeout > 30*time.Second ||
		config.RelayTimeout <= 0 ||
		config.RelayTimeout > 30*time.Second ||
		config.MaxClients == 0 || config.MaxClients > 1024 {
		return nil, errors.New("networkjail: broker control unavailable")
	}
	return &BrokerControlServer{
		dialer: dialer,
		config: config,
		slots:  make(chan struct{}, config.MaxClients),
	}, nil
}

func (server *BrokerControlServer) Serve(
	ctx context.Context,
	listener *net.UnixListener,
) error {
	if server == nil || ctx == nil || listener == nil {
		return errors.New("networkjail: broker control unavailable")
	}
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errors.New("networkjail: broker control accept failed")
		}
		select {
		case server.slots <- struct{}{}:
			go func() {
				defer func() { <-server.slots }()
				_ = server.handleControl(ctx, connection)
				_ = connection.Close()
			}()
		default:
			_ = connection.Close()
		}
	}
}

func (server *BrokerControlServer) handleControl(
	ctx context.Context,
	control net.Conn,
) error {
	if server == nil || control == nil {
		return errors.New("networkjail: broker control invalid")
	}
	deadline := time.Now().Add(server.config.HandshakeTimeout)
	if bounded, found := ctx.Deadline(); found && bounded.Before(deadline) {
		deadline = bounded
	}
	if err := control.SetDeadline(deadline); err != nil {
		return errors.New("networkjail: broker control deadline failed")
	}
	frame, err := readControlDialFrame(control)
	if err != nil {
		return err
	}
	upstream, err := server.dialer.DialFrame(ctx, frame)
	zeroBytes(frame)
	if err != nil || upstream == nil {
		if upstream != nil {
			_ = upstream.Close()
		}
		_ = writeDialStatus(control, false)
		return errors.New("networkjail: broker upstream unavailable")
	}
	defer upstream.Close()
	if err := writeDialStatus(control, true); err != nil {
		return err
	}
	if err := control.SetDeadline(time.Time{}); err != nil {
		return nil
	}
	if err := upstream.SetDeadline(time.Time{}); err != nil {
		return errors.New("networkjail: broker upstream deadline reset failed")
	}
	return relayBounded(control, upstream, server.config.RelayTimeout)
}

func readControlDialFrame(connection net.Conn) ([]byte, error) {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return readDialRequestFrame(connection)
	}
	header := make([]byte, dialFrameHeaderBytes)
	if err := readUnixControlExact(unixConnection, header); err != nil {
		return nil, err
	}
	hostLength := int(header[12])<<8 | int(header[13])
	if hostLength <= 0 || hostLength > MaxDialHostBytes {
		zeroBytes(header)
		return nil, errors.New("networkjail: control frame length invalid")
	}
	frame := make([]byte, dialFrameHeaderBytes+hostLength)
	copy(frame, header)
	zeroBytes(header)
	if err := readUnixControlExact(
		unixConnection,
		frame[dialFrameHeaderBytes:],
	); err != nil {
		zeroBytes(frame)
		return nil, err
	}
	if queuedStreamData(unixConnection) {
		zeroBytes(frame)
		return nil, errors.New("networkjail: control frame trailing data")
	}
	return frame, nil
}

func readUnixControlExact(
	connection *net.UnixConn,
	target []byte,
) error {
	offset := 0
	oob := make([]byte, unixFrameOOBBytes)
	defer zeroBytes(oob)
	for offset < len(target) {
		count, oobBytes, flags, address, err := connection.ReadMsgUnix(
			target[offset:],
			oob,
		)
		if oobBytes > 0 {
			closeReceivedUnixRights(oob[:oobBytes])
		}
		if err != nil || count <= 0 || address != nil ||
			oobBytes != 0 ||
			flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 {
			return errors.New("networkjail: control frame rejected")
		}
		offset += count
	}
	return nil
}
