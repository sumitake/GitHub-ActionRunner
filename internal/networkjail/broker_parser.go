package networkjail

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

const (
	httpConnectOK = "HTTP/1.1 200 Connection Established\r\n\r\n"
)

var (
	socksGreetingOK = []byte{5, 0}
	socksConnectOK  = []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
)

type ControlConnector interface {
	Connect(context.Context) (net.Conn, error)
}

type ParserRuntimeConfig struct {
	HandshakeTimeout time.Duration
	RelayTimeout     time.Duration
	MaxClients       uint32
}

type BrokerParser struct {
	graph     DecisionGraph
	connector ControlConnector
	config    ParserRuntimeConfig
	slots     chan struct{}
}

func NewBrokerParser(
	graph DecisionGraph,
	connector ControlConnector,
	config ParserRuntimeConfig,
) (*BrokerParser, error) {
	if graph.digest == (Digest{}) || connector == nil ||
		config.HandshakeTimeout <= 0 ||
		config.HandshakeTimeout > 30*time.Second ||
		config.RelayTimeout <= 0 ||
		config.RelayTimeout > 30*time.Second ||
		config.MaxClients == 0 || config.MaxClients > 1024 {
		return nil, errors.New("networkjail: broker parser unavailable")
	}
	return &BrokerParser{
		graph:     graph,
		connector: connector,
		config:    config,
		slots:     make(chan struct{}, config.MaxClients),
	}, nil
}

func (parser *BrokerParser) Serve(
	ctx context.Context,
	listener *net.UnixListener,
) error {
	if parser == nil || ctx == nil || listener == nil {
		return errors.New("networkjail: broker parser unavailable")
	}
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errors.New("networkjail: broker parser accept failed")
		}
		select {
		case parser.slots <- struct{}{}:
			go func() {
				defer func() { <-parser.slots }()
				_ = parser.handleClient(ctx, connection)
				_ = connection.Close()
			}()
		default:
			_ = connection.Close()
		}
	}
}

func (parser *BrokerParser) handleClient(
	ctx context.Context,
	client net.Conn,
) error {
	if parser == nil || client == nil {
		return errors.New("networkjail: parser client invalid")
	}
	deadline := time.Now().Add(parser.config.HandshakeTimeout)
	if bounded, found := ctx.Deadline(); found && bounded.Before(deadline) {
		deadline = bounded
	}
	if err := client.SetDeadline(deadline); err != nil {
		return errors.New("networkjail: parser client deadline failed")
	}

	request, protocol, err := parser.readClientRequest(client)
	if err != nil {
		return err
	}
	frame, err := EncodeDialRequest(request)
	if err != nil {
		return errors.New("networkjail: parser frame failed")
	}
	control, err := parser.connector.Connect(ctx)
	if err != nil || control == nil {
		if control != nil {
			_ = control.Close()
		}
		return errors.New("networkjail: parser control unavailable")
	}
	defer control.Close()
	if err := control.SetDeadline(deadline); err != nil {
		return errors.New("networkjail: parser control deadline failed")
	}
	if err := writeDialRequestFrame(control, frame); err != nil {
		return err
	}
	allowed, err := readDialStatus(control)
	if err != nil || !allowed {
		return errors.New("networkjail: parser dial rejected")
	}
	switch protocol {
	case HTTPConnect:
		if _, err := io.WriteString(client, httpConnectOK); err != nil {
			return errors.New("networkjail: parser response failed")
		}
	case SOCKS5Connect:
		if _, err := client.Write(socksConnectOK); err != nil {
			return errors.New("networkjail: parser response failed")
		}
	default:
		return errors.New("networkjail: parser protocol invalid")
	}
	if err := client.SetDeadline(time.Time{}); err != nil {
		return nil
	}
	if err := control.SetDeadline(time.Time{}); err != nil {
		return errors.New("networkjail: parser relay deadline reset failed")
	}
	return relayBounded(client, control, parser.config.RelayTimeout)
}

func (parser *BrokerParser) readClientRequest(
	client net.Conn,
) (DialRequest, ProxyProtocol, error) {
	var first [1]byte
	if _, err := io.ReadFull(client, first[:]); err != nil {
		return DialRequest{}, "", errors.New("networkjail: parser request unavailable")
	}
	switch first[0] {
	case 'C':
		data, err := readHTTPConnectRemainder(client, first[0])
		if err != nil {
			return DialRequest{}, "", err
		}
		request, err := ParseHTTPConnect(data, parser.graph)
		zeroBytes(data)
		if err != nil {
			return DialRequest{}, "", errors.New("networkjail: parser connect rejected")
		}
		return request, HTTPConnect, nil
	case 5:
		return parser.readSOCKS5(client, first[0])
	default:
		return DialRequest{}, "", errors.New("networkjail: parser protocol rejected")
	}
}

func readHTTPConnectRemainder(
	connection net.Conn,
	first byte,
) ([]byte, error) {
	data := make([]byte, 1, MaxProxyHeaderBytes+1)
	data[0] = first
	buffer := make([]byte, 4096)
	defer zeroBytes(buffer)
	for {
		count, err := connection.Read(buffer)
		if count > 0 {
			data = append(data, buffer[:count]...)
			if len(data) > MaxProxyHeaderBytes {
				zeroBytes(data)
				return nil, errors.New("networkjail: parser connect too large")
			}
			if boundary := bytes.Index(data, []byte("\r\n\r\n")); boundary >= 0 {
				if boundary+4 != len(data) ||
					queuedStreamData(connection) {
					zeroBytes(data)
					return nil, errors.New("networkjail: parser connect trailing data")
				}
				return data, nil
			}
		}
		if err != nil {
			zeroBytes(data)
			return nil, errors.New("networkjail: parser connect incomplete")
		}
	}
}

func (parser *BrokerParser) readSOCKS5(
	connection net.Conn,
	first byte,
) (DialRequest, ProxyProtocol, error) {
	greeting := []byte{first, 0, 0}
	if _, err := io.ReadFull(connection, greeting[1:]); err != nil ||
		!bytes.Equal(greeting, []byte{5, 1, 0}) ||
		queuedStreamData(connection) {
		return DialRequest{}, "", errors.New("networkjail: parser socks greeting rejected")
	}
	if _, err := connection.Write(socksGreetingOK); err != nil {
		return DialRequest{}, "", errors.New("networkjail: parser socks greeting failed")
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(connection, header); err != nil ||
		header[0] != 5 || header[1] != 1 || header[2] != 0 {
		return DialRequest{}, "", errors.New("networkjail: parser socks request rejected")
	}
	bodyBytes := 0
	switch header[3] {
	case 1:
		bodyBytes = 4 + 2
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(connection, length[:]); err != nil ||
			length[0] == 0 || int(length[0]) > MaxDialHostBytes {
			return DialRequest{}, "", errors.New("networkjail: parser socks name rejected")
		}
		header = append(header, length[0])
		bodyBytes = int(length[0]) + 2
	case 4:
		bodyBytes = 16 + 2
	default:
		return DialRequest{}, "", errors.New("networkjail: parser socks address rejected")
	}
	body := make([]byte, bodyBytes)
	if _, err := io.ReadFull(connection, body); err != nil ||
		queuedStreamData(connection) {
		zeroBytes(body)
		return DialRequest{}, "", errors.New("networkjail: parser socks body rejected")
	}
	combined := make([]byte, 3+len(header)+len(body))
	copy(combined, greeting)
	copy(combined[3:], header)
	copy(combined[3+len(header):], body)
	zeroBytes(body)
	request, err := ParseSOCKS5Connect(combined, parser.graph)
	zeroBytes(combined)
	if err != nil {
		return DialRequest{}, "", errors.New("networkjail: parser socks rejected")
	}
	return request, SOCKS5Connect, nil
}

func queuedStreamData(connection net.Conn) bool {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return true
	}
	queued := false
	controlErr := raw.Control(func(fd uintptr) {
		var probe [1]byte
		count, _, recvErr := unix.Recvfrom(
			int(fd),
			probe[:],
			unix.MSG_PEEK|unix.MSG_DONTWAIT,
		)
		if count > 0 || (recvErr != nil &&
			!errors.Is(recvErr, unix.EAGAIN) &&
			!errors.Is(recvErr, unix.EWOULDBLOCK)) {
			queued = true
		}
	})
	return controlErr != nil || queued
}

type UnixControlConnector struct {
	Path    string
	Timeout time.Duration
}

func (connector UnixControlConnector) Connect(ctx context.Context) (net.Conn, error) {
	if connector.Path == "" || connector.Timeout <= 0 ||
		connector.Timeout > 30*time.Second {
		return nil, errors.New("networkjail: parser control unavailable")
	}
	deadline := time.Now().Add(connector.Timeout)
	if bounded, found := ctx.Deadline(); found && bounded.Before(deadline) {
		deadline = bounded
	}
	dialer := net.Dialer{Deadline: deadline}
	connection, err := dialer.DialContext(ctx, "unix", connector.Path)
	if err != nil {
		return nil, errors.New("networkjail: parser control unavailable")
	}
	return connection, nil
}
