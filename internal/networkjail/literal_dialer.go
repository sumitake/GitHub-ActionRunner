package networkjail

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"
)

const maxLiteralDialTimeout = 30 * time.Second

type literalDialContext func(context.Context, string, string) (net.Conn, error)

type LiteralNetDialer struct {
	timeout time.Duration
	dial    literalDialContext
}

func NewLiteralNetDialer(timeout time.Duration) (*LiteralNetDialer, error) {
	system := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: -1,
	}
	return newLiteralNetDialer(timeout, system.DialContext)
}

func newLiteralNetDialer(
	timeout time.Duration,
	dial literalDialContext,
) (*LiteralNetDialer, error) {
	if timeout <= 0 || timeout > maxLiteralDialTimeout || dial == nil {
		return nil, errors.New("networkjail: literal dialer unavailable")
	}
	return &LiteralNetDialer{timeout: timeout, dial: dial}, nil
}

func (dialer *LiteralNetDialer) DialLiteral(
	ctx context.Context,
	address netip.Addr,
	port uint16,
) (net.Conn, error) {
	if !address.IsValid() || address.Zone() != "" ||
		normalizeEmbedded(address) != address || port == 0 {
		return nil, errors.New("networkjail: literal dial input invalid")
	}
	network := "tcp4"
	if address.Is6() {
		network = "tcp6"
	}
	bounded, cancel := context.WithTimeout(ctx, dialer.timeout)
	defer cancel()
	connection, err := dialer.dial(
		bounded,
		network,
		net.JoinHostPort(address.String(), strconv.Itoa(int(port))),
	)
	if err != nil {
		if connection != nil {
			_ = connection.Close()
		}
		return nil, err
	}
	if connection == nil {
		return nil, errors.New("networkjail: literal dial returned no connection")
	}
	return connection, nil
}

var _ LiteralDialer = (*LiteralNetDialer)(nil)
