//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

const closedDirectPort = 443

var (
	closedIPv4Sentinel = netip.AddrFrom4(
		[4]byte{192, 0, 2, 1},
	).String()
	closedIPv6Sentinel = netip.AddrFrom16(
		[16]byte{
			0x20, 0x01, 0x0d, 0xb8,
			0, 0, 0, 0,
			0, 0, 0, 0,
			0, 0, 0, 1,
		},
	).String()
	closedDNSSentinel = netip.AddrFrom4(
		[4]byte{192, 0, 2, 53},
	).String()
)

var closedDNSQuery = []byte{
	0x50, 0x47,
	0x01, 0x00,
	0x00, 0x01,
	0x00, 0x00,
	0x00, 0x00,
	0x00, 0x00,
	0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
	0x03, 'c', 'o', 'm',
	0x00,
	0x00, 0x01,
	0x00, 0x01,
}

func closedDenialsPlatform() error {
	return nil
}

func defaultClosedDenialsProbeRuntime() closedDenialsProbeRuntime {
	return closedDenialsProbeRuntime{
		inspectEmpty: inspectCurrentNamespace,
		inspectParser: func() (closedParserTopology, error) {
			snapshot, err := inspectCurrentNamespaceTopology(false)
			if err != nil {
				return closedParserTopology{}, err
			}
			return closedParserTopology{
				Identity:     snapshot.Identity,
				LoopbackOnly: snapshot.LoopbackOnly,
				TablesEmpty:  snapshot.TablesEmpty,
			}, nil
		},
		direct: runClosedDirectDenial,
		parser: runClosedParserDenial,
	}
}

func runClosedDirectDenial(
	ctx context.Context,
	operation closedDenialOperation,
) error {
	if ctx == nil {
		return errClosedDenials
	}
	bounded, cancel := context.WithTimeout(ctx, verifierProbeTimeout)
	defer cancel()
	switch operation {
	case closedIPv4TCP:
		return dialClosedStream(
			bounded,
			"tcp4",
			net.JoinHostPort(
				closedIPv4Sentinel,
				strconv.Itoa(closedDirectPort),
			),
		)
	case closedIPv4UDP:
		return sendClosedDatagram(
			bounded,
			"udp4",
			net.JoinHostPort(
				closedIPv4Sentinel,
				strconv.Itoa(closedDirectPort),
			),
			[]byte{0},
		)
	case closedIPv6TCP:
		return dialClosedStream(
			bounded,
			"tcp6",
			net.JoinHostPort(
				closedIPv6Sentinel,
				strconv.Itoa(closedDirectPort),
			),
		)
	case closedIPv6UDP:
		return sendClosedDatagram(
			bounded,
			"udp6",
			net.JoinHostPort(
				closedIPv6Sentinel,
				strconv.Itoa(closedDirectPort),
			),
			[]byte{0},
		)
	case closedDNSUDP:
		return sendClosedDatagram(
			bounded,
			"udp4",
			net.JoinHostPort(closedDNSSentinel, "53"),
			closedDNSQuery,
		)
	case closedRawICMP:
		descriptor, err := unix.Socket(
			unix.AF_INET,
			unix.SOCK_RAW|unix.SOCK_CLOEXEC,
			unix.IPPROTO_ICMP,
		)
		if err == nil {
			_ = unix.Close(descriptor)
		}
		return err
	default:
		return errClosedDenials
	}
}

func dialClosedStream(
	ctx context.Context,
	network,
	address string,
) error {
	connection, err := (&net.Dialer{}).DialContext(
		ctx,
		network,
		address,
	)
	if err == nil {
		_ = connection.Close()
	}
	return err
}

func sendClosedDatagram(
	ctx context.Context,
	network,
	address string,
	payload []byte,
) error {
	connection, err := (&net.Dialer{}).DialContext(
		ctx,
		network,
		address,
	)
	if err != nil {
		return err
	}
	defer connection.Close()
	if deadline, found := ctx.Deadline(); found {
		if err := connection.SetDeadline(deadline); err != nil {
			return errClosedDenials
		}
	}
	_, err = connection.Write(payload)
	return err
}

func runClosedParserDenial(
	ctx context.Context,
	request closedParserRequest,
) error {
	if ctx == nil {
		return errClosedDenials
	}
	bounded, cancel := context.WithTimeout(ctx, verifierProbeTimeout)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(
		bounded,
		"tcp4",
		verifierProxyAddress,
	)
	if err != nil {
		return errClosedDenials
	}
	defer connection.Close()
	if deadline, found := bounded.Deadline(); found {
		if err := connection.SetDeadline(deadline); err != nil {
			return errClosedDenials
		}
	}
	switch request.Operation {
	case closedPlaintextHTTP:
		frame := []byte(
			"GET / HTTP/1.1\r\n" +
				"Host: localhost\r\n" +
				"Connection: close\r\n\r\n",
		)
		if err := writeProbeFrame(connection, frame); err != nil {
			zero(frame)
			return errClosedDenials
		}
		zero(frame)
		if !closedParserRejected(connection) {
			return errClosedDenials
		}
		return errClosedPlaintextHTTPRejected
	case closedUnsupportedConnectPort:
		if request.Host == "" ||
			request.Port != closedUnsupportedPort {
			return errClosedDenials
		}
		authority := net.JoinHostPort(
			request.Host,
			strconv.Itoa(int(request.Port)),
		)
		frame := []byte(
			"CONNECT " + authority + " HTTP/1.1\r\n" +
				"Host: " + authority + "\r\n\r\n",
		)
		if err := writeProbeFrame(connection, frame); err != nil {
			zero(frame)
			return errClosedDenials
		}
		zero(frame)
		if !closedParserRejected(connection) {
			return errClosedDenials
		}
		return errClosedUnsupportedConnectRejected
	case closedSOCKSBind, closedSOCKSUDPAssociate:
		if request.Host == "" ||
			len(request.Host) > 255 ||
			request.Port != closedUnsupportedPort {
			return errClosedDenials
		}
		if err := writeProbeFrame(
			connection,
			[]byte{5, 1, 0},
		); err != nil {
			return errClosedDenials
		}
		var greeting [2]byte
		if _, err := io.ReadFull(connection, greeting[:]); err != nil ||
			greeting != [2]byte{5, 0} {
			return errClosedDenials
		}
		command := byte(2)
		rejected := errClosedSOCKSBindRejected
		if request.Operation == closedSOCKSUDPAssociate {
			command = 3
			rejected = errClosedSOCKSUDPAssociateRejected
		}
		frame := []byte{5, command, 0, 3, byte(len(request.Host))}
		frame = append(frame, request.Host...)
		var port [2]byte
		binary.BigEndian.PutUint16(port[:], request.Port)
		frame = append(frame, port[:]...)
		if err := writeProbeFrame(connection, frame); err != nil {
			zero(frame)
			return errClosedDenials
		}
		zero(frame)
		if !closedParserRejected(connection) {
			return errClosedDenials
		}
		return rejected
	default:
		return errClosedDenials
	}
}

func closedParserRejected(connection net.Conn) bool {
	var response [1]byte
	count, err := connection.Read(response[:])
	response[0] = 0
	return count == 0 &&
		(errors.Is(err, io.EOF) ||
			errors.Is(err, syscall.ECONNRESET) ||
			errors.Is(err, syscall.EPIPE))
}
