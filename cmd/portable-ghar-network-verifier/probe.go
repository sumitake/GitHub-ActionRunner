package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/sumitake/portable-ghar/internal/networkjail"
)

const (
	verifierProxyAddress = "127.0.0.1:18080"
	verifierProbeTimeout = 15 * time.Second
)

type loopbackProbeClient struct{}

func (loopbackProbeClient) Probe(
	ctx context.Context,
	probe networkjail.Probe,
) error {
	if ctx == nil {
		return errors.New("network-verifier: probe unavailable")
	}
	bounded, cancel := context.WithTimeout(ctx, verifierProbeTimeout)
	defer cancel()
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(
		bounded,
		"tcp4",
		verifierProxyAddress,
	)
	if err != nil {
		return errors.New("network-verifier: proxy unavailable")
	}
	defer connection.Close()
	deadline, _ := bounded.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		return errors.New("network-verifier: proxy deadline failed")
	}
	switch probe.Protocol {
	case networkjail.HTTPConnect:
		return probeHTTPConnect(connection, probe)
	case networkjail.SOCKS5Connect:
		return probeSOCKS5(connection, probe)
	default:
		return errors.New("network-verifier: proxy protocol invalid")
	}
}

func probeHTTPConnect(connection net.Conn, probe networkjail.Probe) error {
	authority := net.JoinHostPort(
		probe.Host,
		strconv.Itoa(int(probe.Port)),
	)
	request := []byte(
		"CONNECT " + authority + " HTTP/1.1\r\n" +
			"Host: " + authority + "\r\n\r\n",
	)
	if err := writeProbeFrame(connection, request); err != nil {
		zero(request)
		return err
	}
	zero(request)
	response := make([]byte, len("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if _, err := io.ReadFull(connection, response); err != nil ||
		!bytes.Equal(
			response,
			[]byte("HTTP/1.1 200 Connection Established\r\n\r\n"),
		) {
		zero(response)
		return errors.New("network-verifier: connect rejected")
	}
	zero(response)
	return nil
}

func probeSOCKS5(connection net.Conn, probe networkjail.Probe) error {
	if err := writeProbeFrame(connection, []byte{5, 1, 0}); err != nil {
		return err
	}
	var greeting [2]byte
	if _, err := io.ReadFull(connection, greeting[:]); err != nil ||
		greeting != [2]byte{5, 0} {
		return errors.New("network-verifier: socks greeting rejected")
	}
	request, err := encodeSOCKSProbe(probe)
	if err != nil {
		return err
	}
	if err := writeProbeFrame(connection, request); err != nil {
		zero(request)
		return err
	}
	zero(request)
	response := make([]byte, 10)
	if _, err := io.ReadFull(connection, response); err != nil ||
		!bytes.Equal(response, []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}) {
		zero(response)
		return errors.New("network-verifier: socks connect rejected")
	}
	zero(response)
	return nil
}

func encodeSOCKSProbe(probe networkjail.Probe) ([]byte, error) {
	if probe.Port == 0 || probe.Host == "" {
		return nil, errors.New("network-verifier: socks destination invalid")
	}
	request := []byte{5, 1, 0}
	if address, err := netip.ParseAddr(probe.Host); err == nil {
		if address.Is4() {
			request = append(request, 1)
			bytes4 := address.As4()
			request = append(request, bytes4[:]...)
		} else if address.Is6() && address.Zone() == "" {
			request = append(request, 4)
			bytes16 := address.As16()
			request = append(request, bytes16[:]...)
		} else {
			return nil, errors.New("network-verifier: socks literal invalid")
		}
	} else {
		if len(probe.Host) > 255 {
			return nil, errors.New("network-verifier: socks name invalid")
		}
		request = append(request, 3, byte(len(probe.Host)))
		request = append(request, probe.Host...)
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], probe.Port)
	request = append(request, port[:]...)
	return request, nil
}

func writeProbeFrame(writer io.Writer, frame []byte) error {
	buffered := bufio.NewWriterSize(writer, len(frame))
	if _, err := buffered.Write(frame); err != nil ||
		buffered.Flush() != nil {
		return errors.New("network-verifier: proxy write failed")
	}
	return nil
}
