package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
)

const maxFloodRequestBytes = 128

type floodRequest struct {
	Version  uint8  `json:"version"`
	Attempts uint64 `json:"attempts"`
}

func decodeFloodRequest(reader io.Reader) (floodRequest, error) {
	if reader == nil {
		return floodRequest{}, errors.New("network-verifier: flood input invalid")
	}
	document, err := io.ReadAll(io.LimitReader(reader, maxFloodRequestBytes+1))
	if err != nil || len(document) == 0 || len(document) > maxFloodRequestBytes {
		zero(document)
		return floodRequest{}, errors.New("network-verifier: flood input invalid")
	}
	defer zero(document)
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var request floodRequest
	if err := decoder.Decode(&request); err != nil ||
		decoder.Decode(&struct{}{}) != io.EOF ||
		request.Version != 1 ||
		request.Attempts == 0 {
		return floodRequest{}, errors.New("network-verifier: flood input invalid")
	}
	canonical, err := json.Marshal(request)
	if err != nil {
		return floodRequest{}, errors.New("network-verifier: flood input invalid")
	}
	canonical = append(canonical, '\n')
	defer zero(canonical)
	if !bytes.Equal(document, canonical) {
		return floodRequest{}, errors.New("network-verifier: flood input invalid")
	}
	return request, nil
}

func runLoopbackFlood(ctx context.Context, attempts uint64) error {
	if ctx == nil || ctx.Err() != nil || attempts == 0 {
		return errors.New("network-verifier: loopback flood unavailable")
	}
	listener, err := (&net.ListenConfig{}).Listen(
		ctx,
		"tcp4",
		net.JoinHostPort(net.IPv4(127, 0, 0, 1).String(), "0"),
	)
	if err != nil {
		return errors.New("network-verifier: loopback listener unavailable")
	}
	defer listener.Close()
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || address.Port <= 0 || !address.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		return errors.New("network-verifier: loopback listener invalid")
	}
	stopListener := context.AfterFunc(ctx, func() {
		_ = listener.Close()
	})
	defer stopListener()

	for attempt := uint64(0); attempt < attempts; attempt++ {
		if ctx.Err() != nil {
			return errors.New("network-verifier: loopback flood canceled")
		}
		client, err := (&net.Dialer{}).DialContext(
			ctx,
			"tcp4",
			listener.Addr().String(),
		)
		if err != nil {
			return errors.New("network-verifier: loopback client unavailable")
		}
		server, err := listener.Accept()
		if err != nil {
			_ = client.Close()
			return errors.New("network-verifier: loopback accept failed")
		}
		if err := exchangeFloodByte(ctx, client, server, byte(attempt)); err != nil {
			_ = client.Close()
			_ = server.Close()
			return err
		}
		clientErr := client.Close()
		serverErr := server.Close()
		if clientErr != nil || serverErr != nil {
			return errors.New("network-verifier: loopback close failed")
		}
	}
	return nil
}

func exchangeFloodByte(
	ctx context.Context,
	client,
	server net.Conn,
	value byte,
) error {
	if ctx == nil || client == nil || server == nil {
		return errors.New("network-verifier: loopback exchange unavailable")
	}
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = client.Close()
			_ = server.Close()
		})
	}
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		if client.SetDeadline(deadline) != nil ||
			server.SetDeadline(deadline) != nil {
			return errors.New("network-verifier: loopback deadline failed")
		}
	}
	request := []byte{value}
	if _, err := client.Write(request); err != nil {
		return errors.New("network-verifier: loopback client write failed")
	}
	var observed [1]byte
	if _, err := io.ReadFull(server, observed[:]); err != nil ||
		observed[0] != value {
		return errors.New("network-verifier: loopback server read failed")
	}
	response := value ^ 0xff
	if _, err := server.Write([]byte{response}); err != nil {
		return errors.New("network-verifier: loopback server write failed")
	}
	if _, err := io.ReadFull(client, observed[:]); err != nil ||
		observed[0] != response {
		return errors.New("network-verifier: loopback client read failed")
	}
	if ctx.Err() != nil {
		return errors.New("network-verifier: loopback flood canceled")
	}
	return nil
}
