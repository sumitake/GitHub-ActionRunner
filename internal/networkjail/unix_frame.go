//go:build linux || darwin

package networkjail

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

const (
	maxUnixFrameReadTimeout = 30 * time.Second
	unixFrameOOBBytes       = 4096
)

func ReadDialRequestUnix(
	ctx context.Context,
	connection *net.UnixConn,
	graph DecisionGraph,
	timeout time.Duration,
) (DialRequest, error) {
	if connection == nil || graph.digest == (Digest{}) ||
		timeout <= 0 || timeout > maxUnixFrameReadTimeout {
		return DialRequest{}, errors.New("networkjail: unix dial frame reader unavailable")
	}
	if err := ctx.Err(); err != nil {
		return DialRequest{}, errors.New("networkjail: unix dial frame cancelled")
	}
	deadline := time.Now().Add(timeout)
	if contextDeadline, found := ctx.Deadline(); found &&
		contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetReadDeadline(deadline); err != nil {
		return DialRequest{}, errors.New("networkjail: unix dial frame deadline failed")
	}
	defer func() { _ = connection.SetReadDeadline(time.Time{}) }()

	data := make([]byte, 0, MaxDialRequestFrameBytes+1)
	oob := make([]byte, unixFrameOOBBytes)
	for {
		remaining := MaxDialRequestFrameBytes + 1 - len(data)
		if remaining <= 0 {
			return DialRequest{}, errors.New("networkjail: unix dial frame rejected")
		}
		chunk := make([]byte, remaining)
		dataBytes, oobBytes, flags, _, err := connection.ReadMsgUnix(
			chunk,
			oob,
		)
		if oobBytes > 0 {
			closeReceivedUnixRights(oob[:oobBytes])
		}
		if oobBytes != 0 ||
			flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 {
			return DialRequest{}, errors.New("networkjail: unix dial frame rejected")
		}
		if dataBytes < 0 || dataBytes > len(chunk) {
			return DialRequest{}, errors.New("networkjail: unix dial frame rejected")
		}
		data = append(data, chunk[:dataBytes]...)
		if len(data) > MaxDialRequestFrameBytes {
			return DialRequest{}, errors.New("networkjail: unix dial frame rejected")
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return DialRequest{}, errors.New("networkjail: unix dial frame read failed")
		}
		if dataBytes == 0 {
			return DialRequest{}, errors.New("networkjail: unix dial frame rejected")
		}
	}
	if len(data) == 0 {
		return DialRequest{}, errors.New("networkjail: unix dial frame rejected")
	}
	request, err := DecodeDialRequest(data, graph)
	if err != nil {
		return DialRequest{}, errors.New("networkjail: unix dial frame rejected")
	}
	return request, nil
}

func closeReceivedUnixRights(oob []byte) {
	messages, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return
	}
	for _, message := range messages {
		descriptors, err := unix.ParseUnixRights(&message)
		if err != nil {
			continue
		}
		for _, descriptor := range descriptors {
			_ = unix.Close(descriptor)
		}
	}
}
