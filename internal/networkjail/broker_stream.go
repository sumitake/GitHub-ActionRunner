package networkjail

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

const dialStatusBytes = 9

var dialStatusMagic = [8]byte{'P', 'G', 'H', 'D', 'S', 'T', 'A', '1'}

func readDialRequestFrame(reader io.Reader) ([]byte, error) {
	if reader == nil {
		return nil, errors.New("networkjail: dial stream unavailable")
	}
	header := make([]byte, dialFrameHeaderBytes)
	if _, err := io.ReadFull(reader, header); err != nil ||
		!bytes.Equal(header[:8], dialFrameMagic[:]) {
		return nil, errors.New("networkjail: dial stream header invalid")
	}
	hostLength := int(binary.BigEndian.Uint16(header[12:14]))
	if hostLength <= 0 || hostLength > MaxDialHostBytes {
		return nil, errors.New("networkjail: dial stream length invalid")
	}
	frame := make([]byte, dialFrameHeaderBytes+hostLength)
	copy(frame, header)
	if _, err := io.ReadFull(reader, frame[dialFrameHeaderBytes:]); err != nil {
		return nil, errors.New("networkjail: dial stream body invalid")
	}
	return frame, nil
}

func writeDialRequestFrame(writer io.Writer, frame []byte) error {
	if writer == nil || len(frame) < dialFrameHeaderBytes ||
		len(frame) > MaxDialRequestFrameBytes {
		return errors.New("networkjail: dial stream frame invalid")
	}
	written := 0
	for written < len(frame) {
		count, err := writer.Write(frame[written:])
		if err != nil || count <= 0 {
			return errors.New("networkjail: dial stream write failed")
		}
		written += count
	}
	return nil
}

func writeDialStatus(writer io.Writer, allowed bool) error {
	frame := make([]byte, dialStatusBytes)
	copy(frame[:8], dialStatusMagic[:])
	if allowed {
		frame[8] = 1
	}
	written := 0
	for written < len(frame) {
		count, err := writer.Write(frame[written:])
		if err != nil || count <= 0 {
			return errors.New("networkjail: dial status write failed")
		}
		written += count
	}
	return nil
}

func readDialStatus(reader io.Reader) (bool, error) {
	var frame [dialStatusBytes]byte
	if reader == nil {
		return false, errors.New("networkjail: dial status unavailable")
	}
	if _, err := io.ReadFull(reader, frame[:]); err != nil ||
		!bytes.Equal(frame[:8], dialStatusMagic[:]) ||
		(frame[8] != 0 && frame[8] != 1) {
		return false, errors.New("networkjail: dial status invalid")
	}
	return frame[8] == 1, nil
}

func relayBounded(
	left,
	right net.Conn,
	timeout time.Duration,
) error {
	if left == nil || right == nil || timeout <= 0 {
		return errors.New("networkjail: relay unavailable")
	}
	type result struct {
		err error
	}
	results := make(chan result, 2)
	copyDirection := func(destination, source net.Conn) {
		buffer := make([]byte, 32<<10)
		_, err := io.CopyBuffer(destination, source, buffer)
		zeroBytes(buffer)
		if closer, ok := destination.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
		results <- result{err: err}
	}
	go copyDirection(right, left)
	go copyDirection(left, right)

	first := <-results
	deadline := time.Now().Add(timeout)
	_ = left.SetDeadline(deadline)
	_ = right.SetDeadline(deadline)
	second := <-results
	if first.err != nil && !errors.Is(first.err, net.ErrClosed) {
		return errors.New("networkjail: relay failed")
	}
	if second.err != nil && !errors.Is(second.err, net.ErrClosed) {
		if timeoutError, ok := second.err.(net.Error); !ok || !timeoutError.Timeout() {
			return errors.New("networkjail: relay failed")
		}
	}
	return nil
}
