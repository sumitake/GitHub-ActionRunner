package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

const (
	brokerStateDirectory       = "/run/portable-ghar/state"
	brokerCommandFIFOName      = "command.fifo"
	brokerResponseFIFOName     = "response.fifo"
	brokerCommandHeaderBytes   = 30
	brokerResponseHeaderBytes  = 30
	maxBrokerCommandPayload    = 160 << 10
	brokerControlPollInterval  = 25 * time.Millisecond
	brokerControlProtocol      = 1
	brokerResponseStatusOK     = 0
	brokerResponseStatusFailed = 1
)

var (
	brokerCommandMagic  = [8]byte{'P', 'G', 'H', 'B', 'C', 'M', 'D', '1'}
	brokerResponseMagic = [8]byte{'P', 'G', 'H', 'B', 'R', 'S', 'P', '1'}
)

type brokerControlPaths struct {
	directory string
	command   string
	response  string
}

type fifoIdentity struct {
	device uint64
	inode  uint64
	uid    uint32
	gid    uint32
	mode   uint32
}

func defaultBrokerControlPaths() brokerControlPaths {
	return brokerControlPaths{
		directory: brokerStateDirectory,
		command:   filepath.Join(brokerStateDirectory, brokerCommandFIFOName),
		response:  filepath.Join(brokerStateDirectory, brokerResponseFIFOName),
	}
}

func serveBrokerCommands(
	ctx context.Context,
	paths brokerControlPaths,
	machine *brokerMachine,
) error {
	if ctx == nil || machine == nil || validateControlPaths(paths) != nil {
		return errors.New("broker-dialer: command transport unavailable")
	}
	if err := verifyPrivateDirectory(paths.directory); err != nil {
		return err
	}
	commandFD, commandIdentity, err := createControlFIFO(paths.command)
	if err != nil {
		return err
	}
	defer closeAndRemoveFIFO(commandFD, paths.command, commandIdentity)
	responseFD, responseIdentity, err := createControlFIFO(paths.response)
	if err != nil {
		return err
	}
	defer closeAndRemoveFIFO(responseFD, paths.response, responseIdentity)

	for {
		header := make([]byte, brokerCommandHeaderBytes)
		if err := readFIFOExact(ctx, commandFD, header); err != nil {
			zero(header)
			if ctx.Err() != nil {
				return nil
			}
			return errors.New("broker-dialer: command read failed")
		}
		if !bytes.Equal(header[:8], brokerCommandMagic[:]) ||
			header[8] != brokerControlProtocol ||
			header[9] < byte(brokerOpArm) ||
			header[9] > byte(brokerOpAudit) {
			zero(header)
			return errors.New("broker-dialer: command header invalid")
		}
		operation := brokerOperation(header[9])
		payloadLength := int(binary.BigEndian.Uint32(header[10:14]))
		if payloadLength < 0 || payloadLength > maxBrokerCommandPayload {
			zero(header)
			return errors.New("broker-dialer: command length invalid")
		}
		var requestID [16]byte
		copy(requestID[:], header[14:30])
		zero(header)
		if allZero(requestID[:]) {
			return errors.New("broker-dialer: command identity invalid")
		}
		payload := make([]byte, payloadLength)
		if payloadLength > 0 {
			if err := readFIFOExact(ctx, commandFD, payload); err != nil {
				zero(payload)
				return errors.New("broker-dialer: command payload failed")
			}
		}
		response, applyErr := machine.apply(ctx, operation, payload)
		zero(payload)
		status := byte(brokerResponseStatusOK)
		if applyErr != nil {
			zero(response)
			response = nil
			status = brokerResponseStatusFailed
		}
		if err := writeBrokerResponse(
			ctx,
			responseFD,
			requestID,
			status,
			response,
		); err != nil {
			zero(response)
			zero(requestID[:])
			return errors.New("broker-dialer: response write failed")
		}
		zero(response)
		zero(requestID[:])
		if applyErr != nil {
			return errors.New("broker-dialer: command rejected")
		}
	}
}

func forwardBroker(
	ctx context.Context,
	operation brokerOperation,
	input io.Reader,
	output io.Writer,
) error {
	return forwardBrokerAt(
		ctx,
		defaultBrokerControlPaths(),
		operation,
		input,
		output,
	)
}

func forwardBrokerAt(
	ctx context.Context,
	paths brokerControlPaths,
	operation brokerOperation,
	input io.Reader,
	output io.Writer,
) error {
	if ctx == nil || output == nil ||
		operation < brokerOpArm || operation > brokerOpAudit ||
		validateControlPaths(paths) != nil ||
		verifyPrivateDirectory(paths.directory) != nil {
		return errors.New("broker-dialer: command transport unavailable")
	}
	payload, err := readBoundedInput(input, maxBrokerCommandPayload)
	if err != nil {
		return err
	}
	defer zero(payload)
	commandFD, commandIdentity, err := openControlFIFO(paths.command, unix.O_WRONLY)
	if err != nil {
		return err
	}
	defer unix.Close(commandFD)
	responseFD, responseIdentity, err := openControlFIFO(paths.response, unix.O_RDONLY)
	if err != nil {
		return err
	}
	defer unix.Close(responseFD)
	if commandIdentity.uid != responseIdentity.uid ||
		commandIdentity.gid != responseIdentity.gid {
		return errors.New("broker-dialer: command transport owner mismatch")
	}
	var requestID [16]byte
	if _, err := io.ReadFull(rand.Reader, requestID[:]); err != nil ||
		allZero(requestID[:]) {
		zero(requestID[:])
		return errors.New("broker-dialer: command identity unavailable")
	}
	header := make([]byte, brokerCommandHeaderBytes)
	copy(header[:8], brokerCommandMagic[:])
	header[8] = brokerControlProtocol
	header[9] = byte(operation)
	binary.BigEndian.PutUint32(header[10:14], uint32(len(payload)))
	copy(header[14:], requestID[:])
	if err := writeFIFOAll(ctx, commandFD, header); err != nil {
		zero(header)
		zero(requestID[:])
		return errors.New("broker-dialer: command write failed")
	}
	zero(header)
	if len(payload) > 0 {
		if err := writeFIFOAll(ctx, commandFD, payload); err != nil {
			zero(requestID[:])
			return errors.New("broker-dialer: command write failed")
		}
	}
	responseHeader := make([]byte, brokerResponseHeaderBytes)
	if err := readFIFOExact(ctx, responseFD, responseHeader); err != nil {
		zero(responseHeader)
		zero(requestID[:])
		return errors.New("broker-dialer: response read failed")
	}
	status := responseHeader[9]
	responseLength := int(binary.BigEndian.Uint32(responseHeader[10:14]))
	validHeader := bytes.Equal(responseHeader[:8], brokerResponseMagic[:]) &&
		responseHeader[8] == brokerControlProtocol &&
		subtleEqual(responseHeader[14:30], requestID[:]) &&
		(status == brokerResponseStatusOK ||
			status == brokerResponseStatusFailed) &&
		responseLength >= 0 &&
		responseLength <= maxBrokerCommandResponse
	zero(responseHeader)
	zero(requestID[:])
	if !validHeader ||
		(status == brokerResponseStatusFailed && responseLength != 0) {
		return errors.New("broker-dialer: response invalid")
	}
	response := make([]byte, responseLength)
	if responseLength > 0 {
		if err := readFIFOExact(ctx, responseFD, response); err != nil {
			zero(response)
			return errors.New("broker-dialer: response read failed")
		}
	}
	if status != brokerResponseStatusOK {
		zero(response)
		return errors.New("broker-dialer: operation rejected")
	}
	if len(response) > 0 {
		if err := writeOutput(output, response); err != nil {
			zero(response)
			return errors.New("broker-dialer: output failed")
		}
	}
	zero(response)
	return nil
}

func writeBrokerResponse(
	ctx context.Context,
	fd int,
	requestID [16]byte,
	status byte,
	response []byte,
) error {
	if len(response) > maxBrokerCommandResponse ||
		(status != brokerResponseStatusOK &&
			status != brokerResponseStatusFailed) {
		return errors.New("broker-dialer: response invalid")
	}
	header := make([]byte, brokerResponseHeaderBytes)
	copy(header[:8], brokerResponseMagic[:])
	header[8] = brokerControlProtocol
	header[9] = status
	binary.BigEndian.PutUint32(header[10:14], uint32(len(response)))
	copy(header[14:], requestID[:])
	if err := writeFIFOAll(ctx, fd, header); err != nil {
		zero(header)
		return err
	}
	zero(header)
	if len(response) > 0 {
		return writeFIFOAll(ctx, fd, response)
	}
	return nil
}

func validateControlPaths(paths brokerControlPaths) error {
	if !filepath.IsAbs(paths.directory) ||
		filepath.Clean(paths.directory) != paths.directory ||
		paths.command != filepath.Join(paths.directory, brokerCommandFIFOName) ||
		paths.response != filepath.Join(paths.directory, brokerResponseFIFOName) ||
		paths.command == paths.response {
		return errors.New("broker-dialer: command paths invalid")
	}
	return nil
}

func verifyPrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o700 {
		return errors.New("broker-dialer: command directory invalid")
	}
	var stat unix.Stat_t
	if unix.Lstat(path, &stat) != nil ||
		stat.Dev == 0 || stat.Ino == 0 ||
		stat.Uid != uint32(os.Geteuid()) ||
		stat.Gid != uint32(os.Getegid()) ||
		stat.Nlink == 0 {
		return errors.New("broker-dialer: command directory identity invalid")
	}
	return nil
}

func createControlFIFO(path string) (int, fifoIdentity, error) {
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return -1, fifoIdentity{}, errors.New("broker-dialer: command fifo exists")
	}
	if err := unix.Mkfifo(path, 0o600); err != nil {
		return -1, fifoIdentity{}, errors.New("broker-dialer: command fifo create failed")
	}
	fd, identity, err := openControlFIFO(path, unix.O_RDWR)
	if err != nil {
		_ = os.Remove(path)
		return -1, fifoIdentity{}, err
	}
	return fd, identity, nil
}

func openControlFIFO(path string, access int) (int, fifoIdentity, error) {
	var before unix.Stat_t
	if unix.Lstat(path, &before) != nil ||
		uint32(before.Mode)&unix.S_IFMT != unix.S_IFIFO ||
		uint32(before.Mode)&0o777 != 0o600 ||
		before.Uid != uint32(os.Geteuid()) ||
		before.Gid != uint32(os.Getegid()) ||
		before.Nlink != 1 {
		return -1, fifoIdentity{}, errors.New("broker-dialer: command fifo invalid")
	}
	fd, err := unix.Open(
		path,
		access|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return -1, fifoIdentity{}, errors.New("broker-dialer: command fifo open failed")
	}
	var after unix.Stat_t
	if unix.Fstat(fd, &after) != nil ||
		after.Dev != before.Dev ||
		after.Ino != before.Ino ||
		after.Mode != before.Mode ||
		after.Uid != before.Uid ||
		after.Gid != before.Gid ||
		after.Nlink != before.Nlink {
		_ = unix.Close(fd)
		return -1, fifoIdentity{}, errors.New("broker-dialer: command fifo changed")
	}
	return fd, fifoIdentity{
		device: uint64(after.Dev),
		inode:  after.Ino,
		uid:    after.Uid,
		gid:    after.Gid,
		mode:   uint32(after.Mode),
	}, nil
}

func closeAndRemoveFIFO(fd int, path string, identity fifoIdentity) {
	if fd >= 0 {
		_ = unix.Close(fd)
	}
	var current unix.Stat_t
	if unix.Lstat(path, &current) == nil &&
		uint64(current.Dev) == identity.device &&
		current.Ino == identity.inode &&
		current.Uid == identity.uid &&
		current.Gid == identity.gid &&
		uint32(current.Mode) == identity.mode {
		_ = os.Remove(path)
	}
}

func readBoundedInput(reader io.Reader, maximum int) ([]byte, error) {
	if reader == nil {
		return nil, nil
	}
	payload, err := io.ReadAll(io.LimitReader(reader, int64(maximum)+1))
	if err != nil || len(payload) > maximum {
		zero(payload)
		return nil, errors.New("broker-dialer: input invalid")
	}
	return payload, nil
}

func readFIFOExact(ctx context.Context, fd int, output []byte) error {
	offset := 0
	for offset < len(output) {
		count, err := unix.Read(fd, output[offset:])
		if count > 0 {
			offset += count
			continue
		}
		if err != nil && !errors.Is(err, unix.EAGAIN) &&
			!errors.Is(err, unix.EINTR) {
			return err
		}
		if err := waitFIFO(ctx, fd, unix.POLLIN); err != nil {
			return err
		}
	}
	return nil
}

func writeFIFOAll(ctx context.Context, fd int, input []byte) error {
	offset := 0
	for offset < len(input) {
		count, err := unix.Write(fd, input[offset:])
		if count > 0 {
			offset += count
			continue
		}
		if err != nil && !errors.Is(err, unix.EAGAIN) &&
			!errors.Is(err, unix.EINTR) {
			return err
		}
		if err := waitFIFO(ctx, fd, unix.POLLOUT); err != nil {
			return err
		}
	}
	return nil
}

func waitFIFO(ctx context.Context, fd int, events int16) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		ready, err := unix.Poll(
			[]unix.PollFd{{Fd: int32(fd), Events: events}},
			int(brokerControlPollInterval/time.Millisecond),
		)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		if ready > 0 {
			return nil
		}
	}
}

func writeOutput(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		count, err := writer.Write(data)
		if err != nil || count <= 0 {
			return errors.New("broker-dialer: output write failed")
		}
		data = data[count:]
	}
	return nil
}

func subtleEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}

func allZero(value []byte) bool {
	var aggregate byte
	for _, current := range value {
		aggregate |= current
	}
	return aggregate == 0
}
