package productionruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"syscall"

	"github.com/sumitake/portable-ghar/internal/controller"
)

const maximumControllerProbeBytes = 4096

var ErrControllerProbe = errors.New(
	"productionruntime: controller probe failed",
)

type DisabledControllerObservation struct {
	PolicyEpoch  uint64
	PolicyDigest string
}

type DisabledControllerProbe interface {
	Observe(context.Context) (DisabledControllerObservation, error)
}

type SystemDisabledControllerProbe struct {
	binary       string
	binaryDigest string
	privatePath  string
}

func NewSystemDisabledControllerProbe(
	binary string,
	privatePath string,
) (*SystemDisabledControllerProbe, error) {
	if !canonicalPath(binary) ||
		!canonicalPath(privatePath) {
		return nil, ErrControllerProbe
	}
	binaryDigest, err := digestPinnedExecutable(binary)
	if err != nil {
		return nil, ErrControllerProbe
	}
	return &SystemDisabledControllerProbe{
		binary:       binary,
		binaryDigest: binaryDigest,
		privatePath:  privatePath,
	}, nil
}

func (probe *SystemDisabledControllerProbe) Observe(
	ctx context.Context,
) (DisabledControllerObservation, error) {
	if probe == nil ||
		ctx == nil ||
		ctx.Err() != nil {
		return DisabledControllerObservation{}, ErrControllerProbe
	}
	beforeDigest, err := digestPinnedExecutable(probe.binary)
	if err != nil || beforeDigest != probe.binaryDigest {
		return DisabledControllerObservation{}, ErrControllerProbe
	}
	command := exec.Command(probe.binary, "probe")
	command.Env = []string{
		"LANG=C",
		"LC_ALL=C",
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"PORTABLE_GHAR_PRIVATE_OVERLAY=" + probe.privatePath,
	}
	command.Stdin = nil
	stdout := &probeBoundedBuffer{maximum: maximumControllerProbeBytes}
	stderr := &probeBoundedBuffer{maximum: maximumControllerProbeBytes}
	command.Stdout = stdout
	command.Stderr = stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil ||
		command.Process == nil ||
		command.Process.Pid <= 0 {
		return DisabledControllerObservation{}, ErrControllerProbe
	}
	waited := make(chan error, 1)
	go func() {
		waited <- command.Wait()
	}()
	var waitErr error
	select {
	case waitErr = <-waited:
	case <-ctx.Done():
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		waitErr = <-waited
	}
	afterDigest, digestErr := digestPinnedExecutable(probe.binary)
	if waitErr != nil ||
		digestErr != nil ||
		afterDigest != probe.binaryDigest ||
		command.ProcessState == nil ||
		!command.ProcessState.Success() ||
		stdout.overflow ||
		stderr.overflow ||
		len(stderr.bytes) != 0 {
		return DisabledControllerObservation{}, ErrControllerProbe
	}
	var status controller.PolicyStatus
	document := stdout.bytes
	if len(document) < 2 ||
		document[len(document)-1] != '\n' ||
		bytes.IndexByte(document[:len(document)-1], '\n') >= 0 ||
		!decodeClosed(document[:len(document)-1], &status) {
		return DisabledControllerObservation{}, ErrControllerProbe
	}
	canonical, err := json.Marshal(status)
	if err != nil ||
		!bytes.Equal(canonical, document[:len(document)-1]) ||
		status.Mode != controller.AcquisitionDisabled ||
		status.Epoch == 0 ||
		!lowerHexDigest(status.Digest) ||
		status.Capacity != 0 {
		return DisabledControllerObservation{}, ErrControllerProbe
	}
	return DisabledControllerObservation{
		PolicyEpoch:  status.Epoch,
		PolicyDigest: status.Digest,
	}, nil
}

type probeBoundedBuffer struct {
	bytes    []byte
	maximum  int
	overflow bool
}

func (buffer *probeBoundedBuffer) Write(document []byte) (int, error) {
	count := len(document)
	remaining := buffer.maximum - len(buffer.bytes)
	if remaining <= 0 {
		buffer.overflow = buffer.overflow || count > 0
		return count, nil
	}
	if count > remaining {
		buffer.bytes = append(buffer.bytes, document[:remaining]...)
		buffer.overflow = true
		return count, nil
	}
	buffer.bytes = append(buffer.bytes, document...)
	return count, nil
}

var _ DisabledControllerProbe = (*SystemDisabledControllerProbe)(nil)
