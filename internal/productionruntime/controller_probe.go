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

type lifecycleControllerAdmin interface {
	Policy(context.Context) (controller.PolicyStatus, error)
	Disable(context.Context) (controller.PolicyStatus, error)
	Drain(context.Context) error
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
	status, err := probe.Policy(ctx)
	if err != nil ||
		status.Mode != controller.AcquisitionDisabled ||
		status.Capacity != 0 {
		return DisabledControllerObservation{}, ErrControllerProbe
	}
	return DisabledControllerObservation{
		PolicyEpoch:  status.Epoch,
		PolicyDigest: status.Digest,
	}, nil
}

func (probe *SystemDisabledControllerProbe) Policy(
	ctx context.Context,
) (controller.PolicyStatus, error) {
	document, err := probe.run(ctx, "probe")
	if err != nil {
		return controller.PolicyStatus{}, ErrControllerProbe
	}
	var status controller.PolicyStatus
	if !parseControllerPolicy(document, &status) {
		return controller.PolicyStatus{}, ErrControllerProbe
	}
	return status, nil
}

func (probe *SystemDisabledControllerProbe) Disable(
	ctx context.Context,
) (controller.PolicyStatus, error) {
	before, err := probe.Policy(ctx)
	if err != nil {
		return controller.PolicyStatus{}, ErrControllerProbe
	}
	if before.Mode == controller.AcquisitionDisabled {
		return before, nil
	}
	if before.Mode != controller.AcquisitionEnabled &&
		before.Mode != controller.AcquisitionCanaryOnly {
		return controller.PolicyStatus{}, ErrControllerProbe
	}
	document, err := probe.run(
		ctx,
		"acquisition",
		"--set",
		"disabled",
		"--expected",
		string(before.Mode),
		"--json",
	)
	if err != nil {
		return controller.PolicyStatus{}, ErrControllerProbe
	}
	var after controller.PolicyStatus
	if !parseControllerPolicy(document, &after) ||
		after.Mode != controller.AcquisitionDisabled ||
		after.Capacity != 0 ||
		after.Epoch <= before.Epoch {
		return controller.PolicyStatus{}, ErrControllerProbe
	}
	return after, nil
}

func (probe *SystemDisabledControllerProbe) Drain(ctx context.Context) error {
	document, err := probe.run(ctx, "drain", "--policy", "wait")
	if err != nil || !bytes.Equal(document, []byte("{\"status\":\"ok\"}\n")) {
		return ErrControllerProbe
	}
	status, err := probe.Policy(ctx)
	if err != nil ||
		status.Mode != controller.AcquisitionDisabled ||
		status.Capacity != 0 {
		return ErrControllerProbe
	}
	return nil
}

func (probe *SystemDisabledControllerProbe) run(
	ctx context.Context,
	arguments ...string,
) ([]byte, error) {
	if probe == nil ||
		ctx == nil ||
		ctx.Err() != nil ||
		len(arguments) == 0 {
		return nil, ErrControllerProbe
	}
	beforeDigest, err := digestPinnedExecutable(probe.binary)
	if err != nil || beforeDigest != probe.binaryDigest {
		return nil, ErrControllerProbe
	}
	command := exec.Command(probe.binary, arguments...)
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
		return nil, ErrControllerProbe
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
		return nil, ErrControllerProbe
	}
	return append([]byte(nil), stdout.bytes...), nil
}

func parseControllerPolicy(
	document []byte,
	status *controller.PolicyStatus,
) bool {
	if status == nil {
		return false
	}
	if len(document) < 2 ||
		document[len(document)-1] != '\n' ||
		bytes.IndexByte(document[:len(document)-1], '\n') >= 0 ||
		!decodeClosed(document[:len(document)-1], status) {
		return false
	}
	canonical, err := json.Marshal(*status)
	if err != nil ||
		!bytes.Equal(canonical, document[:len(document)-1]) ||
		!validControllerPolicyStatus(*status) {
		return false
	}
	return true
}

func validControllerPolicyStatus(status controller.PolicyStatus) bool {
	if status.Epoch == 0 ||
		!lowerHexDigest(status.Digest) ||
		status.Capacity < 0 {
		return false
	}
	switch status.Mode {
	case controller.AcquisitionDisabled:
		return status.Capacity == 0
	case controller.AcquisitionCanaryOnly:
		return status.Capacity == 1
	case controller.AcquisitionEnabled:
		return status.Capacity > 0
	default:
		return false
	}
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
var _ lifecycleControllerAdmin = (*SystemDisabledControllerProbe)(nil)
