//go:build linux

package productionruntime

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"golang.org/x/sys/unix"
)

type linuxProcessKernel struct {
	mu       sync.Mutex
	children map[uint64]*linuxControllerChild
}

type linuxControllerChild struct {
	pgid uint64
	done chan struct{}
}

func NewSystemProcessKernel() (ProcessKernel, error) {
	return &linuxProcessKernel{
		children: make(map[uint64]*linuxControllerChild),
	}, nil
}

func (kernel *linuxProcessKernel) LaunchDisabled(
	ctx context.Context,
	launch ControllerLaunch,
) (hostruntime.ProcessStartObservation, uint64, error) {
	if kernel == nil || ctx == nil || ctx.Err() != nil ||
		!validControllerLaunch(launch) {
		return hostruntime.ProcessStartObservation{}, 0,
			ErrProcessStartFailed
	}
	stdout, err := openControllerLog(launch.StdoutLog)
	if err != nil {
		return hostruntime.ProcessStartObservation{}, 0,
			ErrProcessStartFailed
	}
	defer stdout.Close()
	stderr, err := openControllerLog(launch.StderrLog)
	if err != nil {
		return hostruntime.ProcessStartObservation{}, 0,
			ErrProcessStartFailed
	}
	defer stderr.Close()

	command := exec.CommandContext(
		context.WithoutCancel(ctx),
		launch.ControllerBinary,
		"run",
		"--config",
		launch.PrivateOverlay,
		"--database",
		launch.DatabasePath,
	)
	command.Env = []string{
		"LANG=C",
		"LC_ALL=C",
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"PORTABLE_GHAR_PRIVATE_OVERLAY=" + launch.PrivateOverlay,
	}
	command.Stdin = nil
	command.Stdout = stdout
	command.Stderr = stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil || command.Process == nil ||
		command.Process.Pid <= 0 {
		return hostruntime.ProcessStartObservation{}, 0,
			ErrProcessStartFailed
	}
	pid := uint64(command.Process.Pid)
	pgid, err := unix.Getpgid(command.Process.Pid)
	if err != nil || pgid <= 0 || uint64(pgid) != pid {
		_ = command.Process.Kill()
		_ = command.Wait()
		return hostruntime.ProcessStartObservation{}, 0,
			ErrProcessStartFailed
	}
	child := &linuxControllerChild{
		pgid: pid,
		done: make(chan struct{}),
	}
	kernel.mu.Lock()
	if kernel.children == nil {
		kernel.children = make(map[uint64]*linuxControllerChild)
	}
	if _, exists := kernel.children[pid]; exists {
		kernel.mu.Unlock()
		_ = unix.Kill(-pgid, unix.SIGKILL)
		_ = command.Wait()
		return hostruntime.ProcessStartObservation{}, 0,
			ErrProcessStartFailed
	}
	kernel.children[pid] = child
	kernel.mu.Unlock()
	go func() {
		_ = command.Wait()
		close(child.done)
	}()

	observation, _, err :=
		hostruntime.ObserveLinuxProcessStartIdentity(pid)
	if err != nil ||
		observation.ExecutableDigest != launch.ExecutableDigest {
		_ = kernel.CleanupStarted(
			context.WithoutCancel(ctx),
			pid,
			pid,
		)
		return hostruntime.ProcessStartObservation{}, 0,
			ErrProcessStartFailed
	}
	return observation, pid, nil
}

func (kernel *linuxProcessKernel) Observe(
	ctx context.Context,
	pid uint64,
) (ProcessObservation, error) {
	if kernel == nil || ctx == nil || ctx.Err() != nil || pid == 0 {
		return ProcessObservation{}, ErrProcessObservationUnavailable
	}
	observation, _, err :=
		hostruntime.ObserveLinuxProcessStartIdentity(pid)
	if err == nil {
		return ProcessObservation{
			Present: true,
			Start:   observation,
		}, nil
	}
	if errors.Is(err, hostruntime.ErrProcessIdentityUnavailable) {
		return ProcessObservation{}, nil
	}
	return ProcessObservation{}, ErrProcessObservationUnavailable
}

func (kernel *linuxProcessKernel) SignalGroup(
	ctx context.Context,
	pgid uint64,
	signal ProcessSignal,
) error {
	if kernel == nil || ctx == nil || ctx.Err() != nil || pgid == 0 ||
		pgid > uint64(^uint(0)>>1) {
		return ErrProcessStopFailed
	}
	var native unix.Signal
	switch signal {
	case ProcessSignalTerminate:
		native = unix.SIGTERM
	case ProcessSignalKill:
		native = unix.SIGKILL
	default:
		return ErrProcessStopFailed
	}
	if err := unix.Kill(-int(pgid), native); err != nil {
		return ErrProcessStopFailed
	}
	return nil
}

func (kernel *linuxProcessKernel) GroupAbsent(
	ctx context.Context,
	pgid uint64,
) (bool, error) {
	if kernel == nil || ctx == nil || ctx.Err() != nil || pgid == 0 ||
		pgid > uint64(^uint(0)>>1) {
		return false, ErrProcessObservationUnavailable
	}
	err := unix.Kill(-int(pgid), 0)
	switch {
	case err == nil, errors.Is(err, unix.EPERM):
		return false, nil
	case errors.Is(err, unix.ESRCH):
		kernel.mu.Lock()
		for pid, child := range kernel.children {
			if child.pgid == pgid && childReaped(child) {
				delete(kernel.children, pid)
			}
		}
		kernel.mu.Unlock()
		return true, nil
	default:
		return false, ErrProcessObservationUnavailable
	}
}

func (kernel *linuxProcessKernel) CleanupStarted(
	ctx context.Context,
	pid uint64,
	pgid uint64,
) error {
	if kernel == nil || ctx == nil || pid == 0 || pgid != pid ||
		pid > uint64(^uint(0)>>1) {
		return ErrProcessStartFailed
	}
	kernel.mu.Lock()
	child := kernel.children[pid]
	if child == nil || child.pgid != pgid {
		kernel.mu.Unlock()
		return ErrProcessStartFailed
	}
	reaped := childReaped(child)
	if !reaped {
		if err := unix.Kill(-int(pgid), unix.SIGKILL); err != nil &&
			!errors.Is(err, unix.ESRCH) {
			kernel.mu.Unlock()
			return ErrProcessStartFailed
		}
	}
	done := child.done
	kernel.mu.Unlock()

	if !reaped {
		select {
		case <-ctx.Done():
			return ErrProcessStartFailed
		case <-done:
		}
	}
	absent, err := kernel.GroupAbsent(ctx, pgid)
	if err != nil || !absent {
		return ErrProcessStartFailed
	}
	return nil
}

func childReaped(child *linuxControllerChild) bool {
	select {
	case <-child.done:
		return true
	default:
		return false
	}
}

func openControllerLog(path string) (*os.File, error) {
	fd, err := unix.Open(
		path,
		unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT|
			unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0o600,
	)
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil ||
		uint32(stat.Mode)&unix.S_IFMT != unix.S_IFREG ||
		uint32(stat.Mode)&0o777 != 0o600 ||
		stat.Uid != uint32(os.Geteuid()) ||
		stat.Nlink != 1 ||
		stat.Ino == 0 {
		_ = unix.Close(fd)
		return nil, ErrProcessStartFailed
	}
	file := os.NewFile(
		uintptr(fd),
		"portable-ghar-controller-"+strconv.Itoa(fd),
	)
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrProcessStartFailed
	}
	return file, nil
}

var _ ProcessKernel = (*linuxProcessKernel)(nil)
