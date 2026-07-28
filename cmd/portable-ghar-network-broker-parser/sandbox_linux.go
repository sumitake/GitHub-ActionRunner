//go:build linux

package main

import (
	"errors"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	seccompDataArchOffset = 4
	seccompDataArg0Offset = 16
	linuxAuditArchAMD64   = 0xc000003e
	linuxAuditArchARM64   = 0xc00000b7
	socketTypeMask        = 0xf
)

func installParserSandbox() (sandboxProof, error) {
	architecture, err := parserAuditArchitecture()
	if err != nil {
		return sandboxProof{}, err
	}
	if err := unix.Prctl(
		unix.PR_SET_NO_NEW_PRIVS,
		1,
		0,
		0,
		0,
	); err != nil {
		return sandboxProof{}, errors.New("broker-parser: no-new-privileges failed")
	}
	filter := parserSeccompFilter(architecture)
	program := unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}
	_, _, syscallErr := unix.Syscall(
		unix.SYS_SECCOMP,
		uintptr(unix.SECCOMP_SET_MODE_FILTER),
		uintptr(unix.SECCOMP_FILTER_FLAG_TSYNC),
		uintptr(unsafe.Pointer(&program)),
	)
	if syscallErr != 0 {
		return sandboxProof{}, errors.New("broker-parser: seccomp TSYNC failed")
	}
	if !routableSocketDenied() {
		return sandboxProof{}, errors.New("broker-parser: installing-thread probe failed")
	}
	taskCount, err := linuxTaskCount()
	if err != nil || taskCount == 0 {
		return sandboxProof{}, errors.New("broker-parser: task inventory failed")
	}
	workerCount := taskCount
	if workerCount < 2 {
		workerCount = 2
	}
	if workerCount > 32 {
		workerCount = 32
	}
	var failed atomic.Bool
	var wait sync.WaitGroup
	wait.Add(workerCount)
	for index := 0; index < workerCount; index++ {
		go func() {
			defer wait.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			if !routableSocketDenied() {
				failed.Store(true)
			}
		}()
	}
	wait.Wait()
	if failed.Load() {
		return sandboxProof{}, errors.New("broker-parser: fresh-thread probe failed")
	}
	finalCount, err := linuxTaskCount()
	if err != nil || finalCount == 0 {
		return sandboxProof{}, errors.New("broker-parser: final task inventory failed")
	}
	return sandboxProof{
		taskCount:     uint32(finalCount),
		tasksVerified: uint32(finalCount),
	}, nil
}

func parserAuditArchitecture() (uint32, error) {
	switch runtime.GOARCH {
	case "amd64":
		return linuxAuditArchAMD64, nil
	case "arm64":
		return linuxAuditArchARM64, nil
	default:
		return 0, errors.New("broker-parser: architecture unsupported")
	}
}

func parserSeccompFilter(architecture uint32) []unix.SockFilter {
	statement := func(code uint16, value uint32) unix.SockFilter {
		return unix.SockFilter{Code: code, K: value}
	}
	jump := func(
		code uint16,
		value uint32,
		onTrue,
		onFalse uint8,
	) unix.SockFilter {
		return unix.SockFilter{
			Code: code,
			Jt:   onTrue,
			Jf:   onFalse,
			K:    value,
		}
	}
	loadWord := uint16(unix.BPF_LD | unix.BPF_W | unix.BPF_ABS)
	equal := uint16(unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K)
	and := uint16(unix.BPF_ALU | unix.BPF_AND | unix.BPF_K)
	ret := uint16(unix.BPF_RET | unix.BPF_K)
	deny := uint32(unix.SECCOMP_RET_ERRNO) | uint32(unix.EPERM)

	filter := []unix.SockFilter{
		statement(loadWord, seccompDataArchOffset),
		jump(equal, architecture, 1, 0),
		statement(ret, uint32(unix.SECCOMP_RET_KILL_PROCESS)),
		statement(loadWord, 0),
	}
	for _, syscallNumber := range []uint32{
		uint32(unix.SYS_SECCOMP),
		uint32(unix.SYS_BPF),
		uint32(unix.SYS_UNSHARE),
		uint32(unix.SYS_SETNS),
		uint32(unix.SYS_CLONE3),
		uint32(unix.SYS_MOUNT),
		uint32(unix.SYS_UMOUNT2),
		uint32(unix.SYS_PIVOT_ROOT),
	} {
		filter = append(
			filter,
			jump(equal, syscallNumber, 0, 1),
			statement(ret, deny),
		)
	}
	filter = append(
		filter,
		jump(equal, uint32(unix.SYS_PRCTL), 0, 3),
		statement(loadWord, seccompDataArg0Offset),
		jump(equal, uint32(unix.PR_SET_SECCOMP), 0, 1),
		statement(ret, deny),
		statement(loadWord, 0),
	)
	filter = appendSocketFilterBlock(
		filter,
		jump,
		statement,
		uint32(unix.SYS_SOCKET),
		loadWord,
		equal,
		and,
		ret,
		deny,
	)
	filter = appendSocketFilterBlock(
		filter,
		jump,
		statement,
		uint32(unix.SYS_SOCKETPAIR),
		loadWord,
		equal,
		and,
		ret,
		deny,
	)
	namespaceFlags := uint32(
		unix.CLONE_NEWCGROUP |
			unix.CLONE_NEWIPC |
			unix.CLONE_NEWNET |
			unix.CLONE_NEWNS |
			unix.CLONE_NEWPID |
			unix.CLONE_NEWUSER |
			unix.CLONE_NEWUTS,
	)
	filter = append(
		filter,
		jump(equal, uint32(unix.SYS_CLONE), 0, 5),
		statement(loadWord, seccompDataArg0Offset),
		statement(and, namespaceFlags),
		jump(equal, 0, 1, 0),
		statement(ret, deny),
		statement(ret, uint32(unix.SECCOMP_RET_ALLOW)),
		statement(ret, uint32(unix.SECCOMP_RET_ALLOW)),
	)
	return filter
}

func appendSocketFilterBlock(
	filter []unix.SockFilter,
	jump func(uint16, uint32, uint8, uint8) unix.SockFilter,
	statement func(uint16, uint32) unix.SockFilter,
	syscallNumber uint32,
	loadWord,
	equal,
	and,
	ret uint16,
	deny uint32,
) []unix.SockFilter {
	return append(
		filter,
		jump(equal, syscallNumber, 0, 9),
		statement(loadWord, seccompDataArg0Offset),
		jump(equal, uint32(unix.AF_INET), 5, 0),
		jump(equal, uint32(unix.AF_INET6), 4, 0),
		jump(equal, uint32(unix.AF_PACKET), 3, 0),
		statement(loadWord, seccompDataArg0Offset+8),
		statement(and, socketTypeMask),
		jump(equal, uint32(unix.SOCK_RAW), 0, 1),
		statement(ret, deny),
		statement(ret, uint32(unix.SECCOMP_RET_ALLOW)),
	)
}

func routableSocketDenied() bool {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		descriptor, err := unix.Socket(
			family,
			unix.SOCK_STREAM|unix.SOCK_CLOEXEC,
			0,
		)
		if descriptor >= 0 {
			_ = unix.Close(descriptor)
			return false
		}
		if !errors.Is(err, unix.EPERM) {
			return false
		}
	}
	return true
}

func linuxTaskCount() (int, error) {
	entries, err := os.ReadDir("/proc/self/task")
	if err != nil || len(entries) == 0 {
		return 0, errors.New("broker-parser: task inventory unavailable")
	}
	for _, entry := range entries {
		value, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil || value == 0 {
			return 0, errors.New("broker-parser: task inventory invalid")
		}
	}
	return len(entries), nil
}
