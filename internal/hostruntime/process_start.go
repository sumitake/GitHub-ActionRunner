package hostruntime

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

const processStartIdentityDomain = "portable-ghar-process-start-v1"

var ErrProcessIdentityUnavailable = errors.New(
	"hostruntime: process identity unavailable",
)

type ProcessStartObservation struct {
	BootID             string
	PIDNamespaceInode  uint64
	PID                uint64
	StartTimeTicks     uint64
	ExecutableDigest   string
	ExecutableDevice   uint64
	ExecutableInode    uint64
	ExecutableFileSize uint64
}

type processStartObserver interface {
	ObserveProcessStart(uint64) (ProcessStartObservation, error)
}

func DeriveProcessStartIdentity(
	observation ProcessStartObservation,
) (string, error) {
	if !validCanonicalBootID(observation.BootID) ||
		observation.PIDNamespaceInode == 0 ||
		observation.PID == 0 ||
		observation.StartTimeTicks == 0 ||
		!isLowerHex64(observation.ExecutableDigest) {
		return "", ErrProcessIdentityUnavailable
	}
	executableDigest, err := hex.DecodeString(observation.ExecutableDigest)
	if err != nil || len(executableDigest) != sha256.Size {
		return "", ErrProcessIdentityUnavailable
	}
	preimage := make([]byte, 0, 160)
	preimage = append(preimage, processStartIdentityDomain...)
	preimage = append(preimage, 0)
	var ok bool
	if preimage, ok = appendLP(preimage, observation.BootID); !ok {
		return "", ErrProcessIdentityUnavailable
	}
	preimage = appendU64(preimage, observation.PIDNamespaceInode)
	preimage = appendU64(preimage, observation.PID)
	preimage = appendU64(preimage, observation.StartTimeTicks)
	preimage = append(preimage, executableDigest...)
	sum := sha256.Sum256(preimage)
	return hex.EncodeToString(sum[:]), nil
}

func ObserveStableProcessStartIdentity(
	observer processStartObserver,
	pid uint64,
) (ProcessStartObservation, string, error) {
	if observer == nil || pid == 0 {
		return ProcessStartObservation{}, "", ErrProcessIdentityUnavailable
	}
	first, err := observer.ObserveProcessStart(pid)
	if err != nil {
		return ProcessStartObservation{}, "", ErrProcessIdentityUnavailable
	}
	second, err := observer.ObserveProcessStart(pid)
	if err != nil || !sameProcessStartObservation(first, second) {
		return ProcessStartObservation{}, "", ErrProcessIdentityUnavailable
	}
	identity, err := DeriveProcessStartIdentity(second)
	if err != nil {
		return ProcessStartObservation{}, "", err
	}
	return second, identity, nil
}

func ParseLinuxProcStatStartTime(document []byte) (uint64, error) {
	if len(document) == 0 ||
		bytes.IndexByte(document, 0) >= 0 ||
		document[len(document)-1] == '\n' ||
		document[len(document)-1] == '\r' {
		return 0, ErrProcessIdentityUnavailable
	}
	closing := bytes.LastIndexByte(document, ')')
	if closing <= 1 ||
		closing+2 >= len(document) ||
		document[closing+1] != ' ' {
		return 0, ErrProcessIdentityUnavailable
	}
	pidText := document[:bytes.IndexByte(document, ' ')]
	if len(pidText) == 0 || !allDecimalDigits(pidText) {
		return 0, ErrProcessIdentityUnavailable
	}
	if _, err := strconv.ParseUint(string(pidText), 10, 64); err != nil {
		return 0, ErrProcessIdentityUnavailable
	}
	fields := bytes.Fields(document[closing+2:])
	// The first field after comm is field 3 (state), so field 22 is index 19.
	if len(fields) <= 19 ||
		len(fields[0]) != 1 ||
		!isASCIIProcessState(fields[0][0]) ||
		!allDecimalDigits(fields[19]) {
		return 0, ErrProcessIdentityUnavailable
	}
	start, err := strconv.ParseUint(string(fields[19]), 10, 64)
	if err != nil || start == 0 {
		return 0, ErrProcessIdentityUnavailable
	}
	return start, nil
}

func validCanonicalBootID(value string) bool {
	if len(value) != 36 || value != strings.ToLower(value) {
		return false
	}
	for index, character := range []byte(value) {
		switch index {
		case 8, 13, 18, 23:
			if character != '-' {
				return false
			}
		default:
			if !isLowerHexByte(character) {
				return false
			}
		}
	}
	return true
}

func sameProcessStartObservation(
	left ProcessStartObservation,
	right ProcessStartObservation,
) bool {
	return left == right
}

func allDecimalDigits(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func isASCIIProcessState(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func isLowerHexByte(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f'
}
