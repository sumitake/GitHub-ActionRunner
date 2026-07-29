//go:build linux

package fleetfence

import (
	"context"
	"io"
	"os"
	"strconv"
	"strings"
)

const (
	linuxBootIDPath      = "/proc/sys/kernel/random/boot_id"
	maxLinuxIdentityRead = 64 * 1024
)

type systemIdentitySource struct{}

func NewSystemIdentitySource() IdentitySource {
	return systemIdentitySource{}
}

func (systemIdentitySource) Current(
	ctx context.Context,
	pid int,
) (ProcessIdentity, error) {
	if err := ctx.Err(); err != nil {
		return ProcessIdentity{}, err
	}
	if pid <= 0 {
		return ProcessIdentity{}, ErrInvalidState
	}
	bootDocument, err := readLinuxIdentityFile(linuxBootIDPath)
	if err != nil {
		return ProcessIdentity{}, err
	}
	bootID, err := parseLinuxBootID(bootDocument)
	if err != nil {
		return ProcessIdentity{}, err
	}
	statDocument, err := readLinuxIdentityFile(
		"/proc/" + strconv.Itoa(pid) + "/stat",
	)
	if err != nil {
		return ProcessIdentity{}, err
	}
	startID, err := parseLinuxProcessStart(statDocument, pid)
	if err != nil {
		return ProcessIdentity{}, err
	}
	if err := ctx.Err(); err != nil {
		return ProcessIdentity{}, err
	}
	return ProcessIdentity{
		BootID:         bootID,
		ProcessStartID: "linux-process-" + startID,
	}, nil
}

func readLinuxIdentityFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrInvalidState
	}
	defer file.Close()
	document, err := io.ReadAll(io.LimitReader(file, maxLinuxIdentityRead+1))
	if err != nil || len(document) == 0 ||
		len(document) > maxLinuxIdentityRead {
		return nil, ErrInvalidState
	}
	return document, nil
}

func parseLinuxBootID(document []byte) (string, error) {
	if len(document) != 37 || document[36] != '\n' {
		return "", ErrInvalidState
	}
	value := string(document[:36])
	for index, character := range value {
		switch index {
		case 8, 13, 18, 23:
			if character != '-' {
				return "", ErrInvalidState
			}
		default:
			if (character < '0' || character > '9') &&
				(character < 'a' || character > 'f') {
				return "", ErrInvalidState
			}
		}
	}
	return value, nil
}

func parseLinuxProcessStart(document []byte, pid int) (string, error) {
	if len(document) == 0 || document[len(document)-1] != '\n' {
		return "", ErrInvalidState
	}
	line := string(document[:len(document)-1])
	open := strings.IndexByte(line, '(')
	close := strings.LastIndexByte(line, ')')
	if open <= 0 || close <= open || close+2 > len(line) ||
		line[close+1] != ' ' {
		return "", ErrInvalidState
	}
	parsedPID, err := strconv.Atoi(strings.TrimSpace(line[:open]))
	if err != nil || parsedPID != pid {
		return "", ErrInvalidState
	}
	fields := strings.Fields(line[close+2:])
	if len(fields) < 20 {
		return "", ErrInvalidState
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 ||
		strconv.FormatUint(start, 10) != fields[19] {
		return "", ErrInvalidState
	}
	return fields[19], nil
}
