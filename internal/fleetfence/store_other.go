//go:build !darwin && !linux

package fleetfence

import (
	"context"
	"time"
)

const (
	lockShared    = 1
	lockExclusive = 2
)

func openPrivateRoot(string) (int, fileIdentity, error) {
	return -1, fileIdentity{}, ErrInvalidState
}

func (s *Store) operationFDs(bool) (int, int, error) {
	return -1, -1, ErrInvalidState
}

func (s *Store) inspectBootstrapState() (bool, error) {
	return false, ErrInvalidState
}

func openStableLock(int, bool) (int, fileIdentity, error) {
	return -1, fileIdentity{}, ErrInvalidState
}

func fstatRegular(int, uint32) (fileIdentity, error) {
	return fileIdentity{}, ErrInvalidState
}

func fstatDirectory(int) (fileIdentity, error) {
	return fileIdentity{}, ErrInvalidState
}

func readHeader(int) (Header, error) {
	return Header{}, ErrInvalidState
}

func readOptionalHeader(int) (Header, bool, error) {
	return Header{}, false, ErrInvalidState
}

func readHolder(int, string) (HolderRecord, error) {
	return HolderRecord{}, ErrInvalidState
}

func writeCanonicalAtomic(*Store, int, string, any) error {
	return ErrInvalidState
}

func createCanonicalExclusive(*Store, int, string, any) error {
	return ErrInvalidState
}

func readAllHolders(int) ([]HolderRecord, error) {
	return nil, ErrInvalidState
}

func retireAllHolders(int) error {
	return ErrInvalidState
}

func unlinkAndSync(int, string) error {
	return ErrInvalidState
}

func flockContext(context.Context, int, int, time.Duration) error {
	return ErrInvalidState
}

func unlockFD(int) error {
	return ErrInvalidState
}

func closeFD(int) error {
	return nil
}

func duplicateCloseOnExec(int) (int, error) {
	return -1, ErrInvalidState
}

func unlockAndClose(int) error {
	return ErrInvalidState
}
