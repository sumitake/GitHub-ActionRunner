//go:build !darwin && !linux

package productionruntime

import (
	"context"
	"errors"
)

const processRecordName = "controller.process.json"

var ErrProcessRecordStore = errors.New(
	"productionruntime: process record store failed",
)

type PinnedProcessRecordStore struct{}

func OpenProcessRecordStore(
	string,
) (*PinnedProcessRecordStore, error) {
	return nil, ErrProcessRecordStore
}

func (*PinnedProcessRecordStore) Read(
	context.Context,
) (ProcessRecord, string, bool, error) {
	return ProcessRecord{}, "", false, ErrProcessRecordStore
}

func (*PinnedProcessRecordStore) Create(
	context.Context,
	ProcessRecord,
) (string, error) {
	return "", ErrProcessRecordStore
}

func (*PinnedProcessRecordStore) Remove(
	context.Context,
	string,
) error {
	return ErrProcessRecordStore
}

func (*PinnedProcessRecordStore) Close() error {
	return nil
}

var _ ProcessRecordStore = (*PinnedProcessRecordStore)(nil)
