//go:build !darwin && !linux

package upgrade

import "context"

func openFileJournalStore(
	StoreConfig,
) (*FileJournalStore, error) {
	return nil, ErrJournalStore
}

func (store *FileJournalStore) Close() error {
	return ErrJournalStore
}

func (store *FileJournalStore) Acquire(
	context.Context,
) (JournalLease, error) {
	return nil, ErrJournalStore
}

func (lease *fileJournalLease) Read() ([]byte, error) {
	return nil, ErrJournalStore
}

func (lease *fileJournalLease) Create([]byte) error {
	return ErrJournalStore
}

func (lease *fileJournalLease) Replace([]byte, []byte) error {
	return ErrJournalStore
}

func (lease *fileJournalLease) Close() error {
	return ErrJournalStore
}
