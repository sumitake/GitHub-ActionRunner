package upgrade

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
)

const (
	journalLockName        = "runner-upgrade.lock"
	journalFileName        = "runner-upgrade.json"
	maxJournalDocumentSize = 16 << 20
)

var (
	ErrJournalStore  = errors.New("upgrade: journal store unavailable")
	ErrJournalAbsent = errors.New(
		"upgrade: journal absent",
	)
	ErrJournalConflict = errors.New(
		"upgrade: journal compare-and-swap conflict",
	)
	ErrJournalDeadlineRequired = errors.New(
		"upgrade: journal lease deadline required",
	)
	ErrJournalLeaseUnavailable = errors.New(
		"upgrade: journal lease unavailable",
	)
	ErrJournalIntegrity = errors.New(
		"upgrade: journal store integrity failure",
	)
	ErrJournalStoreClosed = errors.New(
		"upgrade: journal store closed",
	)
)

// StoreConfig binds the journal to one caller-provisioned private root.
type StoreConfig struct {
	Root             string
	Bootstrap        bool
	MaxDocumentBytes int
}

// JournalStore serializes every journal read-modify-write operation.
type JournalStore interface {
	Acquire(context.Context) (JournalLease, error)
	Close() error
}

// JournalLease owns the exclusive journal lock until Close.
type JournalLease interface {
	Read() ([]byte, error)
	Create([]byte) error
	Replace(expected, replacement []byte) error
	Close() error
}

type journalFileIdentity struct {
	device uint64
	inode  uint64
}

// FileJournalStore is a descriptor-rooted local journal store.
type FileJournalStore struct {
	mu sync.Mutex

	root             string
	rootFD           int
	rootIdentity     journalFileIdentity
	lockIdentity     journalFileIdentity
	maxDocumentBytes int
	closed           bool
	tempSequence     atomic.Uint64
	fault            func(string) error
}

type fileJournalLease struct {
	mu sync.Mutex

	store        *FileJournalStore
	rootFD       int
	lockFD       int
	rootIdentity journalFileIdentity
	lockIdentity journalFileIdentity
	closed       bool
}

// OpenFileJournalStore never creates Root. Bootstrap permits creation of only
// the stable private lock object inside an already validated Root.
func OpenFileJournalStore(
	config StoreConfig,
) (*FileJournalStore, error) {
	if config.Root == "" ||
		!filepath.IsAbs(config.Root) ||
		filepath.Clean(config.Root) != config.Root ||
		config.MaxDocumentBytes <= 0 ||
		config.MaxDocumentBytes > maxJournalDocumentSize {
		return nil, ErrJournalStore
	}
	return openFileJournalStore(config)
}

func validJournalDocument(document []byte, maximum int) bool {
	return len(document) > 0 && len(document) <= maximum
}
