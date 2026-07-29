// Package fleetfence owns the host-local, generation-bound authority that
// prevents Portable-GHAR and the legacy fleet from acquiring work together.
package fleetfence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/sumitake/portable-ghar/internal/controller"
)

const (
	lockName        = "fleet.lock"
	headerName      = "fleet.json"
	holderDirName   = "holders"
	stateVersion    = uint32(1)
	maxStateBytes   = 64 * 1024
	holderDomain    = "portable-ghar-fleet-holder-v1"
	operationDomain = "portable-ghar-fleet-handoff-v1"
)

var (
	ErrInvalidState      = errors.New("fleetfence: invalid state")
	ErrAuthorityConflict = errors.New("fleetfence: authority conflict")
	ErrDeadlineRequired  = errors.New("fleetfence: deadline required")
	ErrStoreClosed       = errors.New("fleetfence: store closed")
)

type Fleet string

const (
	FleetNone     Fleet = "none"
	FleetPortable Fleet = "portable"
	FleetLegacy   Fleet = "legacy"
)

type Header struct {
	Version      uint32    `json:"version"`
	Generation   uint64    `json:"generation"`
	ActiveFleet  Fleet     `json:"active_fleet"`
	BootID       string    `json:"boot_id"`
	RootDevice   uint64    `json:"root_device"`
	RootInode    uint64    `json:"root_inode"`
	LockDevice   uint64    `json:"lock_device"`
	LockInode    uint64    `json:"lock_inode"`
	HolderDevice uint64    `json:"holder_device"`
	HolderInode  uint64    `json:"holder_inode"`
	UpdatedAt    time.Time `json:"updated_at"`
	OperationID  string    `json:"operation_id"`
}

type HolderIdentity struct {
	Generation     uint64 `json:"generation"`
	Fleet          Fleet  `json:"fleet"`
	OwnerID        string `json:"owner_id"`
	PID            int    `json:"pid"`
	BootID         string `json:"boot_id"`
	ProcessStartID string `json:"process_start_id"`
}

type HolderRecord struct {
	Version   uint32         `json:"version"`
	Identity  HolderIdentity `json:"identity"`
	RenewedAt time.Time      `json:"renewed_at"`
}

type Snapshot struct {
	Header  Header
	Holders []HolderIdentity
}

type ProcessIdentity struct {
	BootID         string
	ProcessStartID string
}

type IdentitySource interface {
	Current(context.Context, int) (ProcessIdentity, error)
}

type StoreConfig struct {
	Root             string
	Identity         IdentitySource
	Now              func() time.Time
	LockPollInterval time.Duration
}

type AcquireRequest struct {
	Fleet      Fleet
	Generation uint64
	OwnerID    string
	PID        int
}

type HandoffRequest struct {
	From               Fleet
	To                 Fleet
	ExpectedGeneration uint64
	OperationID        string
}

type Guard interface {
	controller.AcquisitionGuard
	Renew(context.Context) error
	Failure() <-chan error
	Header() Header
}

type fileIdentity struct {
	device uint64
	inode  uint64
}

type Store struct {
	mu sync.RWMutex

	root             string
	rootFD           int
	holderFD         int
	rootIdentity     fileIdentity
	identity         IdentitySource
	now              func() time.Time
	lockPollInterval time.Duration
	closed           bool
	tempSequence     atomic.Uint64
}

type heldGuard struct {
	store      *Store
	lockFD     int
	recordName string
	identity   HolderIdentity
	header     Header
	failure    chan error
	failOnce   sync.Once
	closeOnce  sync.Once
	recordMu   sync.Mutex
	renewedAt  time.Time
	closeErr   error
}

var _ Guard = (*heldGuard)(nil)

func OpenStore(config StoreConfig) (*Store, error) {
	if config.Root == "" ||
		!filepath.IsAbs(config.Root) ||
		filepath.Clean(config.Root) != config.Root ||
		config.Identity == nil ||
		config.Now == nil ||
		config.LockPollInterval <= 0 {
		return nil, ErrInvalidState
	}
	rootFD, rootIdentity, err := openPrivateRoot(config.Root)
	if err != nil {
		return nil, err
	}
	return &Store{
		root:             config.Root,
		rootFD:           rootFD,
		holderFD:         -1,
		rootIdentity:     rootIdentity,
		identity:         config.Identity,
		now:              config.Now,
		lockPollInterval: config.LockPollInterval,
	}, nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var result error
	if s.holderFD >= 0 {
		result = errors.Join(result, closeFD(s.holderFD))
		s.holderFD = -1
	}
	result = errors.Join(result, closeFD(s.rootFD))
	s.rootFD = -1
	return result
}

func (s *Store) Acquire(
	ctx context.Context,
	request AcquireRequest,
) (Guard, error) {
	if err := requireDeadline(ctx); err != nil {
		return nil, err
	}
	if !acquirableFleet(request.Fleet) ||
		request.Generation == 0 ||
		!validScalar(request.OwnerID) ||
		request.PID <= 0 {
		return nil, ErrInvalidState
	}
	rootFD, holderFD, err := s.operationFDs(false)
	if err != nil {
		return nil, err
	}
	lockFD, lockIdentity, err := openStableLock(rootFD, false)
	if err != nil {
		return nil, err
	}
	locked := false
	defer func() {
		if !locked {
			_ = closeFD(lockFD)
		}
	}()
	if err := flockContext(ctx, lockFD, lockShared, s.lockPollInterval); err != nil {
		return nil, err
	}
	locked = true
	header, err := readHeader(rootFD)
	if err != nil {
		_ = unlockAndClose(lockFD)
		return nil, err
	}
	holderIdentity, err := fstatDirectory(holderFD)
	if err != nil ||
		validateHeader(header) != nil ||
		!s.identitiesMatch(header, lockIdentity, holderIdentity) ||
		header.Generation != request.Generation ||
		header.ActiveFleet != request.Fleet {
		_ = unlockAndClose(lockFD)
		return nil, ErrAuthorityConflict
	}
	process, err := s.identity.Current(ctx, request.PID)
	if err != nil ||
		!validScalar(process.BootID) ||
		!validScalar(process.ProcessStartID) {
		_ = unlockAndClose(lockFD)
		return nil, ErrAuthorityConflict
	}
	identity := HolderIdentity{
		Generation:     request.Generation,
		Fleet:          request.Fleet,
		OwnerID:        request.OwnerID,
		PID:            request.PID,
		BootID:         process.BootID,
		ProcessStartID: process.ProcessStartID,
	}
	record := HolderRecord{
		Version:   stateVersion,
		Identity:  identity,
		RenewedAt: s.now().UTC(),
	}
	if err := validateHolder(record); err != nil {
		_ = unlockAndClose(lockFD)
		return nil, err
	}
	name := holderRecordName(identity)
	if err := createCanonicalExclusive(s, holderFD, name, record); err != nil {
		_ = unlockAndClose(lockFD)
		return nil, err
	}
	return &heldGuard{
		store:      s,
		lockFD:     lockFD,
		recordName: name,
		identity:   identity,
		header:     header,
		failure:    make(chan error, 1),
		renewedAt:  record.RenewedAt,
	}, nil
}

func (s *Store) Handoff(
	ctx context.Context,
	request HandoffRequest,
) (Header, error) {
	if err := requireDeadline(ctx); err != nil {
		return Header{}, err
	}
	if !validFleet(request.From) ||
		!validFleet(request.To) ||
		request.From == request.To ||
		request.OperationID != HandoffOperationID(
			request.ExpectedGeneration,
			request.From,
			request.To,
		) ||
		request.ExpectedGeneration == math.MaxUint64 {
		return Header{}, ErrInvalidState
	}
	bootstrap := request.From == FleetNone && request.ExpectedGeneration == 0
	rootFD, holderFD, err := s.operationFDs(bootstrap)
	if err != nil {
		return Header{}, err
	}
	lockFD, lockIdentity, err := openStableLock(rootFD, bootstrap)
	if err != nil {
		return Header{}, err
	}
	defer closeFD(lockFD)
	if err := flockContext(ctx, lockFD, lockExclusive, s.lockPollInterval); err != nil {
		return Header{}, err
	}
	defer unlockFD(lockFD)
	holderIdentity, err := fstatDirectory(holderFD)
	if err != nil {
		return Header{}, err
	}
	header, exists, err := readOptionalHeader(rootFD)
	if err != nil {
		return Header{}, err
	}
	if !exists {
		if !bootstrap {
			return Header{}, ErrInvalidState
		}
		process, err := s.identity.Current(ctx, os.Getpid())
		if err != nil || !validScalar(process.BootID) {
			return Header{}, ErrInvalidState
		}
		header = Header{
			Version:      stateVersion,
			Generation:   1,
			ActiveFleet:  request.To,
			BootID:       process.BootID,
			RootDevice:   s.rootIdentity.device,
			RootInode:    s.rootIdentity.inode,
			LockDevice:   lockIdentity.device,
			LockInode:    lockIdentity.inode,
			HolderDevice: holderIdentity.device,
			HolderInode:  holderIdentity.inode,
			UpdatedAt:    s.now().UTC(),
			OperationID:  request.OperationID,
		}
		if err := writeCanonicalAtomic(s, rootFD, headerName, header); err != nil {
			return Header{}, err
		}
	} else {
		if err := validateHeader(header); err != nil ||
			!s.identitiesMatch(header, lockIdentity, holderIdentity) {
			return Header{}, ErrInvalidState
		}
		nextGeneration := request.ExpectedGeneration + 1
		if header.Generation == nextGeneration &&
			header.ActiveFleet == request.To &&
			header.OperationID == request.OperationID {
			if err := retireAllHolders(holderFD); err != nil {
				return Header{}, err
			}
			return s.readBackHeader(rootFD, lockFD, holderFD, header)
		}
		if header.Generation != request.ExpectedGeneration ||
			header.ActiveFleet != request.From {
			return Header{}, ErrAuthorityConflict
		}
		process, err := s.identity.Current(ctx, os.Getpid())
		if err != nil || !validScalar(process.BootID) {
			return Header{}, ErrInvalidState
		}
		header.Generation = nextGeneration
		header.ActiveFleet = request.To
		header.BootID = process.BootID
		header.UpdatedAt = s.now().UTC()
		header.OperationID = request.OperationID
		if err := writeCanonicalAtomic(s, rootFD, headerName, header); err != nil {
			return Header{}, err
		}
	}
	if err := retireAllHolders(holderFD); err != nil {
		return Header{}, err
	}
	return s.readBackHeader(rootFD, lockFD, holderFD, header)
}

func (s *Store) Inspect(ctx context.Context) (Snapshot, error) {
	if err := requireDeadline(ctx); err != nil {
		return Snapshot{}, err
	}
	rootFD, holderFD, err := s.operationFDs(false)
	if err != nil {
		return Snapshot{}, err
	}
	lockFD, lockIdentity, err := openStableLock(rootFD, false)
	if err != nil {
		return Snapshot{}, err
	}
	defer closeFD(lockFD)
	if err := flockContext(ctx, lockFD, lockShared, s.lockPollInterval); err != nil {
		return Snapshot{}, err
	}
	defer unlockFD(lockFD)
	header, err := readHeader(rootFD)
	if err != nil {
		return Snapshot{}, err
	}
	holderIdentity, err := fstatDirectory(holderFD)
	if err != nil ||
		validateHeader(header) != nil ||
		!s.identitiesMatch(header, lockIdentity, holderIdentity) {
		return Snapshot{}, ErrInvalidState
	}
	records, err := readAllHolders(holderFD)
	if err != nil {
		return Snapshot{}, err
	}
	holders := make([]HolderIdentity, len(records))
	for index, record := range records {
		holders[index] = record.Identity
	}
	return Snapshot{Header: header, Holders: holders}, nil
}

func (s *Store) readBackHeader(
	rootFD int,
	lockFD int,
	holderFD int,
	expected Header,
) (Header, error) {
	header, err := readHeader(rootFD)
	if err != nil {
		return Header{}, err
	}
	lockIdentity, err := fstatRegular(lockFD, 0o600)
	if err != nil {
		return Header{}, err
	}
	holderIdentity, err := fstatDirectory(holderFD)
	if err != nil {
		return Header{}, err
	}
	if header != expected ||
		!s.identitiesMatch(header, lockIdentity, holderIdentity) {
		return Header{}, ErrInvalidState
	}
	records, err := readAllHolders(holderFD)
	if err != nil || len(records) != 0 {
		return Header{}, ErrInvalidState
	}
	return header, nil
}

func (s *Store) identitiesMatch(
	header Header,
	lockIdentity fileIdentity,
	holderIdentity fileIdentity,
) bool {
	return header.RootDevice == s.rootIdentity.device &&
		header.RootInode == s.rootIdentity.inode &&
		header.LockDevice == lockIdentity.device &&
		header.LockInode == lockIdentity.inode &&
		header.HolderDevice == holderIdentity.device &&
		header.HolderInode == holderIdentity.inode
}

func (g *heldGuard) Header() Header { return g.header }

func (g *heldGuard) Failure() <-chan error { return g.failure }

// ChildAuthorityFile duplicates the guard's locked open-file description for
// inheritance by an exact child through exec.Cmd.ExtraFiles. The caller must
// close its duplicate after Start; the exec'd child then keeps the shared
// flock held if the guard parent exits without orderly cleanup.
func ChildAuthorityFile(guard Guard) (*os.File, error) {
	held, ok := guard.(*heldGuard)
	if !ok {
		return nil, ErrInvalidState
	}
	held.recordMu.Lock()
	defer held.recordMu.Unlock()
	if held.lockFD < 0 {
		return nil, ErrStoreClosed
	}
	duplicate, err := duplicateCloseOnExec(held.lockFD)
	if err != nil {
		return nil, ErrInvalidState
	}
	file := os.NewFile(uintptr(duplicate), "fleetfence-child-authority")
	if file == nil {
		_ = closeFD(duplicate)
		return nil, ErrInvalidState
	}
	return file, nil
}

func (g *heldGuard) Renew(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		g.publishFailure(err)
		return err
	}
	g.recordMu.Lock()
	defer g.recordMu.Unlock()
	process, err := g.store.identity.Current(ctx, g.identity.PID)
	if err != nil ||
		process.BootID != g.identity.BootID ||
		process.ProcessStartID != g.identity.ProcessStartID {
		if err == nil {
			err = ErrAuthorityConflict
		}
		g.publishFailure(err)
		return err
	}
	record, err := readHolder(g.store.holderFDValue(), g.recordName)
	if err != nil ||
		record.Identity != g.identity ||
		!record.RenewedAt.Equal(g.renewedAt) {
		if err == nil {
			err = ErrAuthorityConflict
		}
		g.publishFailure(err)
		return err
	}
	header, err := readHeader(g.store.rootFDValue())
	if err != nil ||
		header.Generation != g.identity.Generation ||
		header.ActiveFleet != g.identity.Fleet {
		if err == nil {
			err = ErrAuthorityConflict
		}
		g.publishFailure(err)
		return err
	}
	nextRenewedAt := g.store.now().UTC()
	if !nextRenewedAt.After(g.renewedAt) {
		nextRenewedAt = g.renewedAt.Add(time.Nanosecond)
	}
	record.RenewedAt = nextRenewedAt
	if err := writeCanonicalAtomic(
		g.store,
		g.store.holderFDValue(),
		g.recordName,
		record,
	); err != nil {
		g.publishFailure(err)
		return err
	}
	g.renewedAt = nextRenewedAt
	return nil
}

func (g *heldGuard) Close() error {
	g.closeOnce.Do(func() {
		g.recordMu.Lock()
		defer g.recordMu.Unlock()
		holderFD := g.store.holderFDValue()
		record, err := readHolder(holderFD, g.recordName)
		if err == nil &&
			(record.Identity != g.identity ||
				!record.RenewedAt.Equal(g.renewedAt)) {
			err = ErrAuthorityConflict
		}
		if err == nil {
			err = unlinkAndSync(holderFD, g.recordName)
		}
		releaseErr := unlockAndClose(g.lockFD)
		g.lockFD = -1
		g.closeErr = errors.Join(err, releaseErr)
	})
	return g.closeErr
}

func (g *heldGuard) publishFailure(err error) {
	g.failOnce.Do(func() {
		select {
		case g.failure <- err:
		default:
		}
	})
}

func (s *Store) rootFDValue() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return -1
	}
	return s.rootFD
}

func (s *Store) holderFDValue() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return -1
	}
	return s.holderFD
}

func HandoffOperationID(expected uint64, from, to Fleet) string {
	input := operationDomain + "\x00" +
		strconv.FormatUint(expected, 10) + "\x00" +
		string(from) + "\x00" + string(to)
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])
}

func holderRecordName(identity HolderIdentity) string {
	document, _ := json.Marshal(identity)
	sum := sha256.Sum256(append([]byte(holderDomain+"\x00"), document...))
	return hex.EncodeToString(sum[:]) + ".json"
}

func validFleet(fleet Fleet) bool {
	return fleet == FleetNone || acquirableFleet(fleet)
}

func acquirableFleet(fleet Fleet) bool {
	return fleet == FleetPortable || fleet == FleetLegacy
}

func validateHeader(header Header) error {
	if header.Version != stateVersion ||
		header.Generation == 0 ||
		!validFleet(header.ActiveFleet) ||
		!validScalar(header.BootID) ||
		header.RootDevice == 0 ||
		header.RootInode == 0 ||
		header.LockDevice == 0 ||
		header.LockInode == 0 ||
		header.HolderDevice == 0 ||
		header.HolderInode == 0 ||
		header.UpdatedAt.IsZero() ||
		header.UpdatedAt.Location() != time.UTC ||
		!isLowerHex64(header.OperationID) {
		return ErrInvalidState
	}
	return nil
}

func validateHolder(record HolderRecord) error {
	if record.Version != stateVersion ||
		record.Identity.Generation == 0 ||
		!acquirableFleet(record.Identity.Fleet) ||
		!validScalar(record.Identity.OwnerID) ||
		record.Identity.PID <= 0 ||
		!validScalar(record.Identity.BootID) ||
		!validScalar(record.Identity.ProcessStartID) ||
		record.RenewedAt.IsZero() ||
		record.RenewedAt.Location() != time.UTC {
		return ErrInvalidState
	}
	return nil
}

func validScalar(value string) bool {
	if value == "" || len(value) > 128 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= 'A' && character <= 'Z':
		case character >= '0' && character <= '9':
		case strings.ContainsRune("._+-", character):
		default:
			return false
		}
	}
	return true
}

func isLowerHex64(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func requireDeadline(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, ok := ctx.Deadline(); !ok {
		return ErrDeadlineRequired
	}
	return nil
}

func canonicalBytes(value any) ([]byte, error) {
	document, err := json.Marshal(value)
	if err != nil {
		return nil, ErrInvalidState
	}
	return append(document, '\n'), nil
}

func decodeCanonical(document []byte, output any) error {
	if len(document) == 0 ||
		len(document) > maxStateBytes ||
		document[len(document)-1] != '\n' {
		return ErrInvalidState
	}
	if err := json.Unmarshal(document[:len(document)-1], output); err != nil {
		return ErrInvalidState
	}
	canonical, err := canonicalBytes(output)
	if err != nil || !bytes.Equal(document, canonical) {
		return ErrInvalidState
	}
	return nil
}
