package productionruntime

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

const (
	releaseManifestName = "runtime-manifest.json"
	releaseOverlayName  = "private-overlay.json"
	currentReleaseName  = "current"

	maximumReleaseManifestBytes = 1 << 16
	maximumReleaseOverlayBytes  = 2 << 20
)

var ErrReleaseBundle = errors.New(
	"productionruntime: release bundle failed",
)

type releaseBundleSnapshot struct {
	present          bool
	manifestDigest   string
	overlayRevision  string
	manifestDocument []byte
	overlayDocument  []byte
	selection        hostruntime.CurrentSelectionProjection
}

type releaseFileIdentity struct {
	device uint64
	inode  uint64
	uid    uint32
	nlink  uint64
	size   int64
	mode   os.FileMode
}

type releaseBundleStore struct {
	mu              sync.Mutex
	stagingPath     string
	releasePath     string
	stagingRoot     *os.Root
	releaseRoot     *os.Root
	stagingIdentity releaseFileIdentity
	releaseIdentity releaseFileIdentity
	closed          bool
}

func openReleaseBundleStore(
	stagingPath string,
	releasePath string,
) (*releaseBundleStore, error) {
	if !canonicalReleasePath(stagingPath) ||
		!canonicalReleasePath(releasePath) ||
		stagingPath == releasePath {
		return nil, ErrReleaseBundle
	}
	stagingRoot, stagingIdentity, err := openPrivateReleaseRoot(stagingPath)
	if err != nil {
		return nil, ErrReleaseBundle
	}
	releaseRoot, releaseIdentity, err := openPrivateReleaseRoot(releasePath)
	if err != nil {
		_ = stagingRoot.Close()
		return nil, ErrReleaseBundle
	}
	if sameReleaseIdentity(stagingIdentity, releaseIdentity) {
		_ = stagingRoot.Close()
		_ = releaseRoot.Close()
		return nil, ErrReleaseBundle
	}
	return &releaseBundleStore{
		stagingPath:     stagingPath,
		releasePath:     releasePath,
		stagingRoot:     stagingRoot,
		releaseRoot:     releaseRoot,
		stagingIdentity: stagingIdentity,
		releaseIdentity: releaseIdentity,
	}, nil
}

func (store *releaseBundleStore) Close() error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil
	}
	store.closed = true
	var result error
	if store.stagingRoot != nil {
		result = errors.Join(result, store.stagingRoot.Close())
		store.stagingRoot = nil
	}
	if store.releaseRoot != nil {
		result = errors.Join(result, store.releaseRoot.Close())
		store.releaseRoot = nil
	}
	if result != nil {
		return ErrReleaseBundle
	}
	return nil
}

func (store *releaseBundleStore) Stage(
	manifestDigest string,
	overlayRevision string,
	overlayDocument []byte,
	manifestDocument []byte,
) error {
	if store == nil ||
		!validReleaseBundleDocuments(
			manifestDigest,
			overlayRevision,
			overlayDocument,
			manifestDocument,
			store.stagingPath,
			store.releasePath,
		) {
		return ErrReleaseBundle
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.readyLocked() != nil {
		return ErrReleaseBundle
	}
	existing, present, err := inspectReleaseBundle(
		store.stagingRoot,
		manifestDigest,
	)
	if err != nil {
		return ErrReleaseBundle
	}
	if present {
		if !bundleMatches(
			existing,
			manifestDigest,
			overlayRevision,
			overlayDocument,
			manifestDocument,
		) {
			return ErrReleaseBundle
		}
		return nil
	}
	if err := writeReleaseBundleAtomic(
		store.stagingRoot,
		".stage-"+manifestDigest,
		manifestDigest,
		overlayDocument,
		manifestDocument,
	); err != nil {
		return ErrReleaseBundle
	}
	readback, present, err := inspectReleaseBundle(
		store.stagingRoot,
		manifestDigest,
	)
	if err != nil ||
		!present ||
		!bundleMatches(
			readback,
			manifestDigest,
			overlayRevision,
			overlayDocument,
			manifestDocument,
		) {
		return ErrReleaseBundle
	}
	return nil
}

func (store *releaseBundleStore) Staged(
	manifestDigest string,
	overlayRevision string,
) (releaseBundleSnapshot, error) {
	snapshot, present, err := store.InspectStaged(
		manifestDigest,
		overlayRevision,
	)
	if err != nil || !present {
		return releaseBundleSnapshot{}, ErrReleaseBundle
	}
	return snapshot, nil
}

func (store *releaseBundleStore) InspectStaged(
	manifestDigest string,
	overlayRevision string,
) (releaseBundleSnapshot, bool, error) {
	if store == nil ||
		!lowerHexDigest(manifestDigest) ||
		!lowerHexDigest(overlayRevision) {
		return releaseBundleSnapshot{}, false, ErrReleaseBundle
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.readyLocked() != nil {
		return releaseBundleSnapshot{}, false, ErrReleaseBundle
	}
	snapshot, present, err := inspectReleaseBundle(
		store.stagingRoot,
		manifestDigest,
	)
	if err != nil ||
		present && (snapshot.manifestDigest != manifestDigest ||
			snapshot.overlayRevision != overlayRevision) {
		return releaseBundleSnapshot{}, false, ErrReleaseBundle
	}
	return snapshot, present, nil
}

func (store *releaseBundleStore) Select(
	manifestDigest string,
	overlayRevision string,
) error {
	if store == nil ||
		!lowerHexDigest(manifestDigest) ||
		!lowerHexDigest(overlayRevision) {
		return ErrReleaseBundle
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.readyLocked() != nil {
		return ErrReleaseBundle
	}
	if err := store.promoteLocked(
		manifestDigest,
		overlayRevision,
	); err != nil {
		return err
	}
	if err := replaceCurrentRelease(
		store.releaseRoot,
		manifestDigest,
	); err != nil {
		return ErrReleaseBundle
	}
	current, present, err := currentReleaseLocked(store.releaseRoot)
	if err != nil ||
		!present ||
		current.manifestDigest != manifestDigest ||
		current.overlayRevision != overlayRevision {
		return ErrReleaseBundle
	}
	return nil
}

// Promote copies one exact staged bundle into its immutable release directory
// without changing the current selection.
func (store *releaseBundleStore) Promote(
	manifestDigest string,
	overlayRevision string,
) error {
	if store == nil ||
		!lowerHexDigest(manifestDigest) ||
		!lowerHexDigest(overlayRevision) {
		return ErrReleaseBundle
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.readyLocked() != nil {
		return ErrReleaseBundle
	}
	return store.promoteLocked(manifestDigest, overlayRevision)
}

func (store *releaseBundleStore) promoteLocked(
	manifestDigest string,
	overlayRevision string,
) error {
	staged, present, err := inspectReleaseBundle(
		store.stagingRoot,
		manifestDigest,
	)
	if err != nil ||
		!present ||
		staged.manifestDigest != manifestDigest ||
		staged.overlayRevision != overlayRevision {
		return ErrReleaseBundle
	}
	release, present, err := inspectReleaseBundle(
		store.releaseRoot,
		manifestDigest,
	)
	if err != nil {
		return ErrReleaseBundle
	}
	if present {
		if !bundleMatches(
			release,
			manifestDigest,
			overlayRevision,
			staged.overlayDocument,
			staged.manifestDocument,
		) {
			return ErrReleaseBundle
		}
	} else if err := writeReleaseBundleAtomic(
		store.releaseRoot,
		".release-"+manifestDigest,
		manifestDigest,
		staged.overlayDocument,
		staged.manifestDocument,
	); err != nil {
		return ErrReleaseBundle
	}
	released, present, err := inspectReleaseBundle(
		store.releaseRoot,
		manifestDigest,
	)
	if err != nil ||
		!present ||
		released.manifestDigest != manifestDigest ||
		released.overlayRevision != overlayRevision ||
		!bundleMatches(
			released,
			manifestDigest,
			overlayRevision,
			staged.overlayDocument,
			staged.manifestDocument,
		) {
		return ErrReleaseBundle
	}
	return nil
}

func (store *releaseBundleStore) Released(
	manifestDigest string,
	overlayRevision string,
) (releaseBundleSnapshot, error) {
	released, present, err := store.InspectReleased(
		manifestDigest,
		overlayRevision,
	)
	if err != nil || !present {
		return releaseBundleSnapshot{}, ErrReleaseBundle
	}
	return released, nil
}

func (store *releaseBundleStore) InspectReleased(
	manifestDigest string,
	overlayRevision string,
) (releaseBundleSnapshot, bool, error) {
	if store == nil ||
		!lowerHexDigest(manifestDigest) ||
		!lowerHexDigest(overlayRevision) {
		return releaseBundleSnapshot{}, false, ErrReleaseBundle
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.readyLocked() != nil {
		return releaseBundleSnapshot{}, false, ErrReleaseBundle
	}
	released, present, err := inspectReleaseBundle(
		store.releaseRoot,
		manifestDigest,
	)
	if err != nil ||
		present && (released.manifestDigest != manifestDigest ||
			released.overlayRevision != overlayRevision) {
		return releaseBundleSnapshot{}, false, ErrReleaseBundle
	}
	return released, present, nil
}

func (store *releaseBundleStore) Current() (
	releaseBundleSnapshot,
	bool,
	error,
) {
	if store == nil {
		return releaseBundleSnapshot{}, false, ErrReleaseBundle
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.readyLocked() != nil {
		return releaseBundleSnapshot{}, false, ErrReleaseBundle
	}
	return currentReleaseLocked(store.releaseRoot)
}

func (store *releaseBundleStore) readyLocked() error {
	if store.closed ||
		store.stagingRoot == nil ||
		store.releaseRoot == nil ||
		!rootStillMatches(store.stagingRoot, store.stagingIdentity) ||
		!rootStillMatches(store.releaseRoot, store.releaseIdentity) {
		return ErrReleaseBundle
	}
	return nil
}

func currentReleaseLocked(
	root *os.Root,
) (releaseBundleSnapshot, bool, error) {
	linkInfo, err := root.Lstat(currentReleaseName)
	if errors.Is(err, os.ErrNotExist) {
		return releaseBundleSnapshot{}, false, nil
	}
	linkIdentity, ok := privateReleaseIdentity(
		linkInfo,
		os.ModeSymlink,
		0,
		false,
	)
	if err != nil || !ok {
		return releaseBundleSnapshot{}, false, ErrReleaseBundle
	}
	linkText, err := root.Readlink(currentReleaseName)
	if err != nil || !lowerHexDigest(linkText) {
		return releaseBundleSnapshot{}, false, ErrReleaseBundle
	}
	snapshot, present, err := inspectReleaseBundle(root, linkText)
	if err != nil || !present {
		return releaseBundleSnapshot{}, false, ErrReleaseBundle
	}
	bundleRoot, err := root.OpenRoot(linkText)
	if err != nil {
		return releaseBundleSnapshot{}, false, ErrReleaseBundle
	}
	defer bundleRoot.Close()
	directoryInfo, err := bundleRoot.Stat(".")
	if err != nil {
		return releaseBundleSnapshot{}, false, ErrReleaseBundle
	}
	directoryIdentity, ok := privateReleaseIdentity(
		directoryInfo,
		os.ModeDir,
		0o700,
		false,
	)
	if !ok {
		return releaseBundleSnapshot{}, false, ErrReleaseBundle
	}
	_, manifestIdentity, err := readReleaseFile(
		bundleRoot,
		releaseManifestName,
		maximumReleaseManifestBytes,
	)
	if err != nil {
		return releaseBundleSnapshot{}, false, ErrReleaseBundle
	}
	releaseMajor, releaseMinor, ok :=
		releaseDeviceNumbers(directoryIdentity.device)
	if !ok {
		return releaseBundleSnapshot{}, false, ErrReleaseBundle
	}
	linkMajor, linkMinor, ok :=
		releaseDeviceNumbers(linkIdentity.device)
	if !ok {
		return releaseBundleSnapshot{}, false, ErrReleaseBundle
	}
	manifestMajor, manifestMinor, ok :=
		releaseDeviceNumbers(manifestIdentity.device)
	if !ok {
		return releaseBundleSnapshot{}, false, ErrReleaseBundle
	}
	snapshot.selection = hostruntime.CurrentSelectionProjection{
		ReleaseDirectoryDeviceMajor: releaseMajor,
		ReleaseDirectoryDeviceMinor: releaseMinor,
		ReleaseDirectoryInode:       directoryIdentity.inode,
		SymlinkDeviceMajor:          linkMajor,
		SymlinkDeviceMinor:          linkMinor,
		SymlinkInode:                linkIdentity.inode,
		RelativeLinkText:            linkText,
		ManifestDeviceMajor:         manifestMajor,
		ManifestDeviceMinor:         manifestMinor,
		ManifestInode:               manifestIdentity.inode,
		ManifestDigest:              snapshot.manifestDigest,
	}
	return snapshot, true, nil
}

func validReleaseBundleDocuments(
	manifestDigest string,
	overlayRevision string,
	overlayDocument []byte,
	manifestDocument []byte,
	stagingPath string,
	releasePath string,
) bool {
	if !lowerHexDigest(manifestDigest) ||
		!lowerHexDigest(overlayRevision) ||
		len(overlayDocument) == 0 ||
		len(overlayDocument) > maximumReleaseOverlayBytes ||
		len(manifestDocument) == 0 ||
		len(manifestDocument) > maximumReleaseManifestBytes {
		return false
	}
	overlay, parsedRevision, err := hostruntime.ParsePrivateOverlay(
		overlayDocument,
		maximumReleaseOverlayBytes,
	)
	if err != nil ||
		parsedRevision != overlayRevision ||
		overlay.Paths.StagingRoot != stagingPath ||
		overlay.Paths.ReleaseRoot != releasePath {
		return false
	}
	_, parsedDigest, err := hostruntime.ParseRuntimeManifest(
		manifestDocument,
		maximumReleaseManifestBytes,
	)
	return err == nil &&
		parsedDigest == manifestDigest &&
		overlay.Manifest.Digest == manifestDigest
}

func inspectReleaseBundle(
	root *os.Root,
	name string,
) (releaseBundleSnapshot, bool, error) {
	if root == nil || !lowerHexDigest(name) {
		return releaseBundleSnapshot{}, false, ErrReleaseBundle
	}
	bundleRoot, err := root.OpenRoot(name)
	if errors.Is(err, os.ErrNotExist) {
		return releaseBundleSnapshot{}, false, nil
	}
	if err != nil {
		return releaseBundleSnapshot{}, false, ErrReleaseBundle
	}
	defer bundleRoot.Close()
	info, err := bundleRoot.Stat(".")
	if err != nil {
		return releaseBundleSnapshot{}, false, ErrReleaseBundle
	}
	if _, ok := privateReleaseIdentity(
		info,
		os.ModeDir,
		0o700,
		false,
	); !ok {
		return releaseBundleSnapshot{}, false, ErrReleaseBundle
	}
	overlayDocument, _, err := readReleaseFile(
		bundleRoot,
		releaseOverlayName,
		maximumReleaseOverlayBytes,
	)
	if err != nil {
		return releaseBundleSnapshot{}, false, ErrReleaseBundle
	}
	manifestDocument, _, err := readReleaseFile(
		bundleRoot,
		releaseManifestName,
		maximumReleaseManifestBytes,
	)
	if err != nil {
		return releaseBundleSnapshot{}, false, ErrReleaseBundle
	}
	_, overlayRevision, err := hostruntime.ParsePrivateOverlay(
		overlayDocument,
		maximumReleaseOverlayBytes,
	)
	if err != nil {
		return releaseBundleSnapshot{}, false, ErrReleaseBundle
	}
	_, manifestDigest, err := hostruntime.ParseRuntimeManifest(
		manifestDocument,
		maximumReleaseManifestBytes,
	)
	if err != nil || manifestDigest != name {
		return releaseBundleSnapshot{}, false, ErrReleaseBundle
	}
	return releaseBundleSnapshot{
		present:          true,
		manifestDigest:   manifestDigest,
		overlayRevision:  overlayRevision,
		manifestDocument: manifestDocument,
		overlayDocument:  overlayDocument,
	}, true, nil
}

func writeReleaseBundleAtomic(
	root *os.Root,
	tempName string,
	finalName string,
	overlayDocument []byte,
	manifestDocument []byte,
) error {
	if root == nil ||
		root.RemoveAll(tempName) != nil ||
		root.Mkdir(tempName, 0o700) != nil {
		return ErrReleaseBundle
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = root.RemoveAll(tempName)
		}
	}()
	tempRoot, err := root.OpenRoot(tempName)
	if err != nil {
		return ErrReleaseBundle
	}
	if err := writeReleaseFile(
		tempRoot,
		releaseOverlayName,
		overlayDocument,
	); err != nil {
		_ = tempRoot.Close()
		return ErrReleaseBundle
	}
	if err := writeReleaseFile(
		tempRoot,
		releaseManifestName,
		manifestDocument,
	); err != nil ||
		syncReleaseRoot(tempRoot) != nil ||
		tempRoot.Close() != nil ||
		root.Rename(tempName, finalName) != nil ||
		syncReleaseRoot(root) != nil {
		return ErrReleaseBundle
	}
	cleanup = false
	return nil
}

func replaceCurrentRelease(root *os.Root, manifestDigest string) error {
	tempName := ".current-" + manifestDigest
	if err := root.Remove(tempName); err != nil &&
		!errors.Is(err, os.ErrNotExist) {
		return ErrReleaseBundle
	}
	if err := root.Symlink(manifestDigest, tempName); err != nil {
		return ErrReleaseBundle
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = root.Remove(tempName)
		}
	}()
	if err := root.Rename(tempName, currentReleaseName); err != nil ||
		syncReleaseRoot(root) != nil {
		return ErrReleaseBundle
	}
	cleanup = false
	return nil
}

func writeReleaseFile(
	root *os.Root,
	name string,
	document []byte,
) error {
	file, err := root.OpenFile(
		name,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		0o600,
	)
	if err != nil {
		return ErrReleaseBundle
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return ErrReleaseBundle
	}
	written, writeErr := file.Write(document)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil ||
		written != len(document) ||
		syncErr != nil ||
		closeErr != nil {
		return ErrReleaseBundle
	}
	return nil
}

func readReleaseFile(
	root *os.Root,
	name string,
	maximum int,
) ([]byte, releaseFileIdentity, error) {
	file, err := root.Open(name)
	if err != nil {
		return nil, releaseFileIdentity{}, ErrReleaseBundle
	}
	defer file.Close()
	beforeInfo, err := file.Stat()
	if err != nil {
		return nil, releaseFileIdentity{}, ErrReleaseBundle
	}
	before, ok := privateReleaseIdentity(
		beforeInfo,
		0,
		0o600,
		true,
	)
	if !ok || before.size <= 0 || before.size > int64(maximum) {
		return nil, releaseFileIdentity{}, ErrReleaseBundle
	}
	document, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || len(document) == 0 || len(document) > maximum {
		return nil, releaseFileIdentity{}, ErrReleaseBundle
	}
	afterInfo, err := file.Stat()
	if err != nil {
		return nil, releaseFileIdentity{}, ErrReleaseBundle
	}
	after, ok := privateReleaseIdentity(
		afterInfo,
		0,
		0o600,
		true,
	)
	if !ok ||
		before != after ||
		after.size != int64(len(document)) {
		return nil, releaseFileIdentity{}, ErrReleaseBundle
	}
	return document, after, nil
}

func openPrivateReleaseRoot(
	path string,
) (*os.Root, releaseFileIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, releaseFileIdentity{}, ErrReleaseBundle
	}
	expected, ok := privateReleaseIdentity(
		info,
		os.ModeDir,
		0o700,
		false,
	)
	if !ok {
		return nil, releaseFileIdentity{}, ErrReleaseBundle
	}
	root, err := os.OpenRoot(path)
	if err != nil || !rootStillMatches(root, expected) {
		if root != nil {
			_ = root.Close()
		}
		return nil, releaseFileIdentity{}, ErrReleaseBundle
	}
	return root, expected, nil
}

func rootStillMatches(
	root *os.Root,
	expected releaseFileIdentity,
) bool {
	if root == nil {
		return false
	}
	info, err := root.Stat(".")
	if err != nil {
		return false
	}
	actual, ok := privateReleaseIdentity(
		info,
		os.ModeDir,
		0o700,
		false,
	)
	return ok && sameReleaseIdentity(actual, expected)
}

func privateReleaseIdentity(
	info os.FileInfo,
	kind os.FileMode,
	mode os.FileMode,
	singleLink bool,
) (releaseFileIdentity, bool) {
	if info == nil ||
		info.Mode()&os.ModeType != kind ||
		(kind != os.ModeSymlink && info.Mode().Perm() != mode) {
		return releaseFileIdentity{}, false
	}
	identity, ok := releaseIdentityFields(info)
	if !ok ||
		identity.device == 0 ||
		identity.inode == 0 ||
		identity.uid != uint32(os.Geteuid()) ||
		singleLink && identity.nlink != 1 {
		return releaseFileIdentity{}, false
	}
	identity.mode = info.Mode()
	identity.size = info.Size()
	return identity, true
}

func sameReleaseIdentity(
	left releaseFileIdentity,
	right releaseFileIdentity,
) bool {
	return left.device == right.device &&
		left.inode == right.inode
}

func bundleMatches(
	snapshot releaseBundleSnapshot,
	manifestDigest string,
	overlayRevision string,
	overlayDocument []byte,
	manifestDocument []byte,
) bool {
	return snapshot.present &&
		snapshot.manifestDigest == manifestDigest &&
		snapshot.overlayRevision == overlayRevision &&
		bytes.Equal(snapshot.overlayDocument, overlayDocument) &&
		bytes.Equal(snapshot.manifestDocument, manifestDocument)
}

func syncReleaseRoot(root *os.Root) error {
	file, err := root.Open(".")
	if err != nil {
		return ErrReleaseBundle
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if syncErr != nil || closeErr != nil {
		return ErrReleaseBundle
	}
	return nil
}

func canonicalReleasePath(path string) bool {
	return filepath.IsAbs(path) &&
		filepath.Clean(path) == path &&
		path != "/"
}
