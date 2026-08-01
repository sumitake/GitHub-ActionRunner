package productionruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"sync"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

const (
	watchdogMarkerName       = "watchdog.json"
	watchdogMarkerTempName   = ".watchdog.tmp"
	watchdogMarkerMaxBytes   = 4096
	watchdogMarkerSchema     = uint32(1)
	watchdogMarkerDigestZone = "portable-ghar-watchdog-marker-v1"
)

var ErrWatchdogMarker = errors.New(
	"productionruntime: watchdog marker failed",
)

type watchdogMarkerBinding struct {
	PrivateOverlayRevision string
	ManifestDigest         string
	WatchdogBinary         string
}

type watchdogMarkerDocument struct {
	SchemaVersion          uint32 `json:"schema_version"`
	PrivateOverlayRevision string `json:"private_overlay_revision"`
	ManifestDigest         string `json:"manifest_digest"`
	WatchdogBinaryDigest   string `json:"watchdog_binary_digest"`
}

type watchdogMarkerStore struct {
	mu       sync.Mutex
	root     *os.Root
	identity releaseFileIdentity
	closed   bool
}

func openWatchdogMarkerStore(rootPath string) (*watchdogMarkerStore, error) {
	root, identity, err := openPrivateReleaseRoot(rootPath)
	if err != nil {
		return nil, ErrWatchdogMarker
	}
	return &watchdogMarkerStore{
		root:     root,
		identity: identity,
	}, nil
}

func (store *watchdogMarkerStore) Inspect(
	binding watchdogMarkerBinding,
) (hostruntime.ArtifactProjection, bool, error) {
	if store == nil || !validWatchdogMarkerBinding(binding) {
		return hostruntime.ArtifactProjection{}, false,
			ErrWatchdogMarker
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.inspectLocked(binding)
}

func (store *watchdogMarkerStore) Install(
	binding watchdogMarkerBinding,
) error {
	if store == nil || !validWatchdogMarkerBinding(binding) {
		return ErrWatchdogMarker
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.readyLocked() != nil {
		return ErrWatchdogMarker
	}
	if _, present, err := store.inspectLocked(binding); err != nil {
		return err
	} else if present {
		return nil
	}
	document, err := expectedWatchdogMarker(binding)
	if err != nil {
		return err
	}
	if err := store.root.Remove(watchdogMarkerTempName); err != nil &&
		!errors.Is(err, os.ErrNotExist) {
		return ErrWatchdogMarker
	}
	if err := writeReleaseFile(
		store.root,
		watchdogMarkerTempName,
		document,
	); err != nil {
		return ErrWatchdogMarker
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = store.root.Remove(watchdogMarkerTempName)
		}
	}()
	if err := store.root.Rename(
		watchdogMarkerTempName,
		watchdogMarkerName,
	); err != nil ||
		syncReleaseRoot(store.root) != nil {
		return ErrWatchdogMarker
	}
	cleanup = false
	if _, present, err := store.inspectLocked(binding); err != nil ||
		!present {
		return ErrWatchdogMarker
	}
	return nil
}

// Replace atomically moves an exact existing watchdog binding to one exact
// replacement. It is idempotent only when either the prior or target binding
// is positively read back; any third binding fails closed.
func (store *watchdogMarkerStore) Replace(
	prior watchdogMarkerBinding,
	target watchdogMarkerBinding,
) error {
	if store == nil ||
		!validWatchdogMarkerBinding(prior) ||
		!validWatchdogMarkerBinding(target) ||
		prior == target {
		return ErrWatchdogMarker
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.readyLocked() != nil {
		return ErrWatchdogMarker
	}
	_, matched, present, err := store.inspectOneOfLocked(prior, target)
	if err != nil || !present {
		return ErrWatchdogMarker
	}
	if matched == 1 {
		return nil
	}
	document, err := expectedWatchdogMarker(target)
	if err != nil {
		return ErrWatchdogMarker
	}
	if err := store.root.Remove(watchdogMarkerTempName); err != nil &&
		!errors.Is(err, os.ErrNotExist) {
		return ErrWatchdogMarker
	}
	if err := writeReleaseFile(
		store.root,
		watchdogMarkerTempName,
		document,
	); err != nil {
		return ErrWatchdogMarker
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = store.root.Remove(watchdogMarkerTempName)
		}
	}()
	if err := store.root.Rename(
		watchdogMarkerTempName,
		watchdogMarkerName,
	); err != nil ||
		syncReleaseRoot(store.root) != nil {
		return ErrWatchdogMarker
	}
	cleanup = false
	_, matched, present, err = store.inspectOneOfLocked(prior, target)
	if err != nil || !present || matched != 1 {
		return ErrWatchdogMarker
	}
	return nil
}

func (store *watchdogMarkerStore) Remove(
	binding watchdogMarkerBinding,
) error {
	if store == nil || !validWatchdogMarkerBinding(binding) {
		return ErrWatchdogMarker
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.readyLocked() != nil {
		return ErrWatchdogMarker
	}
	if _, present, err := store.inspectLocked(binding); err != nil {
		return ErrWatchdogMarker
	} else if !present {
		return nil
	}
	if err := store.root.Remove(watchdogMarkerName); err != nil ||
		syncReleaseRoot(store.root) != nil {
		return ErrWatchdogMarker
	}
	if _, present, err := store.inspectLocked(binding); err != nil || present {
		return ErrWatchdogMarker
	}
	return nil
}

func (store *watchdogMarkerStore) InspectOneOf(
	bindings ...watchdogMarkerBinding,
) (hostruntime.ArtifactProjection, int, bool, error) {
	if store == nil || len(bindings) == 0 {
		return hostruntime.ArtifactProjection{}, -1, false,
			ErrWatchdogMarker
	}
	for _, binding := range bindings {
		if !validWatchdogMarkerBinding(binding) {
			return hostruntime.ArtifactProjection{}, -1, false,
				ErrWatchdogMarker
		}
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.inspectOneOfLocked(bindings...)
}

func (store *watchdogMarkerStore) Close() error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil
	}
	store.closed = true
	if store.root == nil {
		return nil
	}
	if err := store.root.Close(); err != nil {
		return ErrWatchdogMarker
	}
	store.root = nil
	return nil
}

func (store *watchdogMarkerStore) inspectLocked(
	binding watchdogMarkerBinding,
) (hostruntime.ArtifactProjection, bool, error) {
	artifact, matched, present, err := store.inspectOneOfLocked(binding)
	if err != nil || !present {
		return artifact, present, err
	}
	if matched != 0 {
		return hostruntime.ArtifactProjection{}, false,
			ErrWatchdogMarker
	}
	return artifact, true, nil
}

func (store *watchdogMarkerStore) inspectOneOfLocked(
	bindings ...watchdogMarkerBinding,
) (hostruntime.ArtifactProjection, int, bool, error) {
	if store.readyLocked() != nil {
		return hostruntime.ArtifactProjection{}, -1, false,
			ErrWatchdogMarker
	}
	if _, err := store.root.Lstat(watchdogMarkerName); errors.Is(
		err,
		os.ErrNotExist,
	) {
		return hostruntime.ArtifactProjection{}, -1, false, nil
	} else if err != nil {
		return hostruntime.ArtifactProjection{}, -1, false,
			ErrWatchdogMarker
	}
	document, identity, err := readReleaseFile(
		store.root,
		watchdogMarkerName,
		watchdogMarkerMaxBytes,
	)
	if err != nil {
		return hostruntime.ArtifactProjection{}, -1, false,
			ErrWatchdogMarker
	}
	matched := -1
	for index, binding := range bindings {
		expected, expectedErr := expectedWatchdogMarker(binding)
		if expectedErr != nil {
			return hostruntime.ArtifactProjection{}, -1, false,
				ErrWatchdogMarker
		}
		if bytes.Equal(document, expected) {
			if matched >= 0 {
				return hostruntime.ArtifactProjection{}, -1, false,
					ErrWatchdogMarker
			}
			matched = index
		}
	}
	if matched < 0 {
		return hostruntime.ArtifactProjection{}, -1, false,
			ErrWatchdogMarker
	}
	major, minor, ok := releaseDeviceNumbers(identity.device)
	if !ok {
		return hostruntime.ArtifactProjection{}, -1, false,
			ErrWatchdogMarker
	}
	contentDigest := digestArtifact(
		watchdogMarkerDigestZone,
		document,
	)
	artifact := hostruntime.ArtifactProjection{
		ObjectID:      "watchdog-marker",
		Kind:          "regular-file",
		Present:       true,
		ContentDigest: &contentDigest,
		DeviceMajor:   major,
		DeviceMinor:   minor,
		Inode:         identity.inode,
		Mode:          uint32(identity.mode.Perm()),
		Size:          uint64(identity.size),
	}
	artifactIdentity, err :=
		hostruntime.DeriveArtifactIdentity(artifact)
	if err != nil {
		return hostruntime.ArtifactProjection{}, -1, false,
			ErrWatchdogMarker
	}
	artifact.IdentityDigest = &artifactIdentity
	return artifact, matched, true, nil
}

func (store *watchdogMarkerStore) readyLocked() error {
	if store.closed ||
		store.root == nil ||
		!rootStillMatches(store.root, store.identity) {
		return ErrWatchdogMarker
	}
	return nil
}

func expectedWatchdogMarker(
	binding watchdogMarkerBinding,
) ([]byte, error) {
	if !validWatchdogMarkerBinding(binding) {
		return nil, ErrWatchdogMarker
	}
	binaryDigest, err := digestPinnedExecutable(
		binding.WatchdogBinary,
	)
	if err != nil {
		return nil, ErrWatchdogMarker
	}
	document, err := json.Marshal(watchdogMarkerDocument{
		SchemaVersion:          watchdogMarkerSchema,
		PrivateOverlayRevision: binding.PrivateOverlayRevision,
		ManifestDigest:         binding.ManifestDigest,
		WatchdogBinaryDigest:   binaryDigest,
	})
	if err != nil ||
		len(document) == 0 ||
		len(document) > watchdogMarkerMaxBytes {
		return nil, ErrWatchdogMarker
	}
	var parsed watchdogMarkerDocument
	if !decodeClosed(document, &parsed) {
		return nil, ErrWatchdogMarker
	}
	return document, nil
}

func validWatchdogMarkerBinding(binding watchdogMarkerBinding) bool {
	return lowerHexDigest(binding.PrivateOverlayRevision) &&
		lowerHexDigest(binding.ManifestDigest) &&
		canonicalPath(binding.WatchdogBinary)
}
