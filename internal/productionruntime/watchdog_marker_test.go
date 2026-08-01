package productionruntime

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWatchdogMarkerReplaceRequiresExactPriorAndIsIdempotent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("Mkdir(state): %v", err)
	}
	makeBinary := func(name, contents string) string {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(contents), 0o500); err != nil {
			t.Fatalf("WriteFile(%s): %v", name, err)
		}
		if err := os.Chmod(path, 0o500); err != nil {
			t.Fatalf("Chmod(%s): %v", name, err)
		}
		return path
	}
	prior := watchdogMarkerBinding{
		PrivateOverlayRevision: strings.Repeat("a", 64),
		ManifestDigest:         strings.Repeat("b", 64),
		WatchdogBinary:         makeBinary("watchdog-prior", "prior"),
	}
	target := watchdogMarkerBinding{
		PrivateOverlayRevision: strings.Repeat("c", 64),
		ManifestDigest:         strings.Repeat("d", 64),
		WatchdogBinary:         makeBinary("watchdog-target", "target"),
	}
	foreign := watchdogMarkerBinding{
		PrivateOverlayRevision: strings.Repeat("e", 64),
		ManifestDigest:         strings.Repeat("f", 64),
		WatchdogBinary:         makeBinary("watchdog-foreign", "foreign"),
	}
	store, err := openWatchdogMarkerStore(root)
	if err != nil {
		t.Fatalf("openWatchdogMarkerStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Install(prior); err != nil {
		t.Fatalf("Install(prior): %v", err)
	}
	if err := store.Replace(foreign, target); !errors.Is(
		err,
		ErrWatchdogMarker,
	) {
		t.Fatalf("Replace(foreign, target) error = %v", err)
	}
	if err := store.Replace(prior, target); err != nil {
		t.Fatalf("Replace(prior, target): %v", err)
	}
	if err := store.Replace(prior, target); err != nil {
		t.Fatalf("Replace(prior, target) replay: %v", err)
	}
	artifact, matched, present, err := store.InspectOneOf(prior, target)
	if err != nil || !present || matched != 1 || !artifact.Present {
		t.Fatalf(
			"InspectOneOf() = (%#v, %d, %t, %v)",
			artifact,
			matched,
			present,
			err,
		)
	}
}

func TestWatchdogMarkerRemovePreservesForeignBinding(t *testing.T) {
	t.Parallel()

	root := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("Mkdir(state): %v", err)
	}
	binary := filepath.Join(root, "watchdog")
	if err := os.WriteFile(binary, []byte("watchdog"), 0o500); err != nil {
		t.Fatalf("WriteFile(watchdog): %v", err)
	}
	expected := watchdogMarkerBinding{
		PrivateOverlayRevision: strings.Repeat("a", 64),
		ManifestDigest:         strings.Repeat("b", 64),
		WatchdogBinary:         binary,
	}
	foreign := watchdogMarkerBinding{
		PrivateOverlayRevision: strings.Repeat("c", 64),
		ManifestDigest:         strings.Repeat("d", 64),
		WatchdogBinary:         binary,
	}
	store, err := openWatchdogMarkerStore(root)
	if err != nil {
		t.Fatalf("openWatchdogMarkerStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Install(foreign); err != nil {
		t.Fatalf("Install(foreign): %v", err)
	}
	if err := store.Remove(expected); !errors.Is(err, ErrWatchdogMarker) {
		t.Fatalf("Remove(expected) error = %v", err)
	}
	if _, present, err := store.Inspect(foreign); err != nil || !present {
		t.Fatalf("foreign marker after removal = present %t, error %v", present, err)
	}
}
