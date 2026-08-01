package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	seedarchive "github.com/sumitake/portable-ghar/internal/archive"
	"github.com/sumitake/portable-ghar/internal/runtimelock"
)

func TestStageSyntheticListenerPublishesExactVerifiedRunnerAuthority(t *testing.T) {
	fixture := newSyntheticListenerFixture(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"stage-synthetic-listener",
		"--listener", fixture.listener,
		"--generation", strconv.FormatUint(fixture.generation, 10),
		"--output-dir", fixture.output,
	}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("stage-synthetic-listener code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	var ready readiness
	if err := json.Unmarshal(stdout.Bytes(), &ready); err != nil {
		t.Fatalf("READY: %v", err)
	}
	if ready.EvidenceGeneration != fixture.generation {
		t.Fatalf("READY generation=%d", ready.EvidenceGeneration)
	}
	publishedListener := filepath.Join(fixture.output, "runner", "bin", "Runner.Listener")
	if data, err := os.ReadFile(publishedListener); err != nil || !bytes.Equal(data, fixture.contents) {
		t.Fatalf("published listener=%q err=%v", data, err)
	}
	for path, wantMode := range map[string]os.FileMode{
		filepath.Join(fixture.output, "runner"):              0o700,
		filepath.Join(fixture.output, "runner", "bin"):       0o555,
		filepath.Join(fixture.output, "runner", "externals"): 0o555,
		publishedListener: 0o555,
	} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode().Perm() != wantMode || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("%s mode=%v err=%v", path, info, err)
		}
	}
	if entries, err := os.ReadDir(filepath.Join(fixture.output, "runner", "externals")); err != nil || len(entries) != 0 {
		t.Fatalf("externals entries=%v err=%v", entries, err)
	}

	manifestBytes, err := os.ReadFile(filepath.Join(fixture.output, runnerManifestName))
	if err != nil {
		t.Fatalf("runner manifest: %v", err)
	}
	manifest, err := seedarchive.LoadRunnerManifest(bytes.NewReader(manifestBytes))
	if err != nil {
		t.Fatalf("LoadRunnerManifest: %v", err)
	}
	if len(manifest.Entries) != 3 ||
		manifest.Entries[0].Path != "bin" ||
		manifest.Entries[1].Path != "bin/Runner.Listener" ||
		manifest.Entries[1].SHA256 != shaHexBytes(fixture.contents) ||
		manifest.Entries[1].Size != uint64(len(fixture.contents)) ||
		manifest.Entries[2].Path != "externals" {
		t.Fatalf("runner manifest=%+v", manifest)
	}
	verified, err := seedarchive.VerifyRunnerDirectory(
		filepath.Join(fixture.output, "runner"),
		manifest,
		fixture.generation,
	)
	if err != nil {
		t.Fatalf("VerifyRunnerDirectory: %v", err)
	}
	if ready.ManifestSHA256 != verified.ManifestDigest() || ready.TreeLockSHA256 != verified.TreeLockDigest() {
		t.Fatalf("READY does not bind published tree: %+v", ready)
	}
	lockBytes, err := os.ReadFile(filepath.Join(fixture.output, runtimeLockName))
	if err != nil {
		t.Fatalf("runtime lock: %v", err)
	}
	lock, err := runtimelock.Load(bytes.NewReader(lockBytes))
	if err != nil {
		t.Fatalf("Load runtime lock: %v", err)
	}
	if lock.Listener.SHA256 != shaHexBytes(fixture.contents) ||
		lock.Listener.Size != uint64(len(fixture.contents)) ||
		ready.RuntimeLockSHA256 != shaHexBytes(lockBytes) {
		t.Fatalf("runtime lock=%+v READY=%+v", lock, ready)
	}
}

func TestStageSyntheticListenerVerifiesAgainImmediatelyBeforeReadiness(t *testing.T) {
	fixture := newSyntheticListenerFixture(t)
	observed := false
	err := stageSyntheticListener(syntheticListenerOptions{
		listenerPath:       fixture.listener,
		evidenceGeneration: fixture.generation,
		outputDirectory:    fixture.output,
	}, func(stage string) error {
		if stage != "before-ready" {
			return nil
		}
		observed = true
		published := filepath.Join(fixture.output, "runner", "bin", "Runner.Listener")
		if err := os.Chmod(published, 0o600); err != nil {
			return err
		}
		return os.WriteFile(published, []byte("changed"), 0o600)
	})
	if err == nil || !observed {
		t.Fatalf("stageSyntheticListener err=%v observed=%v", err, observed)
	}
	if _, err := os.Lstat(fixture.output); !os.IsNotExist(err) {
		t.Fatalf("failed synthetic transaction remained: %v", err)
	}
}

func TestStageSyntheticListenerRejectsNoncanonicalOrUntrustedInput(t *testing.T) {
	t.Run("incomplete arguments", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		if code := run([]string{"stage-synthetic-listener", "--generation", "1"}, &stdout, &stderr); code != 2 {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
	})

	tests := map[string]func(*testing.T, syntheticListenerFixture) syntheticListenerOptions{
		"zero generation": func(t *testing.T, fixture syntheticListenerFixture) syntheticListenerOptions {
			options := fixture.options()
			options.evidenceGeneration = 0
			return options
		},
		"relative listener": func(t *testing.T, fixture syntheticListenerFixture) syntheticListenerOptions {
			options := fixture.options()
			options.listenerPath = filepath.Base(fixture.listener)
			return options
		},
		"wrong basename": func(t *testing.T, fixture syntheticListenerFixture) syntheticListenerOptions {
			wrong := filepath.Join(filepath.Dir(fixture.listener), "other-listener")
			writeSyntheticListenerFixtureFile(t, wrong, fixture.contents, 0o555)
			options := fixture.options()
			options.listenerPath = wrong
			return options
		},
		"indirect listener": func(t *testing.T, fixture syntheticListenerFixture) syntheticListenerOptions {
			link := filepath.Join(filepath.Dir(fixture.listener), "listener-link")
			if err := os.Symlink(fixture.listener, link); err != nil {
				t.Fatalf("Symlink: %v", err)
			}
			options := fixture.options()
			options.listenerPath = link
			return options
		},
		"writable listener": func(t *testing.T, fixture syntheticListenerFixture) syntheticListenerOptions {
			if err := os.Chmod(fixture.listener, 0o755); err != nil {
				t.Fatalf("Chmod: %v", err)
			}
			return fixture.options()
		},
		"empty listener": func(t *testing.T, fixture syntheticListenerFixture) syntheticListenerOptions {
			if err := os.Chmod(fixture.listener, 0o600); err != nil {
				t.Fatalf("Chmod: %v", err)
			}
			if err := os.WriteFile(fixture.listener, nil, 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			if err := os.Chmod(fixture.listener, 0o555); err != nil {
				t.Fatalf("Chmod: %v", err)
			}
			return fixture.options()
		},
		"multiply linked listener": func(t *testing.T, fixture syntheticListenerFixture) syntheticListenerOptions {
			if err := os.Link(fixture.listener, filepath.Join(filepath.Dir(fixture.listener), "second-link")); err != nil {
				t.Fatalf("Link: %v", err)
			}
			return fixture.options()
		},
		"existing output": func(t *testing.T, fixture syntheticListenerFixture) syntheticListenerOptions {
			if err := os.Mkdir(fixture.output, 0o700); err != nil {
				t.Fatalf("Mkdir: %v", err)
			}
			return fixture.options()
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newSyntheticListenerFixture(t)
			options := mutate(t, fixture)
			if err := stageSyntheticListener(options, nil); err == nil {
				t.Fatal("stageSyntheticListener accepted invalid input")
			}
			if name != "existing output" {
				if _, err := os.Lstat(fixture.output); !os.IsNotExist(err) {
					t.Fatalf("invalid input created output: %v", err)
				}
			}
		})
	}
}

type syntheticListenerFixture struct {
	listener   string
	output     string
	contents   []byte
	generation uint64
}

func newSyntheticListenerFixture(t *testing.T) syntheticListenerFixture {
	t.Helper()
	parent := canonicalTestDir(t)
	listener := filepath.Join(parent, syntheticListenerInputName)
	contents := []byte("portable-ghar-task11-synthetic-listener")
	writeSyntheticListenerFixtureFile(t, listener, contents, 0o555)
	return syntheticListenerFixture{
		listener:   listener,
		output:     filepath.Join(parent, "runtime-output"),
		contents:   contents,
		generation: 29,
	}
}

func (fixture syntheticListenerFixture) options() syntheticListenerOptions {
	return syntheticListenerOptions{
		listenerPath:       fixture.listener,
		evidenceGeneration: fixture.generation,
		outputDirectory:    fixture.output,
	}
}

func writeSyntheticListenerFixtureFile(t *testing.T, path string, contents []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
}
