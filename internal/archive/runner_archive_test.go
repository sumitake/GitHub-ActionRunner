package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type runnerTarEntry struct {
	name     string
	typeflag byte
	mode     int64
	body     []byte
	linkname string
	format   tar.Format
	pax      map[string]string
}

const tarTypeRegA byte = 0

func TestExtractRunnerArchiveAcceptsZeroFilesAndConfinedSymlinks(t *testing.T) {
	parent := canonicalTempDir(t)
	archivePath, digest := writeRunnerArchive(t, parent, validRunnerTarEntries())
	output := filepath.Join(parent, "runner-snapshot")
	defer makeRunnerTreeRemovable(output)

	verified, err := ExtractRunnerArchive(RunnerExtractOptions{
		ArchivePath:        archivePath,
		ExpectedSHA256:     digest,
		EvidenceGeneration: 17,
		OutputDirectory:    output,
	})
	if err != nil {
		t.Fatalf("ExtractRunnerArchive: %v", err)
	}
	if verified.Generation() != 17 || len(verified.ManifestDigest()) != 64 || len(verified.TreeLockDigest()) != 64 {
		t.Fatalf("verified identity incomplete: generation=%d manifest=%q tree=%q", verified.Generation(), verified.ManifestDigest(), verified.TreeLockDigest())
	}
	listener, err := verified.File("bin/Runner.Listener")
	if err != nil || listener.Size != uint64(len("listener")) || listener.Mode != 0o555 {
		t.Fatalf("listener=%+v err=%v", listener, err)
	}
	empty, err := verified.File("externals/empty")
	if err != nil || empty.Size != 0 || empty.SHA256 != emptySHA256 || empty.Mode != 0o444 {
		t.Fatalf("empty=%+v err=%v", empty, err)
	}
	link, err := verified.Symlink("externals/node/bin/npm")
	if err != nil || link.Target != "../lib/node_modules/npm/bin/npm-cli.js" {
		t.Fatalf("link=%+v err=%v", link, err)
	}
	target, err := os.Readlink(filepath.Join(output, "externals", "node", "bin", "npm"))
	if err != nil || target != link.Target {
		t.Fatalf("Readlink target=%q err=%v", target, err)
	}

	var manifestDocument, treeLock bytes.Buffer
	if err := WriteRunnerManifest(&manifestDocument, verified); err != nil {
		t.Fatalf("WriteRunnerManifest: %v", err)
	}
	if err := WriteRunnerTreeLock(&treeLock, verified); err != nil {
		t.Fatalf("WriteRunnerTreeLock: %v", err)
	}
	manifest, err := LoadRunnerManifest(bytes.NewReader(manifestDocument.Bytes()))
	if err != nil {
		t.Fatalf("LoadRunnerManifest: %v", err)
	}
	reverified, err := VerifyRunnerDirectory(output, manifest, 17)
	if err != nil {
		t.Fatalf("VerifyRunnerDirectory: %v", err)
	}
	if reverified.ManifestDigest() != verified.ManifestDigest() || reverified.TreeLockDigest() != verified.TreeLockDigest() {
		t.Fatalf("reverification mismatch: first=%s/%s second=%s/%s", verified.ManifestDigest(), verified.TreeLockDigest(), reverified.ManifestDigest(), reverified.TreeLockDigest())
	}
	if digestBytes(manifestDocument.Bytes()) != verified.ManifestDigest() || digestBytes(treeLock.Bytes()) != verified.TreeLockDigest() {
		t.Fatal("emitted runner evidence digest mismatch")
	}
}

func TestVerifyRunnerDirectoryRejectsFIFOWithoutBlocking(t *testing.T) {
	parent := canonicalTempDir(t)
	archivePath, digest := writeRunnerArchive(t, parent, validRunnerTarEntries())
	output := filepath.Join(parent, "runner-fifo")
	defer makeRunnerTreeRemovable(output)
	verified, err := ExtractRunnerArchive(RunnerExtractOptions{
		ArchivePath:        archivePath,
		ExpectedSHA256:     digest,
		EvidenceGeneration: 17,
		OutputDirectory:    output,
	})
	if err != nil {
		t.Fatalf("ExtractRunnerArchive: %v", err)
	}
	bin := filepath.Join(output, "bin")
	listener := filepath.Join(bin, "Runner.Listener")
	if err := os.Chmod(bin, 0o700); err != nil {
		t.Fatalf("Chmod bin writable: %v", err)
	}
	if err := os.Remove(listener); err != nil {
		t.Fatalf("Remove listener: %v", err)
	}
	if err := unix.Mkfifo(listener, 0o555); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}
	if err := os.Chmod(bin, 0o555); err != nil {
		t.Fatalf("Chmod bin sealed: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := VerifyRunnerDirectory(output, verified.manifest, 17)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("VerifyRunnerDirectory accepted a FIFO")
		}
	case <-time.After(time.Second):
		t.Fatal("VerifyRunnerDirectory blocked opening a FIFO")
	}
}

func TestExtractRunnerArchiveRejectsUnsafeHeadersBeforePublication(t *testing.T) {
	tests := map[string][]runnerTarEntry{
		"hardlink": append(validRunnerTarEntries(), runnerTarEntry{
			name:     "./externals/hard",
			typeflag: tar.TypeLink,
			mode:     0o644,
			linkname: "./bin/Runner.Listener",
		}),
		"traversal": append(validRunnerTarEntries(), runnerTarEntry{
			name:     "./externals/../escape",
			typeflag: tar.TypeReg,
			mode:     0o644,
			body:     []byte("escape"),
		}),
		"absolute": append(validRunnerTarEntries(), runnerTarEntry{
			name:     "/absolute",
			typeflag: tar.TypeReg,
			mode:     0o644,
			body:     []byte("absolute"),
		}),
		"mutable-work": append(validRunnerTarEntries(), runnerTarEntry{
			name:     "./_work/payload",
			typeflag: tar.TypeReg,
			mode:     0o644,
			body:     []byte("mutable"),
		}),
		"case-collision": append(validRunnerTarEntries(), runnerTarEntry{
			name:     "./BIN/Runner.Listener",
			typeflag: tar.TypeReg,
			mode:     0o755,
			body:     []byte("collision"),
		}),
		"escaping-symlink": replaceRunnerTarEntry(validRunnerTarEntries(), "./externals/node/bin/npm", runnerTarEntry{
			name:     "./externals/node/bin/npm",
			typeflag: tar.TypeSymlink,
			mode:     0o777,
			linkname: "../../../../outside",
		}),
		"missing-symlink-target": replaceRunnerTarEntry(validRunnerTarEntries(), "./externals/node/bin/npm", runnerTarEntry{
			name:     "./externals/node/bin/npm",
			typeflag: tar.TypeSymlink,
			mode:     0o777,
			linkname: "../lib/node_modules/npm/bin/missing.js",
		}),
		"duplicate": append(validRunnerTarEntries(), runnerTarEntry{
			name:     "./externals/empty",
			typeflag: tar.TypeReg,
			mode:     0o644,
		}),
		"device": append(validRunnerTarEntries(), runnerTarEntry{
			name:     "./externals/device",
			typeflag: tar.TypeChar,
			mode:     0o600,
		}),
		"block-device": append(validRunnerTarEntries(), runnerTarEntry{
			name:     "./externals/block",
			typeflag: tar.TypeBlock,
			mode:     0o600,
		}),
		"fifo": append(validRunnerTarEntries(), runnerTarEntry{
			name:     "./externals/fifo",
			typeflag: tar.TypeFifo,
			mode:     0o600,
		}),
		"continuation": append(validRunnerTarEntries(), runnerTarEntry{
			name:     "./externals/continuation",
			typeflag: tar.TypeCont,
			mode:     0o600,
		}),
		"unknown-type": append(validRunnerTarEntries(), runnerTarEntry{
			name:     "./externals/unknown",
			typeflag: 'Z',
			mode:     0o600,
		}),
		"pax-path-override": append(validRunnerTarEntries(), runnerTarEntry{
			name:     "./externals/" + strings.Repeat("p", 200),
			typeflag: tar.TypeReg,
			mode:     0o644,
			body:     []byte("pax"),
			format:   tar.FormatPAX,
			pax:      map[string]string{"VENDOR.meta": "must-be-rejected"},
		}),
		"gnu-longname": append(validRunnerTarEntries(), runnerTarEntry{
			name:     "./externals/" + strings.Repeat("a", 513),
			typeflag: tar.TypeReg,
			mode:     0o644,
			body:     []byte("long"),
			format:   tar.FormatGNU,
		}),
		"missing-listener": removeRunnerTarEntry(validRunnerTarEntries(), "./bin/Runner.Listener"),
		"extra-top-level-tree": append(validRunnerTarEntries(),
			runnerTarEntry{name: "./unexpected/", typeflag: tar.TypeDir, mode: 0o755},
			runnerTarEntry{name: "./unexpected/payload", typeflag: tar.TypeReg, mode: 0o644, body: []byte("payload")},
		),
		"absolute-symlink": replaceRunnerTarEntry(validRunnerTarEntries(), "./externals/node/bin/npm", runnerTarEntry{
			name:     "./externals/node/bin/npm",
			typeflag: tar.TypeSymlink,
			mode:     0o777,
			linkname: "/etc/passwd",
		}),
		"symlink-chain": append(validRunnerTarEntries(), runnerTarEntry{
			name:     "./externals/node/bin/npm-chain",
			typeflag: tar.TypeSymlink,
			mode:     0o777,
			linkname: "npm",
		}),
	}

	for name, entries := range tests {
		t.Run(name, func(t *testing.T) {
			parent := canonicalTempDir(t)
			archivePath, digest := writeRunnerArchive(t, parent, entries)
			output := filepath.Join(parent, "runner-snapshot")
			defer makeRunnerTreeRemovable(output)
			if _, err := ExtractRunnerArchive(RunnerExtractOptions{
				ArchivePath:        archivePath,
				ExpectedSHA256:     digest,
				EvidenceGeneration: 1,
				OutputDirectory:    output,
			}); err == nil {
				t.Fatal("ExtractRunnerArchive accepted unsafe archive")
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatalf("unsafe preflight left output: %v", err)
			}
		})
	}
}

func TestExtractRunnerArchiveRejectsDigestTrailingDataAndIndirectArchive(t *testing.T) {
	t.Run("digest", func(t *testing.T) {
		parent := canonicalTempDir(t)
		archivePath, _ := writeRunnerArchive(t, parent, validRunnerTarEntries())
		output := filepath.Join(parent, "runner-snapshot")
		if _, err := ExtractRunnerArchive(RunnerExtractOptions{
			ArchivePath:        archivePath,
			ExpectedSHA256:     strings.Repeat("0", 64),
			EvidenceGeneration: 1,
			OutputDirectory:    output,
		}); err == nil {
			t.Fatal("ExtractRunnerArchive accepted wrong digest")
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatalf("digest failure left output: %v", err)
		}
	})

	t.Run("trailing-data", func(t *testing.T) {
		parent := canonicalTempDir(t)
		archivePath, _ := writeRunnerArchive(t, parent, validRunnerTarEntries())
		file, err := os.OpenFile(archivePath, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatalf("OpenFile: %v", err)
		}
		if _, err := file.Write([]byte("trailing")); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		contents, err := os.ReadFile(archivePath)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		digest := sha256.Sum256(contents)
		output := filepath.Join(parent, "runner-snapshot")
		if _, err := ExtractRunnerArchive(RunnerExtractOptions{
			ArchivePath:        archivePath,
			ExpectedSHA256:     hex.EncodeToString(digest[:]),
			EvidenceGeneration: 1,
			OutputDirectory:    output,
		}); err == nil {
			t.Fatal("ExtractRunnerArchive accepted trailing data")
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatalf("trailing-data failure left output: %v", err)
		}
	})

	t.Run("concatenated-empty-gzip-member", func(t *testing.T) {
		parent := canonicalTempDir(t)
		archivePath, _ := writeRunnerArchive(t, parent, validRunnerTarEntries())
		appendGzipMember(t, archivePath, nil)
		digest := fileDigest(t, archivePath)
		output := filepath.Join(parent, "runner-snapshot")
		if _, err := ExtractRunnerArchive(RunnerExtractOptions{
			ArchivePath:        archivePath,
			ExpectedSHA256:     digest,
			EvidenceGeneration: 1,
			OutputDirectory:    output,
		}); err == nil {
			t.Fatal("ExtractRunnerArchive accepted a second gzip member")
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatalf("concatenated-member failure left output: %v", err)
		}
	})

	t.Run("concatenated-tar-member", func(t *testing.T) {
		parent := canonicalTempDir(t)
		archivePath, _ := writeRunnerArchive(t, parent, validRunnerTarEntries())
		appendGzipMember(t, archivePath, []runnerTarEntry{
			{name: "./", typeflag: tar.TypeDir, mode: 0o755},
			{name: "./bin/", typeflag: tar.TypeDir, mode: 0o755},
			{name: "./bin/Runner.Listener", typeflag: tar.TypeReg, mode: 0o755, body: []byte("smuggled")},
		})
		digest := fileDigest(t, archivePath)
		output := filepath.Join(parent, "runner-snapshot")
		if _, err := ExtractRunnerArchive(RunnerExtractOptions{
			ArchivePath:        archivePath,
			ExpectedSHA256:     digest,
			EvidenceGeneration: 1,
			OutputDirectory:    output,
		}); err == nil {
			t.Fatal("ExtractRunnerArchive accepted a smuggled tar member")
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatalf("concatenated-tar failure left output: %v", err)
		}
	})

	t.Run("indirect", func(t *testing.T) {
		parent := canonicalTempDir(t)
		archivePath, digest := writeRunnerArchive(t, parent, validRunnerTarEntries())
		indirect := filepath.Join(parent, "runner-link.tar.gz")
		if err := os.Symlink(archivePath, indirect); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		output := filepath.Join(parent, "runner-snapshot")
		if _, err := ExtractRunnerArchive(RunnerExtractOptions{
			ArchivePath:        indirect,
			ExpectedSHA256:     digest,
			EvidenceGeneration: 1,
			OutputDirectory:    output,
		}); err == nil {
			t.Fatal("ExtractRunnerArchive accepted indirect archive")
		}
	})

	t.Run("fifo-source", func(t *testing.T) {
		parent := canonicalTempDir(t)
		fifo := filepath.Join(parent, "runner.fifo")
		if err := unix.Mkfifo(fifo, 0o600); err != nil {
			t.Fatalf("Mkfifo: %v", err)
		}
		output := filepath.Join(parent, "runner-snapshot")
		if _, err := ExtractRunnerArchive(RunnerExtractOptions{
			ArchivePath:        fifo,
			ExpectedSHA256:     strings.Repeat("0", 64),
			EvidenceGeneration: 1,
			OutputDirectory:    output,
		}); err == nil {
			t.Fatal("ExtractRunnerArchive accepted a non-regular archive")
		}
	})
}

func TestVerifyRunnerDirectoryRejectsSymlinkAndFileIdentityChanges(t *testing.T) {
	parent := canonicalTempDir(t)
	archivePath, digest := writeRunnerArchive(t, parent, validRunnerTarEntries())
	output := filepath.Join(parent, "runner-snapshot")
	defer makeRunnerTreeRemovable(output)
	verified, err := ExtractRunnerArchive(RunnerExtractOptions{
		ArchivePath:        archivePath,
		ExpectedSHA256:     digest,
		EvidenceGeneration: 9,
		OutputDirectory:    output,
	})
	if err != nil {
		t.Fatalf("ExtractRunnerArchive: %v", err)
	}
	var document bytes.Buffer
	if err := WriteRunnerManifest(&document, verified); err != nil {
		t.Fatalf("WriteRunnerManifest: %v", err)
	}
	manifest, err := LoadRunnerManifest(bytes.NewReader(document.Bytes()))
	if err != nil {
		t.Fatalf("LoadRunnerManifest: %v", err)
	}

	linkParent := filepath.Join(output, "externals", "node", "bin")
	if err := os.Chmod(linkParent, 0o700); err != nil {
		t.Fatalf("Chmod link parent writable: %v", err)
	}
	if err := os.Remove(filepath.Join(linkParent, "npm")); err != nil {
		t.Fatalf("Remove symlink: %v", err)
	}
	if err := os.Symlink("../lib/node_modules/npm/bin/other.js", filepath.Join(linkParent, "npm")); err != nil {
		t.Fatalf("replace symlink: %v", err)
	}
	if err := os.Chmod(linkParent, 0o555); err != nil {
		t.Fatalf("Chmod link parent sealed: %v", err)
	}
	if _, err := VerifyRunnerDirectory(output, manifest, 9); err == nil {
		t.Fatal("VerifyRunnerDirectory accepted changed symlink")
	}

	if err := os.Chmod(linkParent, 0o700); err != nil {
		t.Fatalf("Chmod link parent writable for restore: %v", err)
	}
	if err := os.Remove(filepath.Join(linkParent, "npm")); err != nil {
		t.Fatalf("Remove replacement symlink: %v", err)
	}
	if err := os.Symlink("../lib/node_modules/npm/bin/npm-cli.js", filepath.Join(linkParent, "npm")); err != nil {
		t.Fatalf("restore symlink: %v", err)
	}
	if err := os.Chmod(linkParent, 0o555); err != nil {
		t.Fatalf("Chmod link parent resealed: %v", err)
	}
	listener := filepath.Join(output, "bin", "Runner.Listener")
	if err := os.Chmod(listener, 0o644); err != nil {
		t.Fatalf("Chmod listener: %v", err)
	}
	if _, err := VerifyRunnerDirectory(output, manifest, 9); err == nil {
		t.Fatal("VerifyRunnerDirectory accepted changed file mode")
	}
}

func TestExtractRunnerArchiveEnforcesStreamingBoundsBeforeOutput(t *testing.T) {
	tests := map[string]func(*runnerArchiveLimits){
		"compressed": func(limits *runnerArchiveLimits) { limits.maxCompressedBytes = 1 },
		"entries":    func(limits *runnerArchiveLimits) { limits.maxEntries = 2 },
		"path":       func(limits *runnerArchiveLimits) { limits.maxPathBytes = 8 },
		"link":       func(limits *runnerArchiveLimits) { limits.maxLinkBytes = 4 },
		"file":       func(limits *runnerArchiveLimits) { limits.maxFileBytes = 4 },
		"expanded":   func(limits *runnerArchiveLimits) { limits.maxExpandedBytes = 10 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			parent := canonicalTempDir(t)
			archivePath, digest := writeRunnerArchive(t, parent, validRunnerTarEntries())
			output := filepath.Join(parent, "runner-snapshot")
			limits := defaultRunnerArchiveLimits
			mutate(&limits)
			if _, err := extractRunnerArchive(RunnerExtractOptions{
				ArchivePath:        archivePath,
				ExpectedSHA256:     digest,
				EvidenceGeneration: 1,
				OutputDirectory:    output,
			}, limits, runnerExtractHooks{}); err == nil {
				t.Fatal("extractRunnerArchive accepted an over-limit archive")
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatalf("bounds failure left output: %v", err)
			}
		})
	}

	t.Run("high-ratio-expanded-stream", func(t *testing.T) {
		parent := canonicalTempDir(t)
		entries := validRunnerTarEntries()
		entries = append(entries, runnerTarEntry{
			name:     "./externals/compressible",
			typeflag: tar.TypeReg,
			mode:     0o644,
			body:     bytes.Repeat([]byte{0}, 64<<10),
		})
		archivePath, digest := writeRunnerArchive(t, parent, entries)
		output := filepath.Join(parent, "runner-snapshot")
		defer makeRunnerTreeRemovable(output)
		limits := defaultRunnerArchiveLimits
		limits.maxExpandedBytes = 32 << 10
		if _, err := extractRunnerArchive(RunnerExtractOptions{
			ArchivePath:        archivePath,
			ExpectedSHA256:     digest,
			EvidenceGeneration: 1,
			OutputDirectory:    output,
		}, limits, runnerExtractHooks{}); err == nil {
			t.Fatal("extractRunnerArchive accepted a high-ratio expanded-size overrun")
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatalf("expanded-size failure left output: %v", err)
		}
	})
}

func TestExtractRunnerArchiveCleansPassTwoMutation(t *testing.T) {
	parent := canonicalTempDir(t)
	archivePath, digest := writeRunnerArchive(t, parent, validRunnerTarEntries())
	output := filepath.Join(parent, "runner-snapshot")
	hooks := runnerExtractHooks{
		beforeSecondPass: func() {
			file, err := os.OpenFile(archivePath, os.O_RDWR, 0)
			if err != nil {
				t.Fatalf("OpenFile: %v", err)
			}
			one := []byte{0}
			if _, err := file.ReadAt(one, 16); err != nil {
				t.Fatalf("ReadAt: %v", err)
			}
			one[0] ^= 0xff
			if _, err := file.WriteAt(one, 16); err != nil {
				t.Fatalf("WriteAt: %v", err)
			}
			if err := file.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
		},
	}
	if _, err := extractRunnerArchive(RunnerExtractOptions{
		ArchivePath:        archivePath,
		ExpectedSHA256:     digest,
		EvidenceGeneration: 1,
		OutputDirectory:    output,
	}, defaultRunnerArchiveLimits, hooks); err == nil {
		t.Fatal("extractRunnerArchive accepted pass-two archive mutation")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("pass-two failure left output: %v", err)
	}
}

func TestRunnerAndSeedAuthoritiesAreDistinctAndGenerationIsMetadata(t *testing.T) {
	var _ seedDirectoryAuthority = VerifiedDirectory{}
	var _ runnerDirectoryAuthority = VerifiedRunnerDirectory{}
	seedType := reflect.TypeOf(VerifiedDirectory{})
	runnerType := reflect.TypeOf(VerifiedRunnerDirectory{})
	if seedType.AssignableTo(runnerType) || seedType.ConvertibleTo(runnerType) ||
		runnerType.AssignableTo(seedType) || runnerType.ConvertibleTo(seedType) {
		t.Fatal("runner and seed authorities are assignable or convertible")
	}

	parent := canonicalTempDir(t)
	archivePath, digest := writeRunnerArchive(t, parent, validRunnerTarEntries())
	output := filepath.Join(parent, "runner-snapshot")
	defer makeRunnerTreeRemovable(output)
	verified, err := ExtractRunnerArchive(RunnerExtractOptions{
		ArchivePath:        archivePath,
		ExpectedSHA256:     digest,
		EvidenceGeneration: 41,
		OutputDirectory:    output,
	})
	if err != nil {
		t.Fatalf("ExtractRunnerArchive: %v", err)
	}
	var document bytes.Buffer
	if err := WriteRunnerManifest(&document, verified); err != nil {
		t.Fatalf("WriteRunnerManifest: %v", err)
	}
	manifest, err := LoadRunnerManifest(bytes.NewReader(document.Bytes()))
	if err != nil {
		t.Fatalf("LoadRunnerManifest: %v", err)
	}
	next, err := VerifyRunnerDirectory(output, manifest, 42)
	if err != nil {
		t.Fatalf("VerifyRunnerDirectory next generation: %v", err)
	}
	if next.Generation() != 42 || next.ManifestDigest() != verified.ManifestDigest() || next.TreeLockDigest() != verified.TreeLockDigest() {
		t.Fatalf("generation/content binding incorrect: first=%d/%s/%s next=%d/%s/%s",
			verified.Generation(), verified.ManifestDigest(), verified.TreeLockDigest(),
			next.Generation(), next.ManifestDigest(), next.TreeLockDigest())
	}
}

func TestRunnerImageVerificationIsNonAuthorizingAndRequiresInstalledRoot(t *testing.T) {
	var _ runnerImageEvidence = RunnerImageVerification{}
	imageType := reflect.TypeOf(RunnerImageVerification{})
	authorityType := reflect.TypeOf(VerifiedRunnerDirectory{})
	if imageType.AssignableTo(authorityType) || imageType.ConvertibleTo(authorityType) ||
		authorityType.AssignableTo(imageType) || authorityType.ConvertibleTo(imageType) {
		t.Fatal("installed image evidence and staging authority are assignable or convertible")
	}
	if _, ok := any(RunnerImageVerification{}).(runnerDirectoryAuthority); ok {
		t.Fatal("installed image evidence implements runner publication authority")
	}

	parent := canonicalTempDir(t)
	archivePath, digest := writeRunnerArchive(t, parent, validRunnerTarEntries())
	output := filepath.Join(parent, "runner-snapshot")
	defer makeRunnerTreeRemovable(output)
	staging, err := ExtractRunnerArchive(RunnerExtractOptions{
		ArchivePath:        archivePath,
		ExpectedSHA256:     digest,
		EvidenceGeneration: 47,
		OutputDirectory:    output,
	})
	if err != nil {
		t.Fatalf("ExtractRunnerArchive: %v", err)
	}
	var document bytes.Buffer
	if err := WriteRunnerManifest(&document, staging); err != nil {
		t.Fatalf("WriteRunnerManifest: %v", err)
	}
	manifest, err := LoadRunnerManifest(bytes.NewReader(document.Bytes()))
	if err != nil {
		t.Fatalf("LoadRunnerManifest: %v", err)
	}

	if _, err := verifyRunnerImageDirectoryForOwner(
		output,
		manifest,
		47,
		uint32(os.Geteuid()),
		uint32(os.Getegid()),
	); err == nil {
		t.Fatal("installed image verification accepted private root mode 0700")
	}
	if _, err := VerifyRunnerImageDirectory(output, manifest, 47); err == nil {
		t.Fatal("root-owned installed image verifier accepted non-root staging identity")
	}
	if err := os.Chmod(output, 0o555); err != nil {
		t.Fatalf("Chmod installed root: %v", err)
	}
	image, err := verifyRunnerImageDirectoryForOwner(
		output,
		manifest,
		47,
		uint32(os.Geteuid()),
		uint32(os.Getegid()),
	)
	if err != nil {
		t.Fatalf("verifyRunnerImageDirectoryForOwner: %v", err)
	}
	if image.Generation() != staging.Generation() ||
		image.ManifestDigest() != staging.ManifestDigest() ||
		image.TreeLockDigest() != staging.TreeLockDigest() {
		t.Fatalf("installed image evidence differs: image=%d/%s/%s staging=%d/%s/%s",
			image.Generation(), image.ManifestDigest(), image.TreeLockDigest(),
			staging.Generation(), staging.ManifestDigest(), staging.TreeLockDigest())
	}

	if err := os.Chmod(output, 0o755); err != nil {
		t.Fatalf("Chmod writable root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(output, "unexpected"), []byte("extra"), 0o444); err != nil {
		t.Fatalf("WriteFile unexpected: %v", err)
	}
	if err := os.Chmod(output, 0o555); err != nil {
		t.Fatalf("Chmod reseal root: %v", err)
	}
	if _, err := verifyRunnerImageDirectoryForOwner(
		output,
		manifest,
		47,
		uint32(os.Geteuid()),
		uint32(os.Getegid()),
	); err == nil {
		t.Fatal("installed image verification accepted an extra object")
	}
}

func TestPinnedRunnerArchiveConformance(t *testing.T) {
	archivePath := os.Getenv("PGHAR_PINNED_RUNNER_ARCHIVE")
	if archivePath == "" {
		t.Skip("PGHAR_PINNED_RUNNER_ARCHIVE is not set")
	}
	output := filepath.Join(filepath.Dir(archivePath), "package-conformance-output")
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("conformance output must not exist: %v", err)
	}
	defer makeRunnerTreeRemovable(output)
	verified, err := ExtractRunnerArchive(RunnerExtractOptions{
		ArchivePath:        archivePath,
		ExpectedSHA256:     "04cf0be1aff4c3ec3554466c39124ca250e3effd8873bb7e8d68535aa9505d5d",
		EvidenceGeneration: 1,
		OutputDirectory:    output,
	})
	if err != nil {
		t.Fatalf("ExtractRunnerArchive exact pin: %v", err)
	}
	var document bytes.Buffer
	if err := WriteRunnerManifest(&document, verified); err != nil {
		t.Fatalf("WriteRunnerManifest: %v", err)
	}
	manifest, err := LoadRunnerManifest(bytes.NewReader(document.Bytes()))
	if err != nil {
		t.Fatalf("LoadRunnerManifest: %v", err)
	}
	regular, symlinks, zero := 0, 0, 0
	for _, entry := range manifest.Entries {
		switch entry.Type {
		case RunnerEntryRegular:
			regular++
			if entry.Size == 0 {
				zero++
			}
		case RunnerEntrySymlink:
			symlinks++
		}
	}
	if len(manifest.Entries) != 11_432 || regular != 9_291 || symlinks != 6 || zero != 8 {
		t.Fatalf("exact archive inventory entries=%d regular=%d symlinks=%d zero=%d", len(manifest.Entries), regular, symlinks, zero)
	}
}

func validRunnerTarEntries() []runnerTarEntry {
	return []runnerTarEntry{
		{name: "./", typeflag: tar.TypeDir, mode: 0o755},
		{name: "./safe_sleep.sh", typeflag: tar.TypeReg, mode: 0o755, body: []byte("#!/bin/sh\n")},
		{name: "./bin/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "./bin/Runner.Listener", typeflag: tar.TypeReg, mode: 0o744, body: []byte("listener")},
		{name: "./externals/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "./externals/empty", typeflag: tar.TypeReg, mode: 0o644},
		{name: "./externals/node/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "./externals/node/bin/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "./externals/node/bin/npm", typeflag: tar.TypeSymlink, mode: 0o777, linkname: "../lib/node_modules/npm/bin/npm-cli.js"},
		{name: "./externals/node/lib/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "./externals/node/lib/node_modules/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "./externals/node/lib/node_modules/npm/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "./externals/node/lib/node_modules/npm/bin/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "./externals/node/lib/node_modules/npm/bin/npm-cli.js", typeflag: tar.TypeReg, mode: 0o644, body: []byte("npm")},
	}
}

func replaceRunnerTarEntry(entries []runnerTarEntry, name string, replacement runnerTarEntry) []runnerTarEntry {
	result := append([]runnerTarEntry(nil), entries...)
	for index := range result {
		if result[index].name == name {
			result[index] = replacement
			return result
		}
	}
	panic("runner tar fixture entry not found")
}

func removeRunnerTarEntry(entries []runnerTarEntry, name string) []runnerTarEntry {
	result := make([]runnerTarEntry, 0, len(entries)-1)
	for _, entry := range entries {
		if entry.name != name {
			result = append(result, entry)
		}
	}
	if len(result) != len(entries)-1 {
		panic("runner tar fixture entry not found")
	}
	return result
}

func writeRunnerArchive(t *testing.T, parent string, entries []runnerTarEntry) (string, string) {
	t.Helper()
	archivePath := filepath.Join(parent, "runner.tar.gz")
	file, err := os.OpenFile(archivePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		header := &tar.Header{
			Name:       entry.name,
			Typeflag:   entry.typeflag,
			Mode:       entry.mode,
			Size:       int64(len(entry.body)),
			Linkname:   entry.linkname,
			Uid:        1001,
			Gid:        1001,
			Uname:      "runner",
			Gname:      "runner",
			Format:     entry.format,
			PAXRecords: entry.pax,
		}
		if header.Format == tar.FormatUnknown {
			header.Format = tar.FormatGNU
		}
		if entry.typeflag != tar.TypeReg && entry.typeflag != tarTypeRegA {
			header.Size = 0
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatalf("WriteHeader %s: %v", entry.name, err)
		}
		if len(entry.body) > 0 {
			if _, err := tarWriter.Write(entry.body); err != nil {
				t.Fatalf("Write %s: %v", entry.name, err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("file Close: %v", err)
	}
	contents, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	digest := sha256.Sum256(contents)
	return archivePath, hex.EncodeToString(digest[:])
}

func appendGzipMember(t *testing.T, archivePath string, entries []runnerTarEntry) {
	t.Helper()
	file, err := os.OpenFile(archivePath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatalf("OpenFile append: %v", err)
	}
	gzipWriter := gzip.NewWriter(file)
	if entries == nil {
		if err := gzipWriter.Close(); err != nil {
			t.Fatalf("gzip Close: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("file Close: %v", err)
		}
		return
	}
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		header := &tar.Header{
			Name:       entry.name,
			Typeflag:   entry.typeflag,
			Mode:       entry.mode,
			Size:       int64(len(entry.body)),
			Linkname:   entry.linkname,
			Uid:        1001,
			Gid:        1001,
			Uname:      "runner",
			Gname:      "runner",
			Format:     tar.FormatGNU,
			PAXRecords: entry.pax,
		}
		if entry.typeflag != tar.TypeReg && entry.typeflag != tarTypeRegA {
			header.Size = 0
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatalf("WriteHeader append %s: %v", entry.name, err)
		}
		if _, err := io.Copy(tarWriter, bytes.NewReader(entry.body)); err != nil {
			t.Fatalf("Write append %s: %v", entry.name, err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("file Close: %v", err)
	}
}

func fileDigest(t *testing.T, path string) string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	digest := sha256.Sum256(contents)
	return hex.EncodeToString(digest[:])
}

func makeRunnerTreeRemovable(root string) {
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err == nil && entry.IsDir() {
			_ = os.Chmod(path, 0o700)
		}
		return nil
	})
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
