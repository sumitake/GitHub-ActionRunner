//go:build darwin || linux

package cli

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReadPrivateOverlayDocumentPinsClosedPrivateTree(t *testing.T) {
	t.Parallel()

	root := privateOverlayTestRoot(t)
	overlayPath := filepath.Join(root, "controller-runtime.json")
	document := []byte(`{"schema_version":1}`)
	privateOverlayTestFile(t, overlayPath, document)
	nested := filepath.Join(root, "secrets")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatalf("Mkdir(nested) error = %v", err)
	}
	privateOverlayTestFile(t, filepath.Join(nested, "github"), []byte("ref"))
	large := filepath.Join(root, "encrypted-rollback.bin")
	privateOverlayTestFile(t, large, []byte("x"))
	if err := os.Truncate(large, int64(maxPrivateOverlayBytes)+1); err != nil {
		t.Fatalf("Truncate(large) error = %v", err)
	}

	got, err := readPrivateOverlayDocument(overlayPath, maxPrivateOverlayBytes)
	if err != nil || !bytes.Equal(got, document) {
		t.Fatalf("readPrivateOverlayDocument() = %q, %v", got, err)
	}
	second, err := readPrivateOverlayDocument(overlayPath, maxPrivateOverlayBytes)
	if err != nil || !bytes.Equal(second, document) {
		t.Fatalf("second readPrivateOverlayDocument() = %q, %v", second, err)
	}
}

func TestReadPrivateOverlayDocumentRejectsPathAndMetadataBypasses(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*testing.T) string{
		"noncanonical path": func(t *testing.T) string {
			root := privateOverlayTestRoot(t)
			path := filepath.Join(root, "overlay.json")
			privateOverlayTestFile(t, path, []byte("x"))
			return root + "/nested/../overlay.json"
		},
		"symlinked parent": func(t *testing.T) string {
			base := privateOverlayTestRoot(t)
			actual := filepath.Join(base, "actual")
			if err := os.Mkdir(actual, 0o700); err != nil {
				t.Fatalf("Mkdir(actual) error = %v", err)
			}
			privateOverlayTestFile(t, filepath.Join(actual, "overlay.json"), []byte("x"))
			link := filepath.Join(base, "link")
			if err := os.Symlink(actual, link); err != nil {
				t.Fatalf("Symlink(parent) error = %v", err)
			}
			return filepath.Join(link, "overlay.json")
		},
		"symlinked overlay": func(t *testing.T) string {
			root := privateOverlayTestRoot(t)
			target := filepath.Join(root, "target.json")
			privateOverlayTestFile(t, target, []byte("x"))
			path := filepath.Join(root, "overlay.json")
			if err := os.Symlink(target, path); err != nil {
				t.Fatalf("Symlink(overlay) error = %v", err)
			}
			return path
		},
		"hard linked overlay": func(t *testing.T) string {
			root := privateOverlayTestRoot(t)
			target := filepath.Join(root, "target.json")
			privateOverlayTestFile(t, target, []byte("x"))
			path := filepath.Join(root, "overlay.json")
			if err := os.Link(target, path); err != nil {
				t.Fatalf("Link(overlay) error = %v", err)
			}
			return path
		},
		"permissive root": func(t *testing.T) string {
			root := privateOverlayTestRoot(t)
			path := filepath.Join(root, "overlay.json")
			privateOverlayTestFile(t, path, []byte("x"))
			if err := os.Chmod(root, 0o755); err != nil {
				t.Fatalf("Chmod(root) error = %v", err)
			}
			return path
		},
		"permissive nested directory": func(t *testing.T) string {
			root := privateOverlayTestRoot(t)
			path := filepath.Join(root, "overlay.json")
			privateOverlayTestFile(t, path, []byte("x"))
			nested := filepath.Join(root, "nested")
			if err := os.Mkdir(nested, 0o755); err != nil {
				t.Fatalf("Mkdir(nested) error = %v", err)
			}
			return path
		},
		"permissive file": func(t *testing.T) string {
			root := privateOverlayTestRoot(t)
			path := filepath.Join(root, "overlay.json")
			privateOverlayTestFile(t, path, []byte("x"))
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatalf("Chmod(file) error = %v", err)
			}
			return path
		},
		"fifo": func(t *testing.T) string {
			root := privateOverlayTestRoot(t)
			path := filepath.Join(root, "overlay.json")
			if err := unix.Mkfifo(path, 0o600); err != nil {
				t.Fatalf("Mkfifo() error = %v", err)
			}
			return path
		},
		"socket": func(t *testing.T) string {
			root := privateOverlayTestRoot(t)
			path := filepath.Join(root, "overlay.json")
			listener, err := net.Listen("unix", path)
			if err != nil {
				t.Fatalf("Listen(unix) error = %v", err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			return path
		},
		"oversized overlay": func(t *testing.T) string {
			root := privateOverlayTestRoot(t)
			path := filepath.Join(root, "overlay.json")
			privateOverlayTestFile(t, path, []byte("x"))
			if err := os.Truncate(path, int64(maxPrivateOverlayBytes)+1); err != nil {
				t.Fatalf("Truncate(overlay) error = %v", err)
			}
			return path
		},
	}
	for name, fixture := range tests {
		name, fixture := name, fixture
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := fixture(t)
			if document, err := readPrivateOverlayDocument(
				path,
				maxPrivateOverlayBytes,
			); err == nil || len(document) != 0 {
				t.Fatalf("readPrivateOverlayDocument() = %q, %v", document, err)
			}
		})
	}
}

func TestReadPrivateOverlayDocumentRejectsUnboundedTree(t *testing.T) {
	t.Parallel()

	t.Run("entries", func(t *testing.T) {
		root := privateOverlayTestRoot(t)
		overlayPath := filepath.Join(root, "overlay.json")
		privateOverlayTestFile(t, overlayPath, []byte("x"))
		for index := 0; index < maxPrivateTreeEntries; index++ {
			privateOverlayTestFile(
				t,
				filepath.Join(root, "entry-"+privateOverlayTestIndex(index)),
				[]byte("x"),
			)
		}
		if _, err := readPrivateOverlayDocument(
			overlayPath,
			maxPrivateOverlayBytes,
		); err == nil {
			t.Fatal("entry-overflow tree was accepted")
		}
	})

	t.Run("depth", func(t *testing.T) {
		root := privateOverlayTestRoot(t)
		overlayPath := filepath.Join(root, "overlay.json")
		privateOverlayTestFile(t, overlayPath, []byte("x"))
		current := root
		for index := 0; index <= maxPrivateTreeDepth; index++ {
			current = filepath.Join(current, "d")
			if err := os.Mkdir(current, 0o700); err != nil {
				t.Fatalf("Mkdir(depth %d) error = %v", index, err)
			}
		}
		if _, err := readPrivateOverlayDocument(
			overlayPath,
			maxPrivateOverlayBytes,
		); err == nil {
			t.Fatal("depth-overflow tree was accepted")
		}
	})
}

func TestValidatePrivateTreeStatRejectsWrongOwnerAndSpecialModes(t *testing.T) {
	t.Parallel()

	valid := unix.Stat_t{}
	valid.Mode = unix.S_IFREG | 0o600
	valid.Uid = uint32(os.Geteuid())
	valid.Nlink = 1
	valid.Ino = 1
	valid.Size = 1
	if _, err := validatePrivateTreeStat(
		&valid,
		unix.S_IFREG,
		0o600,
		true,
		1,
	); err != nil {
		t.Fatalf("validatePrivateTreeStat(valid) error = %v", err)
	}
	wrongOwner := valid
	wrongOwner.Uid++
	if _, err := validatePrivateTreeStat(
		&wrongOwner,
		unix.S_IFREG,
		0o600,
		true,
		1,
	); err == nil {
		t.Fatal("wrong owner was accepted")
	}
	specialMode := valid
	specialMode.Mode |= unix.S_ISUID
	if _, err := validatePrivateTreeStat(
		&specialMode,
		unix.S_IFREG,
		0o600,
		true,
		1,
	); err == nil {
		t.Fatal("setuid file was accepted")
	}
}

func privateOverlayTestIndex(index int) string {
	const digits = "0123456789abcdef"
	return string([]byte{
		digits[(index>>8)&0xf],
		digits[(index>>4)&0xf],
		digits[index&0xf],
	})
}

func privateOverlayTestRoot(t *testing.T) string {
	t.Helper()
	created, err := os.MkdirTemp("/tmp", "pghar-overlay-")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(created); err != nil {
			t.Errorf("RemoveAll(%s) error = %v", created, err)
		}
	})
	root, err := filepath.EvalSymlinks(created)
	if err != nil {
		t.Fatalf("EvalSymlinks(temp) error = %v", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("Chmod(root) error = %v", err)
	}
	return root
}

func privateOverlayTestFile(t *testing.T, path string, document []byte) {
	t.Helper()
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("Chmod(%s) error = %v", path, err)
	}
}
