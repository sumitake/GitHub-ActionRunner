package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReplaceCanaryReportPreservesPrivateModeAndRefusesChangedInput(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "conformance-report.json")
	uid := uint32(os.Geteuid())
	if err := os.WriteFile(path, []byte("pending"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := replaceCanaryReport(path, []byte("pending"), []byte("completed"), uid); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "completed" {
		t.Fatal("report replacement failed", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("report mode changed")
	}
	if err := replaceCanaryReport(path, []byte("pending"), []byte("other"), uid); err == nil {
		t.Fatal("changed report overwritten")
	}
	data, _ = os.ReadFile(path)
	if string(data) != "completed" {
		t.Fatal("failed replacement changed report")
	}
	entries, _ := os.ReadDir(root)
	if len(entries) != 1 {
		t.Fatal("temporary report remained")
	}
}

func TestReplaceCanaryReportRefusesIndirectOrPublicFiles(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "public file", "public directory", "noncanonical"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "report.json")
			if err := os.WriteFile(path, []byte("pending"), 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink":
				target := path + ".original"
				if err := os.Rename(path, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+".alias"); err != nil {
					t.Fatal(err)
				}
			case "public file":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "public directory":
				if err := os.Chmod(root, 0755); err != nil {
					t.Fatal(err)
				}
			case "noncanonical":
				path = root + "/./report.json"
			}
			if err := replaceCanaryReport(path, []byte("pending"), []byte("completed"), uint32(os.Geteuid())); err == nil {
				t.Fatal("untrusted report path accepted")
			}
		})
	}
}

func TestPinnedOwnedStatKeepsRootReaderStrict(t *testing.T) {
	stat := unix.Stat_t{Mode: unix.S_IFREG | 0600, Uid: 1000, Nlink: 1, Ino: 7, Size: 7}
	if _, err := validatePinnedOwnedStat(&stat, 0600, 1000); err != nil {
		t.Fatal(err)
	}
	if _, err := validatePinnedRootStat(&stat, 0600); err == nil {
		t.Fatal("root reader accepted non-root ownership")
	}
	for name, mutate := range map[string]func(*unix.Stat_t){
		"owner":    func(s *unix.Stat_t) { s.Uid++ },
		"mode":     func(s *unix.Stat_t) { s.Mode = unix.S_IFREG | 0644 },
		"type":     func(s *unix.Stat_t) { s.Mode = unix.S_IFDIR | 0600 },
		"hardlink": func(s *unix.Stat_t) { s.Nlink = 2 },
		"inode":    func(s *unix.Stat_t) { s.Ino = 0 },
		"size":     func(s *unix.Stat_t) { s.Size = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := stat
			mutate(&bad)
			if _, err := validatePinnedOwnedStat(&bad, 0600, 1000); err == nil {
				t.Fatal("invalid private file identity accepted")
			}
		})
	}
}

func TestReplaceCanaryReportRejectsEmptyOrUnboundedDocuments(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "report.json")
	if err := os.WriteFile(path, []byte("pending"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, value := range [][]byte{nil, make([]byte, maxConformanceReportBytes+1)} {
		if replaceCanaryReport(path, []byte("pending"), value, uint32(os.Geteuid())) == nil {
			t.Fatal("invalid completed report bytes accepted")
		}
	}
}

func TestOwnedReportReadDoesNotRelaxProductionRootReads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte("pending"), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := readPinnedOwnedFile(path, 0600, 1024, uint32(os.Geteuid()))
	if err != nil || string(data) != "pending" {
		t.Fatal("owned pinned read failed", err)
	}
	if _, err := readPinnedOwnedFile(path, 0600, 1024, uint32(os.Geteuid()+1)); err == nil {
		t.Fatal("wrong owner accepted")
	}
	if os.Geteuid() != 0 {
		if _, err := readPinnedRootFile(path, 0600, 1024); err == nil {
			t.Fatal("root reader accepted a non-root report")
		}
	}
}
