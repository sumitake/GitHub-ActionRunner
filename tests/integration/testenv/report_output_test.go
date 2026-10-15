package testenv

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

func TestReportOutputWritesExactCanonicalBytesOnce(t *testing.T) {
	t.Parallel()

	directory := privateReportDirectory(t)
	path := filepath.Join(directory, "report.json")
	output, err := OpenReportOutput(path, os.Geteuid())
	if err != nil {
		t.Fatalf("OpenReportOutput: %v", err)
	}
	t.Cleanup(func() { _ = output.Close() })
	report := conformance.Run(context.Background(), newReportShapeProfile(t, false))
	if err := output.Write(report); err != nil {
		t.Fatalf("Write: %v", err)
	}
	want, err := conformance.MarshalReport(report)
	if err != nil {
		t.Fatalf("MarshalReport: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("written report differs from the canonical bytes: %v", err)
	}
	if _, err := conformance.ParseReport(got, len(got)); err != nil {
		t.Fatalf("written report does not parse: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode() != 0o600 {
		t.Fatalf("report mode = %v, %v; want 0600", info.Mode(), err)
	}
	if err := output.Write(report); !errors.Is(err, ErrReportOutput) {
		t.Fatalf("second Write = %v, want a refusal", err)
	}
}

func TestOpenReportOutputRefusesUnsafePaths(t *testing.T) {
	t.Parallel()

	directory := privateReportDirectory(t)
	existing := filepath.Join(directory, "existing.json")
	if err := os.WriteFile(existing, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(directory, "dangling.json")
	if err := os.Symlink(filepath.Join(directory, "nowhere"), dangling); err != nil {
		t.Fatal(err)
	}
	linkedParent := filepath.Join(directory, "linked")
	if err := os.Symlink(directory, linkedParent); err != nil {
		t.Fatal(err)
	}
	shared := filepath.Join(directory, "shared")
	if err := os.Mkdir(shared, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o770); err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		path string
		euid int
	}{
		"relative":              {path: "report.json", euid: os.Geteuid()},
		"unclean":               {path: directory + "/./report.json", euid: os.Geteuid()},
		"missing parent":        {path: filepath.Join(directory, "absent", "r.json"), euid: os.Geteuid()},
		"existing file":         {path: existing, euid: os.Geteuid()},
		"dangling symlink":      {path: dangling, euid: os.Geteuid()},
		"symlinked parent":      {path: filepath.Join(linkedParent, "r.json"), euid: os.Geteuid()},
		"group-writable parent": {path: filepath.Join(shared, "r.json"), euid: os.Geteuid()},
		"parent owned by other": {path: filepath.Join(directory, "r.json"), euid: os.Geteuid() + 1},
	}
	for name, test := range tests {
		output, err := OpenReportOutput(test.path, test.euid)
		if !errors.Is(err, ErrReportOutput) {
			_ = output.Close()
			t.Errorf("%s: OpenReportOutput = %v, want a refusal", name, err)
		}
	}
}

func TestReportOutputRefusesAFileCreatedAfterStartup(t *testing.T) {
	t.Parallel()

	directory := privateReportDirectory(t)
	path := filepath.Join(directory, "report.json")
	output, err := OpenReportOutput(path, os.Geteuid())
	if err != nil {
		t.Fatalf("OpenReportOutput: %v", err)
	}
	t.Cleanup(func() { _ = output.Close() })
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	report := conformance.Run(context.Background(), newReportShapeProfile(t, false))
	if err := output.Write(report); !errors.Is(err, ErrReportOutput) {
		t.Fatalf("Write through a symlink = %v, want a refusal", err)
	}
	if got, _ := os.ReadFile(target); string(got) != "keep" {
		t.Fatalf("symlink target changed to %q", got)
	}
}

func TestReportOutputWritesIntoTheDirectoryCheckedAtStartup(t *testing.T) {
	t.Parallel()

	base := privateReportDirectory(t)
	checked := filepath.Join(base, "checked")
	if err := os.Mkdir(checked, 0o700); err != nil {
		t.Fatal(err)
	}
	output, err := OpenReportOutput(filepath.Join(checked, "report.json"), os.Geteuid())
	if err != nil {
		t.Fatalf("OpenReportOutput: %v", err)
	}
	t.Cleanup(func() { _ = output.Close() })

	// Swap the checked directory for a symlink to another directory, as a
	// writer of an ancestor could during the run.
	moved := filepath.Join(base, "moved")
	if err := os.Rename(checked, moved); err != nil {
		t.Fatal(err)
	}
	elsewhere := filepath.Join(base, "elsewhere")
	if err := os.Mkdir(elsewhere, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, checked); err != nil {
		t.Fatal(err)
	}

	report := conformance.Run(context.Background(), newReportShapeProfile(t, false))
	if err := output.Write(report); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(moved, "report.json")); err != nil {
		t.Fatalf("report not in the directory checked at startup: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(elsewhere, "report.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("report followed the swapped path: %v", err)
	}
}

func TestReportOutputCloseIsIdempotentAndBlocksWrites(t *testing.T) {
	t.Parallel()

	directory := privateReportDirectory(t)
	output, err := OpenReportOutput(filepath.Join(directory, "report.json"), os.Geteuid())
	if err != nil {
		t.Fatalf("OpenReportOutput: %v", err)
	}
	if err := output.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := output.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	report := conformance.Run(context.Background(), newReportShapeProfile(t, false))
	if err := output.Write(report); !errors.Is(err, ErrReportOutput) {
		t.Fatalf("Write after Close = %v, want a refusal", err)
	}
}

func privateReportDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}
