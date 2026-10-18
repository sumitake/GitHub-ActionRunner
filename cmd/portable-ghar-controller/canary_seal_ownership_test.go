package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

func canarySealReadbackFixture(t *testing.T) (string, string, canaryReadback) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	report := pendingCanaryFixture(t)
	document, err := conformance.MarshalReport(report)
	if err != nil {
		t.Fatal(err)
	}
	runtime := canaryRuntimeFixture(report)
	runtime.overlay.Paths.DatabasePath = filepath.Join(root, "controller.db")
	runtime.overlay.Paths.StateRoot = root
	runtime.overlay.Target.ExpectedEUID = uint64(os.Geteuid())
	path := filepath.Join(root, conformanceReportName)
	if err := os.WriteFile(path, document, 0600); err != nil {
		t.Fatal(err)
	}
	return runtime.overlay.Paths.DatabasePath, path, canaryReadback{runtime: runtime, report: report, document: document, record: readyCanaryFixture(report)}
}

func TestCanarySealRefusesAnOwnedControllerDatabase(t *testing.T) {
	database, path, ready := canarySealReadbackFixture(t)
	owner, err := acquireFileOwnership(database + ".owner.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	read := false
	_, err = sealCanaryReport(context.Background(), database, func(context.Context) (canaryReadback, error) {
		read = true
		return ready, nil
	}, replaceCanaryReport)
	if err == nil || read {
		t.Fatal("sealing read or replaced proof while a controller owned the database")
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil || !bytes.Equal(after, ready.document) {
		t.Fatal("refused sealing changed report", readErr)
	}
}

func TestCanarySealHoldsOwnershipThroughReadbackAndReportReplacement(t *testing.T) {
	database, path, ready := canarySealReadbackFixture(t)
	assertOwned := func() {
		t.Helper()
		competing, err := acquireFileOwnership(database + ".owner.lock")
		if err == nil {
			_ = competing.Close()
			t.Fatal("a controller could acquire ownership during sealing")
		}
	}
	replaced := false
	receipt, err := sealCanaryReport(context.Background(), database, func(context.Context) (canaryReadback, error) {
		assertOwned()
		return ready, nil
	}, func(path string, pending, completed []byte, uid uint32) error {
		assertOwned()
		if err := replaceCanaryReport(path, pending, completed, uid); err != nil {
			return err
		}
		assertOwned() // replacement has synced the report and its directory.
		replaced = true
		return nil
	})
	if err != nil || !replaced || receipt.OriginalReportDigest != ready.report.Digest() {
		t.Fatal("sealing failed", receipt, err)
	}
	after, err := os.ReadFile(path)
	if err != nil || bytes.Equal(after, ready.document) {
		t.Fatal("report was not replaced", err)
	}
	report, err := conformance.ParseReport(after, maxConformanceReportBytes)
	if err != nil || report.Status() != conformance.StatusPassed {
		t.Fatal("replacement did not pass", err)
	}
	owner, err := acquireFileOwnership(database + ".owner.lock")
	if err != nil {
		t.Fatal("sealing retained ownership after publication", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCanarySealReleasesOwnershipWithoutPublishingOnFailure(t *testing.T) {
	for _, scenario := range []string{"readback", "database changed", "ownership replaced", "replacement", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			database, path, ready := canarySealReadbackFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "canceled" {
				cancel()
			}
			_, err := sealCanaryReport(ctx, database, func(context.Context) (canaryReadback, error) {
				switch scenario {
				case "readback":
					return canaryReadback{}, errors.New("synthetic readback failure")
				case "database changed":
					ready.runtime.overlay.Paths.DatabasePath += ".other"
				case "ownership replaced":
					if err := os.Rename(database+".owner.lock", database+".old.lock"); err != nil {
						return canaryReadback{}, err
					}
				}
				return ready, nil
			}, func(path string, pending, completed []byte, uid uint32) error {
				if scenario == "replacement" {
					return errors.New("synthetic replacement failure")
				}
				return replaceCanaryReport(path, pending, completed, uid)
			})
			if err == nil {
				t.Fatal("failed or changed sealing input published proof")
			}
			after, readErr := os.ReadFile(path)
			if readErr != nil || !bytes.Equal(after, ready.document) {
				t.Fatal("failed sealing changed report", readErr)
			}
			owner, err := acquireFileOwnership(database + ".owner.lock")
			if err != nil {
				t.Fatal("failed sealing retained ownership", err)
			}
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
