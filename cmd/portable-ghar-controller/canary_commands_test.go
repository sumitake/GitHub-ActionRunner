package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCanaryCommandsUseBoundedRootOnlyOperations(t *testing.T) {
	for _, command := range []string{"canary-status", "canary-seal"} {
		t.Run(command, func(t *testing.T) {
			deps := productionCommandDependencies(time.Now)
			deps.IsRoot = func() bool { return true }
			var called string
			check := func(ctx context.Context, path string) {
				t.Helper()
				if _, ok := ctx.Deadline(); !ok || path != "/example/config.json" {
					t.Fatal("unbounded or wrongly configured canary operation")
				}
			}
			deps.CanaryStatus = func(ctx context.Context, path string) (canaryStatusReceipt, error) {
				check(ctx, path)
				called = "canary-status"
				return canaryStatusReceipt{SchemaVersion: 1, ReadyToSeal: true}, nil
			}
			deps.CanarySeal = func(ctx context.Context, path string) (canarySealReceipt, error) {
				check(ctx, path)
				called = "canary-seal"
				return canarySealReceipt{SchemaVersion: 1}, nil
			}
			var out, errout bytes.Buffer
			if code := runWithDependencies(context.Background(), []string{command, "--config=/example/config.json"}, &out, &errout, deps); code != 0 || called != command {
				t.Fatalf("command: %d %s %s", code, called, errout.String())
			}
			var result map[string]any
			if json.Unmarshal(out.Bytes(), &result) != nil || result["schema_version"] != float64(1) {
				t.Fatal("missing structured receipt")
			}
			called = ""
			deps.IsRoot = func() bool { return false }
			out.Reset()
			errout.Reset()
			if code := runWithDependencies(context.Background(), []string{command, "--config=/example/config.json"}, &out, &errout, deps); code != 1 || called != "" {
				t.Fatal("non-root canary operation allowed")
			}
		})
	}
}

func TestCanaryCommandsRefuseMalformedFlagsOrUnavailableOperations(t *testing.T) {
	for _, command := range []string{"canary-status", "canary-seal"} {
		for _, flags := range [][]string{nil, {"--config=/example/config.json", "--extra"}, {"--config=/example/config.json"}} {
			deps := productionCommandDependencies(time.Now)
			deps.IsRoot = func() bool { return true }
			deps.CanaryStatus = nil
			deps.CanarySeal = nil
			if len(flags) != 1 {
				deps.CanaryStatus = func(context.Context, string) (canaryStatusReceipt, error) {
					return canaryStatusReceipt{SchemaVersion: 1}, nil
				}
				deps.CanarySeal = func(context.Context, string) (canarySealReceipt, error) {
					return canarySealReceipt{SchemaVersion: 1}, nil
				}
			}
			var out, errout bytes.Buffer
			if code := runWithDependencies(context.Background(), append([]string{command}, flags...), &out, &errout, deps); code != 2 {
				t.Fatal("malformed/unavailable operation accepted")
			}
		}
	}
}

func TestCanaryCommandErrorsDoNotExposePrivateDiagnostics(t *testing.T) {
	for _, command := range []string{"canary-status", "canary-seal"} {
		deps := productionCommandDependencies(time.Now)
		deps.IsRoot = func() bool { return true }
		deps.CanaryStatus = func(context.Context, string) (canaryStatusReceipt, error) {
			return canaryStatusReceipt{}, errors.New("private diagnostic")
		}
		deps.CanarySeal = func(context.Context, string) (canarySealReceipt, error) {
			return canarySealReceipt{}, errors.New("private diagnostic")
		}
		var out, errout bytes.Buffer
		if code := runWithDependencies(context.Background(), []string{command, "--config=/example/config.json"}, &out, &errout, deps); code != 1 || out.Len() != 0 || strings.Contains(errout.String(), "private diagnostic") {
			t.Fatal("operation failure ignored or private diagnostic exposed")
		}
	}
}

func TestCanaryStatusDistinguishesIncompleteReadyAndAlreadySealed(t *testing.T) {
	report := pendingCanaryFixture(t)
	record := readyCanaryFixture(report)
	ready := buildCanaryStatus(report, record)
	if !ready.ReadyToSeal || ready.Revision != record.Workflow.Revision || ready.PolicyDigest != record.PolicyDigest || ready.FleetGeneration != report.Binding().FleetGeneration() || !ready.ListenerProcReadable || !ready.DecodedCredentialsReadable {
		t.Fatal("ready observations were not reported")
	}
	record.Finalized = false
	if buildCanaryStatus(report, record).ReadyToSeal {
		t.Fatal("incomplete observations ready to seal")
	}
	full, err := completeCanaryReport(report, readyCanaryFixture(report))
	if err != nil {
		t.Fatal(err)
	}
	if buildCanaryStatus(full, readyCanaryFixture(full)).ReadyToSeal {
		t.Fatal("already completed report ready to seal")
	}
}

func TestReadOnlyRuntimeValidationPreservesExclusiveRunOwnership(t *testing.T) {
	var nilContext context.Context
	for _, ctx := range []context.Context{nilContext, context.Background()} {
		if _, err := readProductionRuntime(ctx, "relative", "/example/controller.db"); err == nil {
			t.Fatal("invalid read-only runtime accepted")
		}
	}
	lease := &testOwnershipLease{validateErr: errors.New("injected")}
	if _, err := loadProductionRuntime(context.Background(), "/example/config.json", "/example/controller.db", lease); err == nil {
		t.Fatal("invalid ownership accepted")
	}
	validateCalls, _ := lease.Counts()
	if validateCalls != 1 {
		t.Fatal("run bypassed its ownership validation")
	}
	if _, err := loadProductionRuntime(context.Background(), "/example/config.json", "/example/controller.db", nil); err == nil {
		t.Fatal("run without ownership accepted")
	}
}
