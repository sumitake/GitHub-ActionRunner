package main

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/failoverclient"
)

func TestWorkerCanaryCommandUsesOneClosedOperation(t *testing.T) {
	for _, test := range []struct {
		name         string
		args         []string
		root         bool
		operationErr error
		exit, calls  int
	}{
		{"stop", []string{"worker-canary", "--config=/private/overlay.json", "--command-file=/private/stop.json"}, true, nil, 0, 1},
		{"failure", []string{"worker-canary", "--config=/private/overlay.json", "--command-file=/private/stop.json"}, true, errors.New("private detail"), 1, 1},
		{"nonroot", []string{"worker-canary", "--config=/private/overlay.json", "--command-file=/private/stop.json"}, false, nil, 1, 0},
		{"missing config", []string{"worker-canary", "--command-file=/private/stop.json"}, true, nil, 2, 0},
		{"missing command", []string{"worker-canary", "--config=/private/overlay.json"}, true, nil, 2, 0},
		{"extra flag", []string{"worker-canary", "--config=/private/overlay.json", "--command-file=/private/stop.json", "--force=true"}, true, nil, 2, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			deps := productionCommandDependencies(time.Now)
			deps.IsRoot = func() bool { return test.root }
			calls := 0
			deps.WorkerCanary = func(_ context.Context, config, command string) (failoverclient.CanaryAdminReceipt, error) {
				calls++
				if config != "/private/overlay.json" || command != "/private/stop.json" {
					t.Fatal("paths changed")
				}
				return failoverclient.CanaryAdminReceipt{ProtocolVersion: 1, Kind: "portable-canary-stop", FleetID: "example-fleet", Status: "hosted"}, test.operationErr
			}
			var out, errout bytes.Buffer
			exit := runWithDependencies(context.Background(), test.args, &out, &errout, deps)
			if exit != test.exit || calls != test.calls {
				t.Fatalf("exit=%d calls=%d", exit, calls)
			}
			if bytes.Contains(errout.Bytes(), []byte("private detail")) {
				t.Fatal("private error leaked")
			}
			if test.exit == 0 && !bytes.Contains(out.Bytes(), []byte(`"status":"hosted"`)) {
				t.Fatal("missing verified receipt")
			}
			if test.exit != 0 && out.Len() != 0 {
				t.Fatal("failed operation emitted receipt")
			}
		})
	}
}

func TestWorkerCanaryRequiresConfiguredOperation(t *testing.T) {
	deps := productionCommandDependencies(time.Now)
	deps.WorkerCanary = nil
	var out, errout bytes.Buffer
	if runWithDependencies(context.Background(), []string{"worker-canary", "--config=/private/overlay.json", "--command-file=/private/stop.json"}, &out, &errout, deps) != 2 {
		t.Fatal("missing operation accepted")
	}
}

func TestWorkerCanaryPreservesCallerDeadlineAndCancellation(t *testing.T) {
	for _, name := range []string{"background", "later deadline", "earlier deadline", "canceled", "expired"} {
		t.Run(name, func(t *testing.T) {
			caller := context.Background()
			cancel := func() {}
			switch name {
			case "later deadline":
				caller, cancel = context.WithTimeout(caller, 5*time.Minute)
			case "earlier deadline":
				caller, cancel = context.WithTimeout(caller, 30*time.Second)
			case "canceled":
				caller, cancel = context.WithCancel(caller)
				cancel()
			case "expired":
				caller, cancel = context.WithDeadline(caller, time.Now().Add(-time.Second))
			}
			defer cancel()
			wantDeadline, wantBound := caller.Deadline()
			wantErr := caller.Err()
			deps := productionCommandDependencies(time.Now)
			deps.AdminTimeout = time.Minute
			deps.IsRoot = func() bool { return true }
			calls := 0
			deps.WorkerCanary = func(ctx context.Context, _, _ string) (failoverclient.CanaryAdminReceipt, error) {
				calls++
				deadline, bounded := ctx.Deadline()
				if bounded != wantBound || !deadline.Equal(wantDeadline) {
					t.Fatalf("Worker context deadline = %s (%t), caller deadline = %s (%t)", deadline, bounded, wantDeadline, wantBound)
				}
				if !errors.Is(ctx.Err(), wantErr) {
					t.Fatalf("Worker context error = %v, want %v", ctx.Err(), wantErr)
				}
				return failoverclient.CanaryAdminReceipt{}, ctx.Err()
			}
			var out, errout bytes.Buffer
			exit := runWithDependencies(caller, []string{"worker-canary", "--config=/private/overlay.json", "--command-file=/private/stop.json"}, &out, &errout, deps)
			wantExit := 0
			if wantErr != nil {
				wantExit = 1
			}
			if exit != wantExit || calls != 1 {
				t.Fatalf("exit=%d calls=%d, want exit=%d and one call", exit, calls, wantExit)
			}
			if wantErr != nil && out.Len() != 0 {
				t.Fatal("canceled operation emitted a receipt")
			}
		})
	}
}
