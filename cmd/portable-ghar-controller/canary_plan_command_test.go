package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCanaryPlanCommandIsBoundedRootOnlyAndDoesNotExposeErrors(t *testing.T) {
	deps := productionCommandDependencies(time.Now)
	deps.IsRoot = func() bool { return true }
	called := false
	deps.CanaryPlan = func(ctx context.Context, config, scale string) (canaryPlanReceipt, error) {
		called = true
		if _, ok := ctx.Deadline(); !ok || config != "/example/config.json" || scale != "example-canary" {
			t.Fatal("unbounded or misdirected plan")
		}
		return canaryPlanReceipt{SchemaVersion: 1, LeaseGeneration: 9}, nil
	}
	args := []string{"canary-plan", "--config=/example/config.json", "--eligible-scale-set=example-canary"}
	var out, errout bytes.Buffer
	if code := runWithDependencies(context.Background(), args, &out, &errout, deps); code != 0 || !called || !strings.Contains(out.String(), `"lease_generation":9`) {
		t.Fatal("plan command unavailable", code, errout.String())
	}
	for _, bad := range [][]string{{"canary-plan"}, {"canary-plan", "--config=/example/config.json"},
		{"canary-plan", "--eligible-scale-set=example-canary"}, append(append([]string{}, args...), "--unknown=true"), append(append([]string{}, args...), "--config=/other/config.json")} {
		called = false
		out.Reset()
		errout.Reset()
		if code := runWithDependencies(context.Background(), bad, &out, &errout, deps); code != 2 || called {
			t.Fatal("malformed plan reached operation")
		}
	}
	called = false
	deps.IsRoot = func() bool { return false }
	out.Reset()
	errout.Reset()
	if code := runWithDependencies(context.Background(), args, &out, &errout, deps); code != 1 || called {
		t.Fatal("nonroot plan allowed")
	}
	deps.IsRoot = func() bool { return true }
	deps.CanaryPlan = func(context.Context, string, string) (canaryPlanReceipt, error) {
		return canaryPlanReceipt{}, errors.New("synthetic private diagnostic")
	}
	out.Reset()
	errout.Reset()
	if code := runWithDependencies(context.Background(), args, &out, &errout, deps); code != 1 || out.Len() != 0 || strings.Contains(errout.String(), "private diagnostic") {
		t.Fatal("plan error lost or exposed")
	}
	deps.CanaryPlan = nil
	out.Reset()
	errout.Reset()
	if code := runWithDependencies(context.Background(), args, &out, &errout, deps); code != 2 {
		t.Fatal("unavailable planner accepted")
	}
}
