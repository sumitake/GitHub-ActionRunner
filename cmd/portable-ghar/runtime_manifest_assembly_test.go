package main

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/cli"
)

func TestRuntimeManifestAssemblyCommand(t *testing.T) {
	args := []string{"assemble-runtime-manifest", "--template", "/private/template.json", "--fleet-generation", "8", "--output", "/private/runtime-manifest.json"}
	for _, test := range []struct {
		name       string
		err        error
		exit       int
		diagnostic string
	}{
		{"success", nil, 0, ""},
		{"usage", cli.ErrHostUsage, 2, "usage:"},
		{"failure", errors.New("private detail"), 1, "portable-ghar: runtime manifest assembly failed\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			calls := 0
			deps := commandDependencies{RunAssembleRuntimeManifest: func(ctx context.Context, got []string) (cli.RuntimeManifestAssemblyReceipt, error) {
				calls++
				if ctx == nil || !reflect.DeepEqual(got, args) {
					t.Fatal("arguments changed")
				}
				return cli.RuntimeManifestAssemblyReceipt{SchemaVersion: 1, RuntimeManifestDigest: strings.Repeat("a", 64), FleetGeneration: 8}, test.err
			}}
			exit := run(context.Background(), args, bytes.NewReader(nil), &stdout, &stderr, false, deps)
			if exit != test.exit || calls != 1 || !strings.HasPrefix(stderr.String(), test.diagnostic) {
				t.Fatalf("exit=%d calls=%d diagnostic=%q", exit, calls, stderr.String())
			}
			if test.exit == 0 && stdout.String() != `{"schema_version":1,"runtime_manifest_digest":"`+strings.Repeat("a", 64)+`","fleet_generation":8}`+"\n" {
				t.Fatalf("receipt: %q", stdout.String())
			}
			if test.exit != 0 && stdout.Len() != 0 {
				t.Fatal("failed command emitted receipt")
			}
			if strings.Contains(stderr.String(), "private detail") {
				t.Fatal("private error escaped")
			}
		})
	}
	var stdout, stderr bytes.Buffer
	if run(context.Background(), args, bytes.NewReader(nil), &stdout, &stderr, false, commandDependencies{}) != 2 {
		t.Fatal("nil assembler accepted")
	}
}

func TestRuntimeManifestAssemblyProductionRejectsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, value := range []context.Context{nil, ctx} {
		_, err := productionCommandDependencies().RunAssembleRuntimeManifest(value, nil)
		if !errors.Is(err, cli.ErrHostCommandFailed) {
			t.Fatalf("context: %v", err)
		}
	}
}
