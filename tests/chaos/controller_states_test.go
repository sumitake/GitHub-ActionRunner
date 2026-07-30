//go:build chaos

package chaos_test

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

const unsupportedHostSkip = "SKIP unsupported host profile"

type chaosHost struct {
	dockerPath string
}

func requireChaosHost(t *testing.T) chaosHost {
	t.Helper()
	if runtime.GOOS != "linux" || os.Getenv("PGHAR_CHAOS_DOCKER") != "1" {
		t.Skip(unsupportedHostSkip)
	}

	dockerPath := os.Getenv("PGHAR_CHAOS_DOCKER_PATH")
	if dockerPath == "" {
		var err error
		dockerPath, err = exec.LookPath("docker")
		if err != nil {
			t.Skip(unsupportedHostSkip)
		}
	}
	if !filepath.IsAbs(dockerPath) || filepath.Clean(dockerPath) != dockerPath {
		t.Fatal("chaos: Docker path must be canonical and absolute")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := hostruntime.NewExecCommandRunner().Run(
		ctx,
		[]string{dockerPath, "info", "--format", "{{json .ServerVersion}}"},
		nil,
		nil,
	)
	if err != nil || result.ExitCode != 0 || result.StdoutTruncated ||
		len(strings.TrimSpace(string(result.Stdout))) < 3 {
		t.Skip(unsupportedHostSkip)
	}
	return chaosHost{dockerPath: dockerPath}
}

func TestChaosSourceOptInBoundary(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("chaos: source location unavailable")
	}
	directory := filepath.Dir(current)
	expected := []string{
		"controller_states_test.go",
		"docker_failure_test.go",
		"fleet_fence_test.go",
		"jail_failure_test.go",
		"qts_install_test.go",
	}
	for _, name := range expected {
		path := filepath.Join(directory, name)
		document, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("chaos: read %s: %v", name, err)
		}
		if !strings.HasPrefix(string(document), "//go:build chaos\n") {
			t.Fatalf("chaos: %s is not protected by the chaos build tag", name)
		}
		file, err := parser.ParseFile(
			token.NewFileSet(),
			path,
			document,
			0,
		)
		if err != nil {
			t.Fatalf("chaos: parse %s: %v", name, err)
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil ||
				!strings.HasPrefix(function.Name.Name, "Test") ||
				function.Name.Name == "TestChaosSourceOptInBoundary" {
				continue
			}
			gated := false
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				identifier, ok := call.Fun.(*ast.Ident)
				if ok && identifier.Name == "requireChaosHost" {
					gated = true
				}
				return true
			})
			if !gated {
				t.Fatalf(
					"chaos: executable test %s in %s bypasses requireChaosHost",
					function.Name.Name,
					name,
				)
			}
		}
	}
	t.Log("SOURCE-ONLY: operational chaos execution remains separately gated")
}

func TestChaosOperationalGate(t *testing.T) {
	host := requireChaosHost(t)
	if host.dockerPath == "" {
		t.Fatal("chaos: supported host produced no Docker authority")
	}
}

func TestControllerStateRestartTable(t *testing.T) {
	_ = requireChaosHost(t)

	states := []controller.State{
		controller.StateReceived,
		controller.StateCapacityReserved,
		controller.StateAdapterCreated,
		controller.StateAdapterVerified,
		controller.StateBrokerHeld,
		controller.StateBrokerPolicyApplied,
		controller.StateDialAuthorityReady,
		controller.StateBrokerReleased,
		controller.StateEgressVerified,
		controller.StateRunnerHeld,
		controller.StateReleaseArmed,
		controller.StateListenerReleased,
		controller.StateJobRunning,
		controller.StateJobFinished,
		controller.StateDestroyed,
	}
	for index, current := range states {
		t.Run(string(current), func(t *testing.T) {
			released := index >= 11
			if err := controller.Transition(current, current, released); err != nil {
				t.Fatalf("restart replay %q: %v", current, err)
			}
			if index+1 == len(states) {
				return
			}
			next := states[index+1]
			if err := controller.Transition(
				current,
				next,
				index+1 >= 11,
			); err != nil {
				t.Fatalf("adjacent transition %q -> %q: %v", current, next, err)
			}
			if index+2 < len(states) && states[index+2] != controller.StateDestroyed {
				if err := controller.Transition(
					current,
					states[index+2],
					released,
				); err == nil {
					t.Fatalf("restart skipped %q -> %q", current, states[index+2])
				}
			}
		})
	}
	if err := controller.Transition(
		controller.StateListenerReleased,
		controller.StateDestroyed,
		true,
	); err == nil {
		t.Fatal("post-release ambiguity permitted blind destroy")
	}
}
