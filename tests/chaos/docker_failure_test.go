//go:build chaos

package chaos_test

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

var chaosContainerSequence atomic.Uint64

func TestDockerComponentFailureCleanup(t *testing.T) {
	host := requireChaosHost(t)
	imageID := requireChaosImage(t, host)

	for _, role := range []string{
		"adapter",
		"held-broker",
		"helper",
		"verifier",
		"listener",
	} {
		t.Run(role, func(t *testing.T) {
			name := fmt.Sprintf(
				"pghar-chaos-%d-%d",
				os.Getpid(),
				chaosContainerSequence.Add(1),
			)
			removeChaosContainer(t, host, name)
			t.Cleanup(func() {
				removeChaosContainer(t, host, name)
			})

			startChaosContainer(t, host, imageID, name, role)
			assertOneChaosContainer(t, host, name)
			assertSingleRunnerPayload(t, host, name)

			mustDocker(t, host, "exec", name, "/bin/mkdir", "-p",
				"/runner/_work/_update")
			mustDocker(t, host, "kill", "--signal", "KILL", name)
			mustDocker(t, host, "start", name)
			assertOneChaosContainer(t, host, name)
			removeChaosContainer(t, host, name)
			assertChaosContainerAbsent(t, host, name)

			startChaosContainer(t, host, imageID, name, role)
			mustDocker(t, host, "exec", name, "/usr/bin/test", "!", "-e",
				"/runner/_work/_update")
			assertSingleRunnerPayload(t, host, name)
			removeChaosContainer(t, host, name)
			assertChaosContainerAbsent(t, host, name)
		})
	}
}

func requireChaosImage(t *testing.T, host chaosHost) string {
	t.Helper()
	image := os.Getenv("PGHAR_CHAOS_IMAGE")
	if image == "" || strings.ContainsAny(image, " \t\r\n\x00") {
		t.Fatal("chaos: PGHAR_CHAOS_IMAGE must name one preloaded immutable runner image")
	}
	result := mustDocker(t, host, "image", "inspect", "--format", "{{.Id}}", image)
	imageID := strings.TrimSpace(string(result.Stdout))
	if !validDockerDigest(imageID) {
		t.Fatalf("chaos: image identity is not an immutable sha256 digest: %q", imageID)
	}
	return imageID
}

func validDockerDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != 71 {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func startChaosContainer(
	t *testing.T,
	host chaosHost,
	imageID string,
	name string,
	role string,
) {
	t.Helper()
	mustDocker(
		t,
		host,
		"run",
		"--detach",
		"--pull",
		"never",
		"--name",
		name,
		"--label",
		"portable-ghar.chaos.run="+name,
		"--label",
		"portable-ghar.chaos.role="+role,
		"--network",
		"none",
		"--read-only",
		"--cap-drop",
		"ALL",
		"--security-opt",
		"no-new-privileges:true",
		"--restart",
		"no",
		"--pids-limit",
		"64",
		"--memory",
		"128m",
		"--tmpfs",
		"/runner:rw,nosuid,nodev,size=67108864,mode=0700,uid=65532,gid=65532",
		"--tmpfs",
		"/tmp:rw,nosuid,nodev,size=16777216,mode=0700,uid=65532,gid=65532",
		"--entrypoint",
		"/bin/sleep",
		imageID,
		"300",
	)
}

func assertSingleRunnerPayload(t *testing.T, host chaosHost, name string) {
	t.Helper()
	result := mustDocker(
		t,
		host,
		"exec",
		name,
		"/usr/bin/find",
		"/opt/actions-runner",
		"-mindepth",
		"1",
		"-maxdepth",
		"1",
		"-type",
		"d",
		"-print",
	)
	var payload []string
	for _, line := range strings.Split(
		strings.TrimSpace(string(result.Stdout)),
		"\n",
	) {
		base := line
		if slash := strings.LastIndexByte(line, '/'); slash >= 0 {
			base = line[slash+1:]
		}
		if strings.HasPrefix(base, "bin") ||
			strings.HasPrefix(base, "externals") {
			payload = append(payload, base)
		}
	}
	sort.Strings(payload)
	if strings.Join(payload, ",") != "bin,externals" {
		t.Fatalf("chaos: runner payload directories = %v, want [bin externals]", payload)
	}
}

func assertOneChaosContainer(t *testing.T, host chaosHost, name string) {
	t.Helper()
	result := mustDocker(
		t,
		host,
		"ps",
		"--all",
		"--quiet",
		"--filter",
		"label=portable-ghar.chaos.run="+name,
	)
	lines := nonemptyLines(result.Stdout)
	if len(lines) != 1 {
		t.Fatalf("chaos: exact component count = %d, want 1", len(lines))
	}
}

func assertChaosContainerAbsent(t *testing.T, host chaosHost, name string) {
	t.Helper()
	result := mustDocker(
		t,
		host,
		"ps",
		"--all",
		"--quiet",
		"--filter",
		"label=portable-ghar.chaos.run="+name,
	)
	if lines := nonemptyLines(result.Stdout); len(lines) != 0 {
		t.Fatalf("chaos: retained component identities = %v", lines)
	}
}

func nonemptyLines(document []byte) []string {
	var result []string
	for _, line := range strings.Split(strings.TrimSpace(string(document)), "\n") {
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

func removeChaosContainer(t *testing.T, host chaosHost, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := hostruntime.NewExecCommandRunner().Run(
		ctx,
		[]string{host.dockerPath, "rm", "--force", name},
		nil,
		nil,
	)
	if err != nil {
		t.Errorf("chaos: cleanup command failed")
		return
	}
	if result.ExitCode != 0 && result.ExitCode != 1 {
		t.Errorf("chaos: cleanup exit code = %d", result.ExitCode)
	}
}

func mustDocker(
	t *testing.T,
	host chaosHost,
	arguments ...string,
) hostruntime.Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	argv := append([]string{host.dockerPath}, arguments...)
	result, err := hostruntime.NewExecCommandRunner().Run(ctx, argv, nil, nil)
	if err != nil {
		t.Fatalf("chaos: Docker command failed")
	}
	if result.ExitCode != 0 ||
		result.StdoutTruncated ||
		result.StderrTruncated {
		t.Fatalf(
			"chaos: Docker command exit=%d stdout_truncated=%t stderr_truncated=%t",
			result.ExitCode,
			result.StdoutTruncated,
			result.StderrTruncated,
		)
	}
	return result
}
