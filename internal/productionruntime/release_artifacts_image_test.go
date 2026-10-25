package productionruntime

import (
	"context"
	"encoding/json"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

// This opt-in development test executes the real production verifier against a
// builder-owned, already-loaded final image. Ordinary tests never start Docker.
func TestReleaseArtifactVerifierRealFinalImage(t *testing.T) {
	if os.Getenv("PGHAR_REAL_FINAL_IMAGE") != "1" {
		t.Skip("explicit disposable-builder image check only")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("Linux builder required")
	}
	docker := os.Getenv("PGHAR_FINAL_IMAGE_DOCKER")
	image := os.Getenv("PGHAR_FINAL_IMAGE_ID")
	verifier, err := NewReleaseArtifactVerifier(docker, hostruntime.NewExecCommandRunner())
	if err != nil {
		t.Fatal("invalid final-image command binding")
	}
	var overlay hostruntime.PrivateOverlay
	overlay.Commands.DockerBinary = docker
	overlay.Docker.RunnerImage = image
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	version, err := verifier.SmokeRunner(ctx, overlay)
	if err != nil {
		t.Fatal("real final-image production smoke failed")
	}
	receipt, err := json.Marshal(map[string]string{"image_id": image, "runner_version": version})
	if err != nil {
		t.Fatal("invalid final-image receipt")
	}
	t.Log("FINAL_IMAGE_SMOKE_RECEIPT=" + string(receipt))
}
