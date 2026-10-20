// SPDX-License-Identifier: MPL-2.0
// Rebuild-only bootstrap: authenticate the original archive before reusing its
// prepared externals. This command cannot select a different runner digest.
package main

import (
	"fmt"
	"os"

	"github.com/sumitake/portable-ghar/internal/archive"
	"github.com/sumitake/portable-ghar/internal/buildinfo"
)

func main() {
	if len(os.Args) != 3 {
		fail()
	}
	_, err := archive.ExtractRunnerArchive(archive.RunnerExtractOptions{
		ArchivePath: os.Args[1], OutputDirectory: os.Args[2],
		ExpectedSHA256:     buildinfo.Pins().UpstreamRunner.LinuxX64SHA256,
		EvidenceGeneration: 1,
	})
	if err != nil {
		fail()
	}
}

func fail() { fmt.Fprintln(os.Stderr, "rebuild-runner: upstream archive unavailable"); os.Exit(1) }
