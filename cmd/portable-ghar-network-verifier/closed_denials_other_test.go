//go:build !linux

package main

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/sumitake/portable-ghar/internal/linuxcap"
)

type countingClosedDenialsReader struct {
	reads int
}

func (reader *countingClosedDenialsReader) Read(
	_ []byte,
) (int, error) {
	reader.reads++
	return 0, io.EOF
}

func TestClosedDenialsNonLinuxFailsBeforeReadingInputOrCapabilities(
	t *testing.T,
) {
	reader := &countingClosedDenialsReader{}
	runtime := defaultVerifierRuntime()
	capabilityCalls := 0
	runtime.capabilities = func() (linuxcap.Wire, error) {
		capabilityCalls++
		return verifierEmptyCapabilities(), nil
	}
	var stdout, stderr bytes.Buffer
	code := run(
		context.Background(),
		[]string{"closed-denials"},
		reader,
		&stdout,
		&stderr,
		runtime,
	)
	if code != 1 ||
		reader.reads != 0 ||
		capabilityCalls != 0 ||
		stdout.Len() != 0 ||
		stderr.String() !=
			"portable-ghar-network-verifier: unavailable\n" {
		t.Fatalf(
			"code=%d reads=%d capabilities=%d stdout=%q stderr=%q",
			code,
			reader.reads,
			capabilityCalls,
			stdout.String(),
			stderr.String(),
		)
	}
}
