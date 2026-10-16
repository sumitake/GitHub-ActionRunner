package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/canary"
)

func TestCanaryReadCommandEmitsOnlyClosedProbeResponses(t *testing.T) {
	var out, errout bytes.Buffer
	runtime := gateRuntime{readCanary: func() (canary.Probe, error) { return canary.Probe{Version: 1, Pending: true}, nil }}
	if code := run([]string{"canary-read"}, strings.NewReader(""), &out, &errout, runtime); code != 0 {
		t.Fatalf("command failed: %d %s", code, errout.String())
	}
	if probe, err := canary.ParseProbe(bytes.TrimSuffix(out.Bytes(), []byte{'\n'})); err != nil || !probe.Pending {
		t.Fatal("missing canonical pending receipt")
	}
	for _, change := range []func(*gateRuntime){
		func(r *gateRuntime) { r.readCanary = nil },
		func(r *gateRuntime) {
			r.readCanary = func() (canary.Probe, error) { return canary.Probe{}, errors.New("private diagnostic") }
		},
		func(r *gateRuntime) { r.readCanary = func() (canary.Probe, error) { return canary.Probe{}, nil } },
	} {
		r := runtime
		change(&r)
		out.Reset()
		errout.Reset()
		if code := run([]string{"canary-read"}, strings.NewReader(""), &out, &errout, r); code != 1 || out.Len() != 0 || strings.Contains(errout.String(), "private diagnostic") {
			t.Fatal("invalid/error response accepted or exposed")
		}
	}
	out.Reset()
	errout.Reset()
	if code := run([]string{"canary-read"}, strings.NewReader("unexpected"), &out, &errout, runtime); code != 1 {
		t.Fatal("canary probe accepted caller-supplied input")
	}
}
