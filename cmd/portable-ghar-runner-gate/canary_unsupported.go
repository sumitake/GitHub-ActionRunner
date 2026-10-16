//go:build !linux

package main

import "github.com/sumitake/portable-ghar/internal/canary"

func defaultCanaryProbe() (canary.Probe, error) { return canary.Probe{}, canary.ErrEvidence }
