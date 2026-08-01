//go:build !linux

package main

func defaultRunnerConformance() (runnerConformanceWire, error) {
	return runnerConformanceWire{}, errRunnerConformance
}
