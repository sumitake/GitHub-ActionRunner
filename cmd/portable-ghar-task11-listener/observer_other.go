//go:build !linux

package main

func newSystemObserver() (listenerObserver, error) {
	return nil, errListenerObservation
}
