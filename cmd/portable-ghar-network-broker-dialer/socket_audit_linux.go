//go:build linux

package main

import (
	"errors"
	"io"
	"os"
)

const maxSocketTableBytes = 1 << 20

func inspectHeldInternetSockets() (heldSocketAuditReport, error) {
	paths := [...]string{
		"/proc/net/tcp",
		"/proc/net/tcp6",
		"/proc/net/udp",
		"/proc/net/udp6",
		"/proc/net/raw",
		"/proc/net/raw6",
	}
	var counts [len(paths)]uint64
	for index, path := range paths {
		document, err := readSocketTable(path)
		if err != nil {
			return heldSocketAuditReport{}, err
		}
		counts[index], err = countSocketRows(document)
		zero(document)
		if err != nil {
			return heldSocketAuditReport{}, err
		}
	}
	return heldSocketAuditReport{
		Version: 1,
		TCP4:    counts[0],
		TCP6:    counts[1],
		UDP4:    counts[2],
		UDP6:    counts[3],
		Raw4:    counts[4],
		Raw6:    counts[5],
	}, nil
}

func readSocketTable(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("broker-dialer: socket table unavailable")
	}
	document, readErr := io.ReadAll(
		io.LimitReader(file, maxSocketTableBytes+1),
	)
	closeErr := file.Close()
	if readErr != nil ||
		closeErr != nil ||
		len(document) > maxSocketTableBytes {
		zero(document)
		return nil, errors.New("broker-dialer: socket table unavailable")
	}
	return document, nil
}
