package main

import (
	"bytes"
	"errors"
	"strings"
)

type heldSocketAuditReport struct {
	Version uint8  `json:"version"`
	TCP4    uint64 `json:"tcp4"`
	TCP6    uint64 `json:"tcp6"`
	UDP4    uint64 `json:"udp4"`
	UDP6    uint64 `json:"udp6"`
	Raw4    uint64 `json:"raw4"`
	Raw6    uint64 `json:"raw6"`
}

func countSocketRows(document []byte) (uint64, error) {
	if len(document) == 0 ||
		document[len(document)-1] != '\n' ||
		bytes.IndexByte(document, 0) >= 0 ||
		bytes.Contains(document, []byte{'\r'}) {
		return 0, errors.New("broker-dialer: socket table invalid")
	}
	lines := strings.Split(string(document[:len(document)-1]), "\n")
	if len(lines) == 0 {
		return 0, errors.New("broker-dialer: socket table invalid")
	}
	header := strings.Fields(lines[0])
	if len(header) < 4 ||
		header[0] != "sl" ||
		header[1] != "local_address" ||
		header[2] != "rem_address" ||
		header[3] != "st" {
		return 0, errors.New("broker-dialer: socket table invalid")
	}
	var count uint64
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 10 ||
			!strings.HasSuffix(fields[0], ":") {
			return 0, errors.New("broker-dialer: socket row invalid")
		}
		count++
	}
	return count, nil
}
