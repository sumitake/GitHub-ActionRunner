//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func currentNetworkNamespace() ([]byte, error) {
	file, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return nil, errors.New("runner-gate: network namespace open failed")
	}
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(int(file.Fd()), &stat) != nil || uint64(stat.Dev) == 0 || stat.Ino == 0 {
		return nil, errors.New("runner-gate: network namespace identity invalid")
	}
	document, err := json.Marshal(struct {
		Version uint8  `json:"version"`
		Device  uint64 `json:"device"`
		Inode   uint64 `json:"inode"`
	}{Version: 1, Device: uint64(stat.Dev), Inode: stat.Ino})
	if err != nil {
		return nil, errors.New("runner-gate: network namespace encoding failed")
	}
	return append(document, '\n'), nil
}
