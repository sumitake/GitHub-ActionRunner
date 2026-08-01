//go:build linux

package main

import (
	"encoding/json"
	"errors"

	"golang.org/x/sys/unix"
)

func currentNetworkNamespace() ([]byte, error) {
	var stat unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &stat); err != nil ||
		uint64(stat.Dev) == 0 || stat.Ino == 0 {
		return nil, errors.New("network-adapter: namespace unavailable")
	}
	document, err := json.Marshal(struct {
		Version uint8  `json:"version"`
		Device  uint64 `json:"device"`
		Inode   uint64 `json:"inode"`
	}{Version: 1, Device: uint64(stat.Dev), Inode: stat.Ino})
	if err != nil {
		return nil, errors.New("network-adapter: namespace encoding failed")
	}
	return append(document, '\n'), nil
}
