//go:build linux

package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/sumitake/portable-ghar/internal/networkjail"
	"golang.org/x/sys/unix"
)

func inspectCurrentNamespace() (networkjail.NamespaceSnapshot, error) {
	return inspectCurrentNamespaceTopology(true)
}

func inspectCurrentNamespaceTopology(
	requireEmptyConntrack bool,
) (networkjail.NamespaceSnapshot, error) {
	identity, err := inspectNamespaceIdentity()
	if err != nil {
		return networkjail.NamespaceSnapshot{}, err
	}
	devices, err := readVerifierProc("/proc/net/dev", 64<<10, false)
	if err != nil || !onlyLoopbackDevice(devices) {
		return networkjail.NamespaceSnapshot{},
			errors.New("network-verifier: network devices invalid")
	}
	ipv4Routes, err := readVerifierProc("/proc/net/route", 64<<10, false)
	if err != nil || !onlyLoopbackRoutes(ipv4Routes, 0) {
		return networkjail.NamespaceSnapshot{},
			errors.New("network-verifier: ipv4 routes invalid")
	}
	ipv6Routes, err := readVerifierProc("/proc/net/ipv6_route", 64<<10, true)
	if err != nil || !onlyLoopbackRoutes(ipv6Routes, -1) {
		return networkjail.NamespaceSnapshot{},
			errors.New("network-verifier: ipv6 routes invalid")
	}
	ipv4Tables, err := readVerifierProc(
		"/proc/net/ip_tables_names",
		4<<10,
		true,
	)
	if err != nil || len(bytes.TrimSpace(ipv4Tables)) != 0 {
		return networkjail.NamespaceSnapshot{},
			errors.New("network-verifier: ipv4 tables not empty")
	}
	ipv6Tables, err := readVerifierProc(
		"/proc/net/ip6_tables_names",
		4<<10,
		true,
	)
	if err != nil || len(bytes.TrimSpace(ipv6Tables)) != 0 {
		return networkjail.NamespaceSnapshot{},
			errors.New("network-verifier: ipv6 tables not empty")
	}
	if requireEmptyConntrack {
		conntrack, err := readVerifierProc(
			"/proc/net/nf_conntrack",
			1<<20,
			true,
		)
		if err != nil || len(bytes.TrimSpace(conntrack)) != 0 {
			return networkjail.NamespaceSnapshot{},
				errors.New(
					"network-verifier: namespace conntrack not empty",
				)
		}
	}
	return networkjail.NamespaceSnapshot{
		Identity:       identity,
		LoopbackOnly:   true,
		TablesEmpty:    true,
		ConntrackEmpty: requireEmptyConntrack,
	}, nil
}

func inspectNamespaceIdentity() (networkjail.NamespaceIdentity, error) {
	var namespace unix.Stat_t
	if unix.Stat("/proc/self/ns/net", &namespace) != nil ||
		namespace.Dev == 0 || namespace.Ino == 0 {
		return networkjail.NamespaceIdentity{},
			errors.New("network-verifier: namespace identity unavailable")
	}
	return networkjail.NamespaceIdentity{
		Device: uint64(namespace.Dev),
		Inode:  namespace.Ino,
	}, nil
}

func readVerifierProc(
	path string,
	maximum int64,
	allowMissing bool,
) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		if allowMissing && errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(data)) > maximum {
		zero(data)
		return nil, errors.New("network-verifier: proc input invalid")
	}
	return data, nil
}

func onlyLoopbackDevice(data []byte) bool {
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 3 {
		return false
	}
	seen := false
	for _, line := range lines[2:] {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] != "lo:" {
			return false
		}
		seen = true
	}
	return seen
}

func onlyLoopbackRoutes(data []byte, interfaceField int) bool {
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for index, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if interfaceField == 0 && index == 0 && fields[0] == "Iface" {
			continue
		}
		field := interfaceField
		if field < 0 {
			field = len(fields) - 1
		}
		if field >= len(fields) || fields[field] != "lo" {
			return false
		}
	}
	return true
}
