// Command portable-ghar-network-helper is the only per-job process granted
// NET_ADMIN. It installs one canonical policy artifact, reads both tables back,
// reports a bounded proof, and exits before the broker listener is released.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/linuxcap"
)

const (
	iptablesRestorePath  = "/usr/sbin/iptables-restore"
	iptablesSavePath     = "/usr/sbin/iptables-save"
	ip6tablesRestorePath = "/usr/sbin/ip6tables-restore"
	ip6tablesSavePath    = "/usr/sbin/ip6tables-save"
	xtablesLockPath      = "/run/xtables.lock"
	maxSavedPolicyBytes  = 256 << 10
)

type policyFamily uint8

const (
	familyIPv4 policyFamily = iota + 1
	familyIPv6
)

func (family policyFamily) String() string {
	switch family {
	case familyIPv4:
		return "ipv4"
	case familyIPv6:
		return "ipv6"
	default:
		return ""
	}
}

type helperRuntime struct {
	ioTimeout    time.Duration
	xtablesLock  func() string
	capabilities func() (linuxcap.Wire, error)
	restore      func(context.Context, policyFamily, []byte) error
	save         func(context.Context, policyFamily) ([]byte, error)
	disableIPv6  func() error
}

type applicationProof struct {
	Version      uint8         `json:"version"`
	Digest       string        `json:"policy_digest"`
	IPv6Posture  string        `json:"ipv6_posture"`
	Capabilities linuxcap.Wire `json:"capabilities"`
}

func defaultHelperRuntime() helperRuntime {
	return helperRuntime{
		ioTimeout:    10 * time.Second,
		xtablesLock:  func() string { return os.Getenv("XTABLES_LOCKFILE") },
		capabilities: linuxcap.ReadSelf,
		restore:      restorePolicy,
		save:         savePolicy,
		disableIPv6:  disableIPv6,
	}
}

func run(
	args []string,
	stdin io.Reader,
	stdout,
	stderr io.Writer,
	runtime helperRuntime,
) int {
	if len(args) != 1 || args[0] != "apply" ||
		stdin == nil || stdout == nil || stderr == nil ||
		runtime.ioTimeout <= 0 ||
		runtime.xtablesLock == nil ||
		runtime.xtablesLock() != xtablesLockPath ||
		runtime.capabilities == nil ||
		runtime.restore == nil || runtime.save == nil ||
		runtime.disableIPv6 == nil {
		return unavailable(stderr)
	}
	capabilities, err := runtime.capabilities()
	if err != nil || linuxcap.ValidateNetAdmin(capabilities) != nil {
		return unavailable(stderr)
	}
	artifact, err := hostruntime.DecodePolicyArtifact(stdin)
	if err != nil {
		return unavailable(stderr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), runtime.ioTimeout)
	defer cancel()

	ipv4 := artifact.IPv4Program()
	defer zero(ipv4)
	if err := runtime.restore(ctx, familyIPv4, ipv4); err != nil {
		return unavailable(stderr)
	}
	readback, err := runtime.save(ctx, familyIPv4)
	if err != nil || !bytes.Equal(readback, ipv4) {
		zero(readback)
		return unavailable(stderr)
	}
	zero(readback)

	posture := ""
	switch artifact.IPv6Posture() {
	case hostruntime.PolicyIPv6DenyViaIP6Tables:
		ipv6 := artifact.IPv6Program()
		defer zero(ipv6)
		if err := runtime.restore(ctx, familyIPv6, ipv6); err != nil {
			return unavailable(stderr)
		}
		readback, err = runtime.save(ctx, familyIPv6)
		if err != nil || !bytes.Equal(readback, ipv6) {
			zero(readback)
			return unavailable(stderr)
		}
		zero(readback)
		posture = "deny-via-ip6tables"
	case hostruntime.PolicyIPv6KernelDisabled:
		if err := runtime.disableIPv6(); err != nil {
			return unavailable(stderr)
		}
		posture = "kernel-disabled"
	default:
		return unavailable(stderr)
	}

	document, err := json.Marshal(applicationProof{
		Version:      2,
		Digest:       artifact.Digest(),
		IPv6Posture:  posture,
		Capabilities: capabilities,
	})
	if err != nil {
		return unavailable(stderr)
	}
	document = append(document, '\n')
	if _, err := stdout.Write(document); err != nil {
		return unavailable(stderr)
	}
	return 0
}

func restorePolicy(
	ctx context.Context,
	family policyFamily,
	program []byte,
) error {
	path := iptablesRestorePath
	if family == familyIPv6 {
		path = ip6tablesRestorePath
	} else if family != familyIPv4 {
		return errors.New("network-helper: policy family invalid")
	}
	command := exec.CommandContext(ctx, path, "--wait", "2")
	command.Stdin = bytes.NewReader(program)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return errors.New("network-helper: restore failed")
	}
	return nil
}

func savePolicy(
	ctx context.Context,
	family policyFamily,
) ([]byte, error) {
	path := iptablesSavePath
	if family == familyIPv6 {
		path = ip6tablesSavePath
	} else if family != familyIPv4 {
		return nil, errors.New("network-helper: policy family invalid")
	}
	command := exec.CommandContext(ctx, path, "-t", "filter")
	command.Stderr = io.Discard
	pipe, err := command.StdoutPipe()
	if err != nil {
		return nil, errors.New("network-helper: save unavailable")
	}
	if err := command.Start(); err != nil {
		return nil, errors.New("network-helper: save failed")
	}
	document, readErr := io.ReadAll(io.LimitReader(pipe, maxSavedPolicyBytes+1))
	if readErr != nil || len(document) > maxSavedPolicyBytes {
		_ = command.Process.Kill()
		_ = command.Wait()
		zero(document)
		return nil, errors.New("network-helper: save output invalid")
	}
	if err := command.Wait(); err != nil {
		zero(document)
		return nil, errors.New("network-helper: save failed")
	}
	canonical, err := canonicalSavedPolicy(document)
	zero(document)
	if err != nil {
		return nil, err
	}
	return canonical, nil
}

func canonicalSavedPolicy(document []byte) ([]byte, error) {
	if len(document) == 0 || len(document) > maxSavedPolicyBytes ||
		bytes.IndexByte(document, 0) >= 0 ||
		bytes.Contains(document, []byte{'\r'}) ||
		document[len(document)-1] != '\n' {
		return nil, errors.New("network-helper: save output invalid")
	}
	lines := bytes.Split(document[:len(document)-1], []byte{'\n'})
	if len(lines) < 5 {
		return nil, errors.New("network-helper: save output invalid")
	}
	first := 0
	last := len(lines)
	if bytes.HasPrefix(lines[0], []byte("# Generated by iptables-save ")) {
		if len(lines) < 7 ||
			!bytes.HasPrefix(lines[len(lines)-1], []byte("# Completed on ")) ||
			!printableSaveComment(lines[0]) ||
			!printableSaveComment(lines[len(lines)-1]) {
			return nil, errors.New("network-helper: save wrapper invalid")
		}
		first++
		last--
	} else if bytes.HasPrefix(lines[len(lines)-1], []byte("#")) {
		return nil, errors.New("network-helper: save wrapper invalid")
	}
	body := lines[first:last]
	if len(body) < 5 ||
		!bytes.Equal(body[0], []byte("*filter")) ||
		!bytes.Equal(body[1], []byte(":INPUT DROP [0:0]")) ||
		!bytes.Equal(body[2], []byte(":FORWARD DROP [0:0]")) ||
		!bytes.Equal(body[3], []byte(":OUTPUT DROP [0:0]")) ||
		!bytes.Equal(body[len(body)-1], []byte("COMMIT")) {
		return nil, errors.New("network-helper: save table invalid")
	}
	for _, line := range body[4 : len(body)-1] {
		if len(line) == 0 || line[0] != '-' ||
			bytes.HasPrefix(line, []byte("#")) {
			return nil, errors.New("network-helper: save rule invalid")
		}
		for _, value := range line {
			if value < 0x20 || value > 0x7e {
				return nil, errors.New("network-helper: save rule invalid")
			}
		}
	}
	var canonical bytes.Buffer
	for _, line := range body {
		_, _ = canonical.Write(line)
		_ = canonical.WriteByte('\n')
	}
	return canonical.Bytes(), nil
}

func printableSaveComment(line []byte) bool {
	if len(line) == 0 || len(line) > 512 {
		return false
	}
	for _, value := range line {
		if value < 0x20 || value > 0x7e {
			return false
		}
	}
	return true
}

func disableIPv6() error {
	for _, path := range []string{
		"/proc/sys/net/ipv6/conf/all/disable_ipv6",
		"/proc/sys/net/ipv6/conf/default/disable_ipv6",
	} {
		if err := os.WriteFile(path, []byte("1"), 0o600); err != nil {
			return errors.New("network-helper: ipv6 posture unavailable")
		}
		value, err := os.ReadFile(path)
		if err != nil || (!bytes.Equal(value, []byte("1")) &&
			!bytes.Equal(value, []byte("1\n"))) {
			zero(value)
			return errors.New("network-helper: ipv6 posture unproven")
		}
		zero(value)
	}
	return nil
}

func unavailable(stderr io.Writer) int {
	if stderr != nil {
		_, _ = fmt.Fprintln(stderr, "portable-ghar-network-helper: unavailable")
	}
	return 1
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func main() {
	os.Exit(run(
		os.Args[1:],
		os.Stdin,
		os.Stdout,
		os.Stderr,
		defaultHelperRuntime(),
	))
}
