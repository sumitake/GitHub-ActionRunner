// Package runtimeenv owns the closed nonsecret environment shared by the
// immutable runner image, host-runtime audit, and listener exec boundary.
package runtimeenv

import (
	"slices"
	"strings"
)

const (
	Home     = "HOME=/runner"
	Language = "LANG=C.UTF-8"
	Path     = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	JITName  = "ACTIONS_RUNNER_INPUT_JITCONFIG="
)

var (
	imageEnvironment = []string{Home, Language, Path}
	proxyEnvironment = func() []string {
		loopback := strings.Join([]string{"127", "0", "0", "1"}, ".")
		ipv6Loopback := strings.Join([]string{"", "", "1"}, ":")
		proxyURL := "http://" + loopback + ":18080"
		noProxy := loopback + "," + ipv6Loopback
		return []string{
			"HTTPS_PROXY=" + proxyURL,
			"https_proxy=" + proxyURL,
			"NO_PROXY=" + noProxy,
			"no_proxy=" + noProxy,
		}
	}()
	runtimeEnvironment = append(slices.Clone(imageEnvironment), proxyEnvironment...)
)

// Image returns the complete image-config environment in canonical order.
func Image() []string {
	return slices.Clone(imageEnvironment)
}

// Proxy returns the complete TLS-only loopback proxy environment in canonical
// order. Plaintext HTTP proxy variables are deliberately absent.
func Proxy() []string {
	return slices.Clone(proxyEnvironment)
}

// Runtime returns the complete held-runner environment in canonical order.
func Runtime() []string {
	return slices.Clone(runtimeEnvironment)
}

// Listener returns a new exact listener bootstrap environment. The caller
// remains responsible for validating and destroying the JIT bytes.
func Listener(jit string) []string {
	environment := make([]string, 0, len(runtimeEnvironment)+1)
	environment = append(environment, runtimeEnvironment...)
	return append(environment, JITName+jit)
}

// MatchesImage accepts Docker's order-insensitive rendering only when every
// exact fixed entry appears once and no other entry exists.
func MatchesImage(environment []string) bool {
	return matchesExactSet(environment, imageEnvironment)
}

// MatchesRuntime accepts Docker's order-insensitive rendering only when the
// complete image-plus-proxy environment appears exactly once and nothing else
// exists.
func MatchesRuntime(environment []string) bool {
	return matchesExactSet(environment, runtimeEnvironment)
}

func matchesExactSet(environment, allowedEnvironment []string) bool {
	if len(environment) != len(allowedEnvironment) {
		return false
	}
	seen := make(map[string]struct{}, len(environment))
	for _, entry := range environment {
		if !slices.Contains(allowedEnvironment, entry) {
			return false
		}
		if _, duplicate := seen[entry]; duplicate {
			return false
		}
		seen[entry] = struct{}{}
	}
	return len(seen) == len(allowedEnvironment)
}

// MatchesListener accepts only the exact ordered runtime environment followed
// by one nonempty, NUL-free JIT entry. Order is load-bearing at the exec
// boundary.
func MatchesListener(environment []string) bool {
	return len(environment) == len(runtimeEnvironment)+1 &&
		slices.Equal(environment[:len(runtimeEnvironment)], runtimeEnvironment) &&
		strings.HasPrefix(environment[len(runtimeEnvironment)], JITName) &&
		len(environment[len(runtimeEnvironment)]) > len(JITName) &&
		!strings.ContainsRune(environment[len(runtimeEnvironment)], 0)
}
