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

var imageEnvironment = []string{Home, Language, Path}

// Image returns the complete image-config environment in canonical order.
func Image() []string {
	return slices.Clone(imageEnvironment)
}

// Listener returns a new exact listener bootstrap environment. The caller
// remains responsible for validating and destroying the JIT bytes.
func Listener(jit string) []string {
	environment := make([]string, 0, len(imageEnvironment)+1)
	environment = append(environment, imageEnvironment...)
	return append(environment, JITName+jit)
}

// MatchesImage accepts Docker's order-insensitive rendering only when every
// exact fixed entry appears once and no other entry exists.
func MatchesImage(environment []string) bool {
	if len(environment) != len(imageEnvironment) {
		return false
	}
	seen := make(map[string]struct{}, len(environment))
	for _, entry := range environment {
		switch entry {
		case Home, Language, Path:
		default:
			return false
		}
		if _, duplicate := seen[entry]; duplicate {
			return false
		}
		seen[entry] = struct{}{}
	}
	return len(seen) == len(imageEnvironment)
}

// MatchesListener accepts only the exact ordered image environment followed by
// one nonempty, NUL-free JIT entry. Order is load-bearing at the exec boundary.
func MatchesListener(environment []string) bool {
	return len(environment) == len(imageEnvironment)+1 &&
		slices.Equal(environment[:len(imageEnvironment)], imageEnvironment) &&
		strings.HasPrefix(environment[len(imageEnvironment)], JITName) &&
		len(environment[len(imageEnvironment)]) > len(JITName) &&
		!strings.ContainsRune(environment[len(imageEnvironment)], 0)
}
