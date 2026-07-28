package runtimeenv

import (
	"slices"
	"testing"
)

func TestClosedRuntimeEnvironmentsAreExactAndCloned(t *testing.T) {
	image := Image()
	if !slices.Equal(image, []string{Home, Language, Path}) || !MatchesImage(image) {
		t.Fatalf("Image=%q", image)
	}
	image[0] = "HOME=/poison"
	if !slices.Equal(Image(), []string{Home, Language, Path}) {
		t.Fatal("Image returned shared mutable state")
	}

	listener := Listener("opaque-jit")
	if !slices.Equal(listener, []string{Home, Language, Path, JITName + "opaque-jit"}) ||
		!MatchesListener(listener) {
		t.Fatalf("Listener=%q", listener)
	}
	listener[3] = JITName + "poison"
	if got := Listener("opaque-jit"); got[3] != JITName+"opaque-jit" {
		t.Fatal("Listener returned shared mutable state")
	}
}

func TestRuntimeEnvironmentMatchersRejectSupersetsDuplicatesAndReordering(t *testing.T) {
	for name, environment := range map[string][]string{
		"image superset":  append(Image(), "EXTRA=value"),
		"image duplicate": {Home, Language, Home},
		"listener empty":  Listener(""),
		"listener NUL":    Listener("bad\x00jit"),
		"listener extra":  append(Listener("jit"), "EXTRA=value"),
		"listener order":  {Language, Home, Path, JITName + "jit"},
	} {
		t.Run(name, func(t *testing.T) {
			if MatchesImage(environment) || MatchesListener(environment) {
				t.Fatalf("matcher accepted %q", environment)
			}
		})
	}
}
