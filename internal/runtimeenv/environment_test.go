package runtimeenv

import (
	"slices"
	"strings"
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

	loopback := strings.Join([]string{"127", "0", "0", "1"}, ".")
	ipv6Loopback := strings.Join([]string{"", "", "1"}, ":")
	proxyURL := "http://" + loopback + ":18080"
	noProxy := loopback + "," + ipv6Loopback
	wantProxy := []string{
		"HTTPS_PROXY=" + proxyURL,
		"https_proxy=" + proxyURL,
		"NO_PROXY=" + noProxy,
		"no_proxy=" + noProxy,
	}
	proxy := Proxy()
	if !slices.Equal(proxy, wantProxy) {
		t.Fatalf("Proxy=%q", proxy)
	}
	proxy[0] = "HTTPS_PROXY=http://" +
		strings.Join([]string{"127", "0", "0", "2"}, ".") + ":18080"
	if !slices.Equal(Proxy(), wantProxy) {
		t.Fatal("Proxy returned shared mutable state")
	}

	wantRuntime := append([]string{Home, Language, Path}, wantProxy...)
	runtime := Runtime()
	if !slices.Equal(runtime, wantRuntime) || !MatchesRuntime(runtime) {
		t.Fatalf("Runtime=%q", runtime)
	}
	runtime[0] = "HOME=/poison"
	if !slices.Equal(Runtime(), wantRuntime) {
		t.Fatal("Runtime returned shared mutable state")
	}

	listener := Listener("opaque-jit")
	if !slices.Equal(listener, append(wantRuntime, JITName+"opaque-jit")) ||
		!MatchesListener(listener) {
		t.Fatalf("Listener=%q", listener)
	}
	listener[len(listener)-1] = JITName + "poison"
	if got := Listener("opaque-jit"); got[len(got)-1] != JITName+"opaque-jit" {
		t.Fatal("Listener returned shared mutable state")
	}
}

func TestRuntimeEnvironmentMatchersRejectSupersetsDuplicatesAndReordering(t *testing.T) {
	runtime := Runtime()
	wrongLoopback := strings.Join([]string{"127", "0", "0", "2"}, ".")
	reorderedRuntime := []string{
		runtime[6], runtime[2], runtime[4], runtime[0], runtime[5], runtime[1], runtime[3],
	}
	if !MatchesRuntime(reorderedRuntime) {
		t.Fatalf("MatchesRuntime rejected order-independent exact set %q", reorderedRuntime)
	}

	for name, environment := range map[string][]string{
		"image superset":        append(Image(), "EXTRA=value"),
		"image duplicate":       {Home, Language, Home},
		"runtime image only":    Image(),
		"runtime missing":       runtime[:len(runtime)-1],
		"runtime duplicate":     append(slices.Clone(runtime[:len(runtime)-1]), runtime[0]),
		"runtime extra":         append(slices.Clone(runtime), "HTTP_PROXY="+strings.TrimPrefix(runtime[3], "HTTPS_PROXY=")),
		"runtime wrong proxy":   append(slices.Clone(runtime[:3]), "HTTPS_PROXY=http://"+wrongLoopback+":18080", runtime[4], runtime[5], runtime[6]),
		"listener empty":        Listener(""),
		"listener NUL":          Listener("bad\x00jit"),
		"listener extra":        append(Listener("jit"), "EXTRA=value"),
		"listener order":        append(reorderedRuntime, JITName+"jit"),
		"listener image only":   append(Image(), JITName+"jit"),
		"listener runtime only": Runtime(),
	} {
		t.Run(name, func(t *testing.T) {
			if strings.HasPrefix(name, "image ") {
				if MatchesImage(environment) {
					t.Fatalf("MatchesImage accepted %q", environment)
				}
				return
			}
			if strings.HasPrefix(name, "runtime ") {
				if MatchesRuntime(environment) {
					t.Fatalf("MatchesRuntime accepted %q", environment)
				}
				return
			}
			if MatchesListener(environment) {
				t.Fatalf("MatchesListener accepted %q", environment)
			}
		})
	}
}
