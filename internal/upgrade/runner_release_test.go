package upgrade

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestOfficialRunnerReleaseObserverHappyPath(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		mu.Lock()
		paths = append(paths, request.URL.EscapedPath())
		mu.Unlock()
		if request.Header.Get("Accept") != "application/vnd.github+json" ||
			request.Header.Get("X-GitHub-Api-Version") != "2022-11-28" ||
			request.Header.Get("User-Agent") !=
				"portable-ghar-runner-release-observer/1" {
			http.Error(writer, "bad headers", http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.EscapedPath() {
		case "/repos/actions/runner/releases/latest":
			_, _ = io.WriteString(writer, `{
				"tag_name":"v2.336.0",
				"draft":false,
				"prerelease":false,
				"published_at":"2026-07-29T12:00:00Z",
				"future_additive_field":{"ignored":true},
				"assets":[
					{"name":"actions-runner-linux-arm64-2.336.0.tar.gz","size":200,"digest":"sha256:`+strings.Repeat("1", 64)+`"},
					{"name":"actions-runner-linux-x64-2.336.0.tar.gz","size":224000000,"digest":"sha256:`+strings.Repeat("2", 64)+`","future_asset_field":"ignored"}
				]
			}`)
		case "/repos/actions/runner/git/ref/tags/v2.336.0":
			_, _ = io.WriteString(writer, `{
				"ref":"refs/tags/v2.336.0",
				"object":{"sha":"`+strings.Repeat("a", 40)+`","type":"tag","url":"ignored"},
				"future_ref_field":true
			}`)
		case "/repos/actions/runner/git/tags/" + strings.Repeat("a", 40):
			_, _ = io.WriteString(writer, `{
				"tag":"v2.336.0",
				"object":{"sha":"`+strings.Repeat("b", 40)+`","type":"commit"},
				"future_tag_field":false
			}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	observer := newTestReleaseObserver(t, server.URL, 1<<20)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	release, err := observer.Observe(ctx)
	if err != nil {
		t.Fatalf("Observe() error = %v", err)
	}
	if err := release.Validate(); err != nil {
		t.Fatalf("release Validate() error = %v", err)
	}
	if release.Version != "v2.336.0" ||
		release.TagRefSHA != strings.Repeat("a", 40) ||
		release.SourceCommitSHA != strings.Repeat("b", 40) ||
		release.LinuxX64AssetName !=
			"actions-runner-linux-x64-2.336.0.tar.gz" ||
		release.LinuxX64AssetSize != 224_000_000 ||
		release.LinuxX64AssetDigest !=
			"sha256:"+strings.Repeat("2", 64) ||
		release.PublishedAt != fixedModelTime() ||
		!validRawDigest(release.ObservationEvidence) {
		t.Fatalf("Observe() release = %#v", release)
	}
	mu.Lock()
	defer mu.Unlock()
	wantPaths := []string{
		"/repos/actions/runner/releases/latest",
		"/repos/actions/runner/git/ref/tags/v2.336.0",
		"/repos/actions/runner/git/tags/" + strings.Repeat("a", 40),
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("request paths = %q, want %q", paths, wantPaths)
	}
}

func TestOfficialRunnerReleaseObserverLightweightTag(t *testing.T) {
	t.Parallel()

	fixture := defaultReleaseFixture()
	fixture.refType = "commit"
	fixture.refSHA = strings.Repeat("b", 40)
	server := releaseFixtureServer(t, fixture)
	defer server.Close()
	observer := newTestReleaseObserver(t, server.URL, 1<<20)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	release, err := observer.Observe(ctx)
	if err != nil {
		t.Fatalf("Observe() error = %v", err)
	}
	if release.TagRefSHA != strings.Repeat("b", 40) ||
		release.SourceCommitSHA != release.TagRefSHA {
		t.Fatalf("lightweight release = %#v", release)
	}
}

func TestOfficialRunnerReleaseObserverRejectsInvalidRelease(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*releaseFixture)
	}{
		{name: "draft", mutate: func(value *releaseFixture) { value.draft = true }},
		{name: "prerelease", mutate: func(value *releaseFixture) { value.prerelease = true }},
		{name: "wrong tag", mutate: func(value *releaseFixture) { value.tag = "v2.336.0-rc.1" }},
		{name: "missing digest", mutate: func(value *releaseFixture) { value.assetDigest = "" }},
		{name: "uppercase digest", mutate: func(value *releaseFixture) { value.assetDigest = "sha256:" + strings.Repeat("A", 64) }},
		{name: "zero size", mutate: func(value *releaseFixture) { value.assetSize = 0 }},
		{name: "duplicate asset", mutate: func(value *releaseFixture) { value.duplicateAsset = true }},
		{name: "changed ref", mutate: func(value *releaseFixture) { value.refName = "refs/tags/v2.335.1" }},
		{name: "nested tag", mutate: func(value *releaseFixture) { value.peeledType = "tag" }},
		{name: "uppercase object", mutate: func(value *releaseFixture) { value.refSHA = strings.Repeat("A", 40) }},
		{name: "duplicate known field", mutate: func(value *releaseFixture) { value.duplicateTagField = true }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := defaultReleaseFixture()
			test.mutate(&fixture)
			server := releaseFixtureServer(t, fixture)
			defer server.Close()
			observer := newTestReleaseObserver(t, server.URL, 1<<20)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := observer.Observe(ctx); !errors.Is(err, ErrRunnerReleaseObservation) {
				t.Fatalf("Observe() error = %v, want ErrRunnerReleaseObservation", err)
			}
		})
	}
}

func TestOfficialRunnerReleaseObserverRequiresDeadline(t *testing.T) {
	t.Parallel()

	server := releaseFixtureServer(t, defaultReleaseFixture())
	defer server.Close()
	observer := newTestReleaseObserver(t, server.URL, 1<<20)
	if _, err := observer.Observe(context.Background()); !errors.Is(
		err,
		ErrRunnerReleaseObservation,
	) {
		t.Fatalf("Observe() error = %v, want ErrRunnerReleaseObservation", err)
	}
}

func TestOfficialRunnerReleaseObserverRejectsRedirectAndOversizedBody(t *testing.T) {
	t.Parallel()

	t.Run("redirect", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			http.Redirect(writer, request, "https://example.invalid/", http.StatusFound)
		}))
		defer server.Close()
		observer := newTestReleaseObserver(t, server.URL, 1<<20)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := observer.Observe(ctx); !errors.Is(err, ErrRunnerReleaseObservation) {
			t.Fatalf("Observe() error = %v, want ErrRunnerReleaseObservation", err)
		}
	})

	t.Run("oversized", func(t *testing.T) {
		t.Parallel()
		server := releaseFixtureServer(t, defaultReleaseFixture())
		defer server.Close()
		observer := newTestReleaseObserver(t, server.URL, 32)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := observer.Observe(ctx); !errors.Is(err, ErrRunnerReleaseObservation) {
			t.Fatalf("Observe() error = %v, want ErrRunnerReleaseObservation", err)
		}
	})
}

type releaseFixture struct {
	tag               string
	draft             bool
	prerelease        bool
	assetSize         int64
	assetDigest       string
	duplicateAsset    bool
	duplicateTagField bool
	refName           string
	refSHA            string
	refType           string
	peeledSHA         string
	peeledType        string
}

func defaultReleaseFixture() releaseFixture {
	return releaseFixture{
		tag:         "v2.336.0",
		assetSize:   224_000_000,
		assetDigest: "sha256:" + strings.Repeat("2", 64),
		refName:     "refs/tags/v2.336.0",
		refSHA:      strings.Repeat("a", 40),
		refType:     "tag",
		peeledSHA:   strings.Repeat("b", 40),
		peeledType:  "commit",
	}
}

func releaseFixtureServer(
	t *testing.T,
	fixture releaseFixture,
) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.EscapedPath() {
		case "/repos/actions/runner/releases/latest":
			assets := []map[string]any{{
				"name":   "actions-runner-linux-x64-2.336.0.tar.gz",
				"size":   fixture.assetSize,
				"digest": fixture.assetDigest,
			}}
			if fixture.duplicateAsset {
				assets = append(assets, assets[0])
			}
			var document strings.Builder
			document.WriteString(`{"tag_name":`)
			encodedTag, _ := json.Marshal(fixture.tag)
			document.Write(encodedTag)
			if fixture.duplicateTagField {
				document.WriteString(`,"tag_name":`)
				document.Write(encodedTag)
			}
			document.WriteString(`,"draft":`)
			document.WriteString(boolJSON(fixture.draft))
			document.WriteString(`,"prerelease":`)
			document.WriteString(boolJSON(fixture.prerelease))
			document.WriteString(`,"published_at":"2026-07-29T12:00:00Z","assets":`)
			encodedAssets, _ := json.Marshal(assets)
			document.Write(encodedAssets)
			document.WriteByte('}')
			_, _ = io.WriteString(writer, document.String())
		case "/repos/actions/runner/git/ref/tags/" +
			url.PathEscape(fixture.tag):
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"ref": fixture.refName,
				"object": map[string]any{
					"sha":  fixture.refSHA,
					"type": fixture.refType,
				},
			})
		case "/repos/actions/runner/git/tags/" + fixture.refSHA:
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"tag": fixture.tag,
				"object": map[string]any{
					"sha":  fixture.peeledSHA,
					"type": fixture.peeledType,
				},
			})
		default:
			http.NotFound(writer, request)
		}
	}))
}

func newTestReleaseObserver(
	t *testing.T,
	serverURL string,
	maxBodyBytes int64,
) *OfficialRunnerReleaseObserver {
	t.Helper()
	target, err := url.Parse(serverURL)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	client := &http.Client{
		Transport: rewriteReleaseTransport{
			target: target,
			base:   http.DefaultTransport,
		},
	}
	observer, err := newOfficialRunnerReleaseObserver(
		client,
		maxBodyBytes,
		2*time.Second,
	)
	if err != nil {
		t.Fatalf("newOfficialRunnerReleaseObserver() error = %v", err)
	}
	return observer
}

type rewriteReleaseTransport struct {
	target *url.URL
	base   http.RoundTripper
}

func (transport rewriteReleaseTransport) RoundTrip(
	request *http.Request,
) (*http.Response, error) {
	cloned := request.Clone(request.Context())
	cloned.URL.Scheme = transport.target.Scheme
	cloned.URL.Host = transport.target.Host
	return transport.base.RoundTrip(cloned)
}

func boolJSON(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
