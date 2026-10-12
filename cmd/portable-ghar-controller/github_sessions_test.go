package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/githubscale"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

type fakeGitHubSession struct {
	githubscale.Session
	report githubscale.ScaleSetCompatibilityReport
	closed int
}

func (s *fakeGitHubSession) Compatibility() githubscale.ScaleSetCompatibilityReport {
	return s.report
}

func (s *fakeGitHubSession) Close(context.Context) error {
	s.closed++
	return nil
}

type fakeGitHubClient struct {
	config    githubscale.ClientConfig
	openErr   error
	session   *fakeGitHubSession
	opened    []githubscale.Fleet
	ensured   []githubscale.Fleet
	ensureErr error
	created   bool
}

func (c *fakeGitHubClient) Open(_ context.Context, fleet githubscale.Fleet) (githubscale.Session, error) {
	c.opened = append(c.opened, fleet)
	if c.openErr != nil {
		return nil, c.openErr
	}
	c.session = &fakeGitHubSession{report: githubscale.ScaleSetCompatibilityReport{
		SingleNameLabel: true,
		DisableUpdate:   true,
	}}
	return c.session, nil
}

func (c *fakeGitHubClient) EnsureScaleSet(
	_ context.Context,
	fleet githubscale.Fleet,
) (githubscale.ScaleSetCompatibilityReport, bool, error) {
	c.ensured = append(c.ensured, fleet)
	if c.ensureErr != nil {
		return githubscale.ScaleSetCompatibilityReport{}, c.created, c.ensureErr
	}
	return githubscale.ScaleSetCompatibilityReport{SingleNameLabel: true, DisableUpdate: true}, c.created, nil
}

func (c *fakeGitHubClient) Probe(context.Context) (githubscale.CompatibilityReport, error) {
	return githubscale.CompatibilityReport{Compatible: true}, nil
}

// fakeGitHub records every client it builds, keyed by config URL, and lets a
// test set per-repository failures before the command runs.
type fakeGitHub struct {
	mu          sync.Mutex
	overlay     hostruntime.PrivateOverlay
	overlayRead int
	secrets     map[string]string
	openErr     map[string]error
	ensureErr   error
	created     bool
	clients     []*fakeGitHubClient
}

func (f *fakeGitHub) access() githubAccess {
	return githubAccess{
		ReadOverlay: func(string) (hostruntime.PrivateOverlay, error) {
			f.overlayRead++
			return f.overlay, nil
		},
		ReadSecret: func(path string) (string, error) {
			value, ok := f.secrets[path]
			if !ok {
				return "", errCommandUnavailable
			}
			return value, nil
		},
		NewClient: func(config githubscale.ClientConfig) (githubscale.Client, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			client := &fakeGitHubClient{
				config:    config,
				openErr:   f.openErr[config.GitHubConfigURL],
				ensureErr: f.ensureErr,
				created:   f.created,
			}
			f.clients = append(f.clients, client)
			return client, nil
		},
	}
}

func newFakeGitHub() *fakeGitHub {
	return &fakeGitHub{
		overlay: hostruntime.PrivateOverlay{
			Repositories: []hostruntime.RepositoryOverlay{
				{
					Alias:          "alpha",
					ConfigURL:      "https://github.example.invalid/owner/alpha",
					ScaleSetName:   "alpha-set",
					CredentialName: "alpha-token",
				},
				{
					Alias:          "beta",
					ConfigURL:      "https://github.example.invalid/owner/beta",
					ScaleSetName:   "beta-set",
					CredentialName: "beta-token",
				},
			},
			Secrets: []hostruntime.NamedSecretRef{
				{Name: "alpha-token", Ref: hostruntime.SecretRefOverlay{Source: "file", Ref: "/secrets/alpha"}},
				{Name: "beta-token", Ref: hostruntime.SecretRefOverlay{Source: "file", Ref: "/secrets/beta"}},
			},
			GitHub: &hostruntime.GitHubOverlay{
				MaxResponseBytes:      1 << 20,
				OperationTimeout:      "30s",
				ResponseHeaderTimeout: "15s",
			},
		},
		secrets: map[string]string{
			"/secrets/alpha": "placeholder-alpha",
			"/secrets/beta":  "placeholder-beta",
		},
		openErr: map[string]error{},
	}
}

func runGitHubCommand(t *testing.T, fake *fakeGitHub, args ...string) (int, string, string) {
	t.Helper()
	deps := testCommandDeps()
	deps.GitHub = fake.access()
	var stdout, stderr bytes.Buffer
	code := runWithDependencies(context.Background(), args, &stdout, &stderr, deps)
	return code, stdout.String(), stderr.String()
}

func TestExternalProbeOpensAndClosesEveryRepositorySession(t *testing.T) {
	fake := newFakeGitHub()
	code, stdout, stderr := runGitHubCommand(t, fake, "external-probe", "--config=/etc/overlay.json")
	if code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, stderr)
	}
	var got struct {
		Repositories []githubProbeResult `json:"repositories"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("decode stdout %q: %v", stdout, err)
	}
	if len(got.Repositories) != 2 ||
		got.Repositories[0] != (githubProbeResult{Alias: "alpha", ScaleSet: "alpha-set", SingleNameLabel: true, DisableUpdate: true}) ||
		got.Repositories[1].Alias != "beta" {
		t.Fatalf("stdout = %+v", got)
	}
	if len(fake.clients) != 2 {
		t.Fatalf("clients = %d, want 2", len(fake.clients))
	}
	alpha := fake.clients[0]
	if alpha.config.PersonalAccessToken != "placeholder-alpha" ||
		alpha.config.GitHubConfigURL != "https://github.example.invalid/owner/alpha" ||
		alpha.config.OperationTimeout != 30*time.Second ||
		alpha.config.ResponseHeaderTimeout != 15*time.Second ||
		alpha.config.MaxResponseBytes != 1<<20 {
		t.Fatalf("alpha client config = %+v", alpha.config)
	}
	if alpha.opened[0] != (githubscale.Fleet{
		RepositoryAlias: "alpha",
		GitHubConfigURL: "https://github.example.invalid/owner/alpha",
		ScaleSetName:    "alpha-set",
	}) {
		t.Fatalf("alpha fleet = %+v", alpha.opened[0])
	}
	for _, client := range fake.clients {
		if client.session.closed != 1 {
			t.Fatalf("%s session closed %d times, want 1", client.config.GitHubConfigURL, client.session.closed)
		}
	}
}

func TestExternalProbeClosesOpenedSessionsWhenALaterOpenFails(t *testing.T) {
	fake := newFakeGitHub()
	fake.openErr["https://github.example.invalid/owner/beta"] = githubscale.ErrLabelMismatch
	code, stdout, stderr := runGitHubCommand(t, fake, "external-probe", "--config=/etc/overlay.json")
	if code != 1 || stdout != "" {
		t.Fatalf("exit = %d, stdout %q; want 1 and no output", code, stdout)
	}
	if !strings.Contains(stderr, "beta") || !strings.Contains(stderr, githubscale.ErrLabelMismatch.Error()) {
		t.Fatalf("stderr = %q, want the alias and the reason", stderr)
	}
	if fake.clients[0].session.closed != 1 {
		t.Fatalf("alpha session closed %d times, want 1", fake.clients[0].session.closed)
	}
}

func TestExternalProbeFailsClosed(t *testing.T) {
	t.Run("not root", func(t *testing.T) {
		fake := newFakeGitHub()
		deps := testCommandDeps()
		deps.GitHub = fake.access()
		deps.IsRoot = func() bool { return false }
		var stdout, stderr bytes.Buffer
		if code := runWithDependencies(context.Background(), []string{"external-probe", "--config=/etc/overlay.json"}, &stdout, &stderr, deps); code != 1 {
			t.Fatalf("exit = %d, want 1", code)
		}
		if fake.overlayRead != 0 {
			t.Fatal("overlay read without root")
		}
	})
	t.Run("no github section", func(t *testing.T) {
		fake := newFakeGitHub()
		fake.overlay.GitHub = nil
		if code, _, _ := runGitHubCommand(t, fake, "external-probe", "--config=/etc/overlay.json"); code != 1 || len(fake.clients) != 0 {
			t.Fatalf("exit = %d, clients %d; want 1 and none", code, len(fake.clients))
		}
	})
	t.Run("unreadable credential", func(t *testing.T) {
		fake := newFakeGitHub()
		delete(fake.secrets, "/secrets/alpha")
		if code, _, _ := runGitHubCommand(t, fake, "external-probe", "--config=/etc/overlay.json"); code != 1 || len(fake.clients) != 0 {
			t.Fatalf("exit = %d, clients %d; want 1 and none", code, len(fake.clients))
		}
	})
	t.Run("env credential", func(t *testing.T) {
		fake := newFakeGitHub()
		fake.overlay.Secrets[0].Ref.Source = "env"
		if code, _, _ := runGitHubCommand(t, fake, "external-probe", "--config=/etc/overlay.json"); code != 1 || len(fake.clients) != 0 {
			t.Fatalf("exit = %d, clients %d; want 1 and none", code, len(fake.clients))
		}
	})
	t.Run("usage", func(t *testing.T) {
		for _, args := range [][]string{
			{"external-probe"},
			{"external-probe", "--config=/a", "--alias=alpha"},
			{"create-scale-set", "--config=/a"},
			{"create-scale-set", "--alias=alpha"},
		} {
			if code, _, _ := runGitHubCommand(t, newFakeGitHub(), args...); code != 2 {
				t.Errorf("%v exit = %d, want 2", args, code)
			}
		}
	})
}

func TestCreateScaleSetEnsuresOnlyTheNamedRepository(t *testing.T) {
	fake := newFakeGitHub()
	fake.created = true
	code, stdout, stderr := runGitHubCommand(t, fake, "create-scale-set", "--config=/etc/overlay.json", "--alias=beta")
	if code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, stderr)
	}
	var got githubProbeResult
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("decode stdout %q: %v", stdout, err)
	}
	if got.Alias != "beta" || got.ScaleSet != "beta-set" || got.Created == nil || !*got.Created ||
		!got.SingleNameLabel || !got.DisableUpdate {
		t.Fatalf("stdout = %+v", got)
	}
	if len(fake.clients) != 1 ||
		fake.clients[0].config.PersonalAccessToken != "placeholder-beta" ||
		len(fake.clients[0].ensured) != 1 ||
		fake.clients[0].ensured[0].ScaleSetName != "beta-set" ||
		len(fake.clients[0].opened) != 0 {
		t.Fatalf("clients = %+v, want one beta client that ensured and opened nothing", fake.clients)
	}
}

func TestCreateScaleSetFailures(t *testing.T) {
	t.Run("unknown alias", func(t *testing.T) {
		fake := newFakeGitHub()
		code, _, stderr := runGitHubCommand(t, fake, "create-scale-set", "--config=/etc/overlay.json", "--alias=gamma")
		if code != 1 || len(fake.clients) != 0 || !strings.Contains(stderr, "alias is not in the overlay") {
			t.Fatalf("exit = %d, clients %d, stderr %q", code, len(fake.clients), stderr)
		}
	})
	t.Run("created but unverified", func(t *testing.T) {
		fake := newFakeGitHub()
		fake.created = true
		fake.ensureErr = githubscale.ErrScaleSetNotFound
		code, stdout, stderr := runGitHubCommand(t, fake, "create-scale-set", "--config=/etc/overlay.json", "--alias=alpha")
		if code != 1 || stdout != "" || !strings.Contains(stderr, "created, but verification failed") {
			t.Fatalf("exit = %d, stdout %q, stderr %q", code, stdout, stderr)
		}
	})
	t.Run("existing incompatible", func(t *testing.T) {
		fake := newFakeGitHub()
		fake.ensureErr = githubscale.ErrUpdateSettingMismatch
		code, _, stderr := runGitHubCommand(t, fake, "create-scale-set", "--config=/etc/overlay.json", "--alias=alpha")
		if code != 1 || strings.Contains(stderr, "created") || !strings.Contains(stderr, githubscale.ErrUpdateSettingMismatch.Error()) {
			t.Fatalf("exit = %d, stderr %q", code, stderr)
		}
	})
}

func TestParseCredential(t *testing.T) {
	for input, want := range map[string]string{
		"placeholder-token":   "placeholder-token",
		"placeholder-token\n": "placeholder-token",
	} {
		got, err := parseCredential([]byte(input))
		if err != nil || got != want {
			t.Errorf("parseCredential(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"", "\n", "placeholder-token\n\n", " placeholder-token", "a b", "token\r\n"} {
		if _, err := parseCredential([]byte(input)); !errors.Is(err, errCommandUnavailable) {
			t.Errorf("parseCredential(%q) error = %v, want rejection", input, err)
		}
	}
}

func TestPollTargetSessionsServesOnlyOpenedRepositories(t *testing.T) {
	alpha := &fakeGitHubSession{}
	sessions := newPollTargetSessions([]controller.PollTarget{{
		Fleet:   githubscale.Fleet{RepositoryAlias: "alpha"},
		Session: alpha,
	}})
	got, err := sessions.Session(context.Background(), "alpha")
	if err != nil || got != alpha {
		t.Fatalf("Session(alpha) = %v, %v; want the opened session", got, err)
	}
	if got, err := sessions.Session(context.Background(), "beta"); err == nil || got != nil {
		t.Fatalf("Session(beta) = %v, %v; want an error", got, err)
	}
}
