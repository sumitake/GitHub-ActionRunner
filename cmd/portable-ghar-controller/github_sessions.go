package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/sumitake/portable-ghar/internal/buildinfo"
	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/githubscale"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/lifecycle"
)

const maxGitHubCredentialBytes = 4096

// githubAccess is how the one-shot GitHub commands reach the overlay, the
// credential files, and GitHub. Production wires the pinned readers and the
// real scale-set client; tests substitute fakes.
type githubAccess struct {
	ReadOverlay func(path string) (hostruntime.PrivateOverlay, error)
	ReadSecret  func(path string) (string, error)
	NewClient   func(githubscale.ClientConfig) (githubscale.Client, error)
}

func productionGitHubAccess() githubAccess {
	return githubAccess{
		ReadOverlay: readProductionOverlay,
		ReadSecret:  readCredentialFile,
		NewClient:   githubscale.NewClient,
	}
}

func (access githubAccess) valid() bool {
	return access.ReadOverlay != nil && access.ReadSecret != nil && access.NewClient != nil
}

// readProductionOverlay reads the private overlay with the same pinned,
// root-owned file rules as run, and checks it names this host's platform and
// user.
func readProductionOverlay(path string) (hostruntime.PrivateOverlay, error) {
	document, err := readPinnedRootFile(path, 0o600, maxProductionConfigBytes)
	if err != nil {
		return hostruntime.PrivateOverlay{}, err
	}
	overlay, _, err := hostruntime.ParsePrivateOverlay(document, maxProductionConfigBytes)
	if err != nil {
		return hostruntime.PrivateOverlay{}, errCommandUnavailable
	}
	if runtime.GOOS != overlay.Target.OS ||
		runtime.GOARCH != overlay.Target.Architecture ||
		uint64(os.Geteuid()) != overlay.Target.ExpectedEUID {
		return hostruntime.PrivateOverlay{}, errCommandUnavailable
	}
	return overlay, nil
}

// readCredentialFile reads one root-owned 0600 credential file. A single
// trailing newline is allowed; any other whitespace is rejected.
func readCredentialFile(path string) (string, error) {
	document, err := readPinnedRootFile(path, 0o600, maxGitHubCredentialBytes)
	if err != nil {
		return "", err
	}
	return parseCredential(document)
}

func parseCredential(document []byte) (string, error) {
	value := strings.TrimSuffix(string(document), "\n")
	if value == "" || strings.ContainsAny(value, " \t\r\n") {
		return "", errCommandUnavailable
	}
	return value, nil
}

// githubClientFor builds the scale-set client for one overlay repository.
// The overlay schema already guarantees the github section's bounds and that
// the repository credential names exactly one file secret.
func githubClientFor(
	overlay hostruntime.PrivateOverlay,
	repository hostruntime.RepositoryOverlay,
	access githubAccess,
) (githubscale.Client, error) {
	if overlay.GitHub == nil {
		return nil, errors.New("overlay has no github section")
	}
	operationTimeout, err := time.ParseDuration(overlay.GitHub.OperationTimeout)
	if err != nil {
		return nil, errors.New("invalid github operation timeout")
	}
	headerTimeout, err := time.ParseDuration(overlay.GitHub.ResponseHeaderTimeout)
	if err != nil {
		return nil, errors.New("invalid github response header timeout")
	}
	credentialPath := ""
	for _, secret := range overlay.Secrets {
		if secret.Name == repository.CredentialName && secret.Ref.Source == "file" {
			credentialPath = secret.Ref.Ref
		}
	}
	if credentialPath == "" {
		return nil, errors.New("repository credential is not a file secret")
	}
	token, err := access.ReadSecret(credentialPath)
	if err != nil {
		return nil, errors.New("repository credential is unreadable")
	}
	build := buildinfo.Info()
	return access.NewClient(githubscale.ClientConfig{
		GitHubConfigURL:       repository.ConfigURL,
		PersonalAccessToken:   token,
		System:                "portable-ghar",
		Subsystem:             "controller",
		Version:               build.Version,
		CommitSHA:             build.Commit,
		OperationTimeout:      operationTimeout,
		ResponseHeaderTimeout: headerTimeout,
		MaxResponseBytes:      int64(overlay.GitHub.MaxResponseBytes),
	})
}

func fleetFor(repository hostruntime.RepositoryOverlay) githubscale.Fleet {
	return githubscale.Fleet{
		RepositoryAlias: repository.Alias,
		GitHubConfigURL: repository.ConfigURL,
		ScaleSetName:    repository.ScaleSetName,
	}
}

// openGitHubPollTargets opens one message session per overlay repository, in
// overlay order. On any failure it closes the sessions it already opened and
// returns no targets. The caller closes the returned targets with
// closePollTargets.
func openGitHubPollTargets(
	ctx context.Context,
	overlay hostruntime.PrivateOverlay,
	access githubAccess,
) ([]controller.PollTarget, error) {
	targets := make([]controller.PollTarget, 0, len(overlay.Repositories))
	for _, repository := range overlay.Repositories {
		client, err := githubClientFor(overlay, repository, access)
		if err == nil {
			var session githubscale.Session
			session, err = client.Open(ctx, fleetFor(repository))
			if err == nil {
				targets = append(targets, controller.PollTarget{
					Fleet:   fleetFor(repository),
					Session: session,
				})
				continue
			}
		}
		return nil, errors.Join(
			fmt.Errorf("%s: %w", repository.Alias, err),
			closePollTargets(ctx, targets),
		)
	}
	return targets, nil
}

func closePollTargets(ctx context.Context, targets []controller.PollTarget) error {
	var errs []error
	for _, target := range targets {
		if err := target.Session.Close(ctx); err != nil {
			errs = append(errs, fmt.Errorf("%s: close session: %w", target.Fleet.RepositoryAlias, err))
		}
	}
	return errors.Join(errs...)
}

// pollTargetSessions serves lifecycle.SessionProvider from the opened poll
// targets, so polling and runner operations share one GitHub session per
// repository. It never opens a session itself.
type pollTargetSessions map[string]githubscale.Session

var _ lifecycle.SessionProvider = pollTargetSessions(nil)

func newPollTargetSessions(targets []controller.PollTarget) pollTargetSessions {
	sessions := make(pollTargetSessions, len(targets))
	for _, target := range targets {
		sessions[target.Fleet.RepositoryAlias] = target.Session
	}
	return sessions
}

func (sessions pollTargetSessions) Session(
	_ context.Context,
	repositoryAlias string,
) (githubscale.Session, error) {
	session, ok := sessions[repositoryAlias]
	if !ok || session == nil {
		return nil, errors.New("no session for repository")
	}
	return session, nil
}

type githubProbeResult struct {
	Alias           string `json:"alias"`
	ScaleSet        string `json:"scale_set"`
	SingleNameLabel bool   `json:"single_name_label"`
	DisableUpdate   bool   `json:"disable_update"`
	Created         *bool  `json:"created,omitempty"`
}

// executeExternalProbe opens and closes one GitHub message session per
// overlay repository and reports the scale-set evidence each session was
// opened against. It touches no controller state. GitHub allows one session
// per scale set, so it fails while a controller holds one.
func executeExternalProbe(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	deps commandDependencies,
) int {
	flags, err := parseExactFlags(args, map[string]bool{"config": true})
	if err != nil || flags["config"] == "" {
		return commandUsage(stderr)
	}
	if !deps.IsRoot() {
		return commandFailure(stderr, "external-probe")
	}
	overlay, err := deps.GitHub.ReadOverlay(flags["config"])
	if err != nil {
		return commandFailure(stderr, "external-probe")
	}
	targets, err := openGitHubPollTargets(ctx, overlay, deps.GitHub)
	if err != nil {
		return commandFailureReason(stderr, "external-probe", err)
	}
	results := make([]githubProbeResult, 0, len(targets))
	for _, target := range targets {
		report := target.Session.Compatibility()
		results = append(results, githubProbeResult{
			Alias:           target.Fleet.RepositoryAlias,
			ScaleSet:        target.Fleet.ScaleSetName,
			SingleNameLabel: report.SingleNameLabel,
			DisableUpdate:   report.DisableUpdate,
		})
	}
	if err := closePollTargets(ctx, targets); err != nil {
		return commandFailureReason(stderr, "external-probe", err)
	}
	if err := json.NewEncoder(stdout).Encode(struct {
		Repositories []githubProbeResult `json:"repositories"`
	}{Repositories: results}); err != nil {
		return commandFailure(stderr, "external-probe")
	}
	return 0
}

// executeCreateScaleSet creates the named repository's scale set when it is
// missing, then re-reads and verifies it. It never changes an existing scale
// set and opens no message session.
func executeCreateScaleSet(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	deps commandDependencies,
) int {
	flags, err := parseExactFlags(args, map[string]bool{"config": true, "alias": true})
	if err != nil || flags["config"] == "" || flags["alias"] == "" {
		return commandUsage(stderr)
	}
	if !deps.IsRoot() {
		return commandFailure(stderr, "create-scale-set")
	}
	overlay, err := deps.GitHub.ReadOverlay(flags["config"])
	if err != nil {
		return commandFailure(stderr, "create-scale-set")
	}
	var repository *hostruntime.RepositoryOverlay
	for index := range overlay.Repositories {
		if overlay.Repositories[index].Alias == flags["alias"] {
			repository = &overlay.Repositories[index]
		}
	}
	if repository == nil {
		return commandFailureReason(stderr, "create-scale-set", errors.New("alias is not in the overlay"))
	}
	client, err := githubClientFor(overlay, *repository, deps.GitHub)
	if err != nil {
		return commandFailureReason(stderr, "create-scale-set", err)
	}
	report, created, err := client.EnsureScaleSet(ctx, fleetFor(*repository))
	if err != nil {
		if created {
			err = fmt.Errorf("created, but verification failed: %w", err)
		}
		return commandFailureReason(stderr, "create-scale-set", err)
	}
	if err := json.NewEncoder(stdout).Encode(githubProbeResult{
		Alias:           repository.Alias,
		ScaleSet:        repository.ScaleSetName,
		SingleNameLabel: report.SingleNameLabel,
		DisableUpdate:   report.DisableUpdate,
		Created:         &created,
	}); err != nil {
		return commandFailure(stderr, "create-scale-set")
	}
	return 0
}

// commandFailureReason adds a reason to the failure line. Callers pass only
// errors built here or by githubscale, which never carries upstream text.
func commandFailureReason(stderr io.Writer, command string, reason error) int {
	_, _ = fmt.Fprintf(
		stderr,
		"portable-ghar-controller: %s unavailable: %v\n",
		command,
		reason,
	)
	return 1
}
