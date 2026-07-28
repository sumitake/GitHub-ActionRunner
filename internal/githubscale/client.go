package githubscale

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/actions/scaleset"
	"github.com/hashicorp/go-retryablehttp"
)

// DefaultOperationTimeout bounds every per-operation context deadline this
// adapter applies to a Poll, Acquire, GenerateJIT, or runner call when the
// caller's own context has no earlier deadline (context.WithTimeout always
// keeps the EARLIER of two deadlines, so a caller-supplied tighter deadline
// is still honored -- see withOperationDeadline in adapter_v040.go).
const DefaultOperationTimeout = 30 * time.Second

// DefaultResponseHeaderTimeout bounds the underlying HTTP transport's wait
// for a response's headers, independent of and in addition to any
// per-operation context deadline. This is what actually protects a call
// against a server that accepts the connection and the request but never
// writes a response -- a context deadline alone still depends on the
// transport eventually noticing, and net/http's default transport has no
// response-header timeout at all.
const DefaultResponseHeaderTimeout = 15 * time.Second

// ClientConfig configures a new Client. It never embeds or accepts an
// upstream scaleset type -- every field here is this adapter's own, and
// NewClient translates them into the upstream scaleset.SystemInfo /
// scaleset.NewClientWithPersonalAccessTokenConfig shapes internally.
type ClientConfig struct {
	// GitHubConfigURL is the GitHub org/repo/enterprise URL this Client
	// authenticates against. Every Fleet later passed to Open must resolve
	// a scale set within this same config URL's scope.
	GitHubConfigURL string

	// PersonalAccessToken authenticates this Client. Task 1's
	// redaction.Secret is for JIT bytes flowing OUT of this package
	// (GenerateJIT's result); the credential flowing IN is the caller's
	// concern to protect before it reaches ClientConfig, not this
	// package's.
	PersonalAccessToken string

	// System, Subsystem, Version, and CommitSHA populate the upstream
	// client's diagnostic User-Agent (SystemInfo). They carry no
	// authentication or authorization meaning.
	System    string
	Subsystem string
	Version   string
	CommitSHA string

	// OperationTimeout overrides DefaultOperationTimeout when non-zero.
	OperationTimeout time.Duration

	// ResponseHeaderTimeout overrides DefaultResponseHeaderTimeout when
	// non-zero.
	ResponseHeaderTimeout time.Duration

	// MaxResponseBytes is the required maximum number of decompressed bytes
	// any scale-set HTTP response may deliver to the pinned client.
	MaxResponseBytes int64

	// retryableHTTPClient is a test-only escape hatch letting
	// adapter_contract_test.go substitute a fully custom retryable HTTP
	// client (for example one whose transport dials an httptest server
	// with a very short response-header timeout). Production callers must
	// never set this; it is unexported so they cannot.
	retryableHTTPClient *retryablehttp.Client
}

// client is Client's only production implementation: a pinned wrapper
// around *scaleset.Client. No exported method or field of client ever
// returns or accepts an upstream scaleset type.
type client struct {
	upstream       *scaleset.Client
	opTimeout      time.Duration
	configScopeURL string
	gate           *serializationGate

	// probe is instance-scoped so package tests can supply synthetic build
	// metadata without a global mutable hook. Production construction always
	// installs the real runtime build-info Probe.
	probe func(context.Context) (CompatibilityReport, error)
}

// NewClient constructs a Client authenticated against cfg.GitHubConfigURL.
// It does not contact GitHub at construction time -- the first network
// call happens on the first Open, Probe, or upstream operation.
func NewClient(cfg ClientConfig) (Client, error) {
	if cfg.GitHubConfigURL == "" {
		return nil, fmt.Errorf("githubscale: NewClient: GitHubConfigURL is required")
	}
	if cfg.PersonalAccessToken == "" {
		return nil, fmt.Errorf("githubscale: NewClient: PersonalAccessToken is required")
	}
	if cfg.MaxResponseBytes <= 0 {
		return nil, fmt.Errorf("githubscale: NewClient: MaxResponseBytes is required")
	}
	configScopeURL, err := canonicalGitHubScopeURL(cfg.GitHubConfigURL)
	if err != nil {
		return nil, fmt.Errorf("githubscale: NewClient: %w", err)
	}

	opTimeout := cfg.OperationTimeout
	if opTimeout <= 0 {
		opTimeout = DefaultOperationTimeout
	}
	headerTimeout := cfg.ResponseHeaderTimeout
	if headerTimeout <= 0 {
		headerTimeout = DefaultResponseHeaderTimeout
	}

	retryable := cfg.retryableHTTPClient
	if retryable == nil {
		retryable = newRetryableHTTPClient(headerTimeout)
	}
	boundRetryableResponseBodies(retryable, cfg.MaxResponseBytes)

	upstream, err := scaleset.NewClientWithPersonalAccessToken(
		scaleset.NewClientWithPersonalAccessTokenConfig{
			GitHubConfigURL:     configScopeURL,
			PersonalAccessToken: cfg.PersonalAccessToken,
			SystemInfo: scaleset.SystemInfo{
				System:    cfg.System,
				Subsystem: cfg.Subsystem,
				Version:   cfg.Version,
				CommitSHA: cfg.CommitSHA,
			},
		},
		scaleset.WithRetryableHTTPClint(retryable),
	)
	if err != nil {
		return nil, sanitizeUpstreamError(context.Background(), "NewClient: initialize upstream client", err)
	}

	return &client{
		upstream:       upstream,
		opTimeout:      opTimeout,
		configScopeURL: configScopeURL,
		gate:           newSerializationGate(),
		probe:          Probe,
	}, nil
}

// serializationGate is an adapter-owned, context-aware mutex shared by Open
// and every Session derived from this Client. Lock order is singular: acquire
// this gate first, then call upstream (which may take its own ordinary mutex),
// then return from upstream before releasing this gate. Adapter code never
// acquires the gate while holding an upstream lock and never calls one gated
// adapter operation from another.
type serializationGate struct {
	token chan struct{}
}

func newSerializationGate() *serializationGate {
	g := &serializationGate{token: make(chan struct{}, 1)}
	g.token <- struct{}{}
	return g
}

func (g *serializationGate) enter(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-g.token:
		if err := ctx.Err(); err != nil {
			g.token <- struct{}{}
			return nil, err
		}
		return func() { g.token <- struct{}{} }, nil
	}
}

// canonicalGitHubScopeURL retains the exact endpoint and organization /
// repository / enterprise path while normalizing URL syntax that does not
// change scope identity. It intentionally does not restrict hosts: deployment
// policy is enforced by later configuration, while this adapter only requires
// the Fleet and Client to name the same canonical scope.
func canonicalGitHubScopeURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("invalid GitHubConfigURL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("invalid GitHubConfigURL scope")
	}

	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	if port := u.Port(); (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		u.Host = strings.TrimSuffix(u.Host, ":"+port)
	}
	u.Path = "/" + strings.Trim(u.Path, "/")
	u.RawPath = ""
	return u.String(), nil
}

type boundedResponseBody struct {
	body      io.ReadCloser
	remaining int64
	tooLarge  bool
	closeOnce sync.Once
	closeErr  error
}

func newBoundedResponseBody(body io.ReadCloser, maxBytes int64) *boundedResponseBody {
	return &boundedResponseBody{body: body, remaining: maxBytes}
}

func (b *boundedResponseBody) Read(p []byte) (int, error) {
	if b.tooLarge {
		return 0, ErrResponseTooLarge
	}
	if len(p) == 0 {
		return 0, nil
	}
	if b.remaining > 0 {
		if int64(len(p)) > b.remaining {
			p = p[:int(b.remaining)]
		}
		n, err := b.body.Read(p)
		b.remaining -= int64(n)
		return n, err
	}

	var probe [1]byte
	n, err := b.body.Read(probe[:])
	if n > 0 {
		b.tooLarge = true
		_ = b.Close()
		return 0, ErrResponseTooLarge
	}
	return 0, err
}

func (b *boundedResponseBody) Close() error {
	b.closeOnce.Do(func() {
		b.closeErr = b.body.Close()
	})
	return b.closeErr
}

func boundRetryableResponseBodies(client *retryablehttp.Client, maxBytes int64) {
	previousRequestHook := client.RequestLogHook
	previousResponseHook := client.ResponseLogHook
	var retryAttempt int
	var shouldRetry bool

	// actions/scaleset v0.4.0 requires HTTPClient.Transport to remain exactly
	// *http.Transport, and it replaces CheckRetry while refreshing its admin
	// connection. RequestLogHook is the stable point immediately before each
	// attempt: wrap the then-current retry policy for one invocation, record
	// its decision, and restore it before calling through.
	client.RequestLogHook = func(logger retryablehttp.Logger, req *http.Request, attempt int) {
		if previousRequestHook != nil {
			previousRequestHook(logger, req, attempt)
		}
		retryAttempt = attempt
		shouldRetry = false
		checkRetry := client.CheckRetry
		client.CheckRetry = func(ctx context.Context, resp *http.Response, err error) (bool, error) {
			client.CheckRetry = checkRetry
			shouldRetry, err = checkRetry(ctx, resp, err)
			return shouldRetry, err
		}
	}

	client.ResponseLogHook = func(logger retryablehttp.Logger, resp *http.Response) {
		if resp != nil && resp.Body != nil {
			resp.Body = newBoundedResponseBody(resp.Body, maxBytes)
		}

		// A response the pinned retry policy would retry must be drained here
		// so an over-limit byte can stop that retry before another network
		// attempt. Bounded retryable bodies are discarded exactly as
		// retryablehttp would discard them; non-retryable bodies remain
		// streaming for the pinned client's eager reader.
		if shouldRetry && resp != nil && resp.Body != nil {
			errorHandler := client.ErrorHandler
			switch {
			case retryAttempt >= client.RetryMax:
				// retryablehttp normally converts a final retryable status
				// into its own error before the pinned eager reader sees the
				// response. Pass the final response through so that same
				// bounded reader remains the single body-reading path.
				client.ErrorHandler = func(resp *http.Response, _ error, _ int) (*http.Response, error) {
					client.ErrorHandler = errorHandler
					return resp, nil
				}

			default:
				_, readErr := io.Copy(io.Discard, resp.Body)
				if !errors.Is(readErr, ErrResponseTooLarge) {
					_ = resp.Body.Close()
					resp.Body = http.NoBody
					break
				}

				retryMax := client.RetryMax
				client.RetryMax = retryAttempt
				client.ErrorHandler = func(resp *http.Response, _ error, _ int) (*http.Response, error) {
					client.RetryMax = retryMax
					client.ErrorHandler = errorHandler
					if resp != nil && resp.Body != nil {
						_ = resp.Body.Close()
					}
					return nil, ErrResponseTooLarge
				}
			}
		}

		if previousResponseHook != nil {
			previousResponseHook(logger, resp)
		}
	}
}

// newRetryableHTTPClient builds a retryablehttp.Client whose underlying
// transport carries explicit dial, TLS-handshake, and
// response-header timeouts, so a server that accepts a connection and then
// never responds cannot hang a call past headerTimeout regardless of
// whether the caller's context has a deadline.
//
// This is a defense-in-depth layer, not the primary bound: the PRIMARY
// bound on every call is the per-operation context deadline
// withOperationDeadline applies in adapter_v040.go, which every Poll,
// Acquire, GenerateJIT, and runner call is wrapped in. Note that this
// function intentionally leaves the returned client's own HTTPClient.Timeout
// (an overall per-request budget covering the full round trip, including
// body read) at its zero value; when this client is handed to
// scaleset.WithRetryableHTTPClint, upstream's own
// httpClientOption.newRetryableHTTPClient back-fills that zero value with
// its own 5-minute default (see scaleset's common_client.go) -- a value
// this adapter never relies on, since the per-operation context deadline
// is always the binding constraint in practice.
func newRetryableHTTPClient(headerTimeout time.Duration) *retryablehttp.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout: 10 * time.Second,
		}).DialContext,
		TLSClientConfig:       &tls.Config{},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: headerTimeout,
		ExpectContinueTimeout: 1 * time.Second,
	}

	rc := retryablehttp.NewClient()
	rc.HTTPClient = &http.Client{Transport: transport}
	rc.RetryMax = 4
	rc.RetryWaitMax = 30 * time.Second
	// Discard retryablehttp's default logger; this adapter never wants
	// upstream request/response bodies (which can carry job-controlled
	// values) on a log stream it does not control the redaction of.
	rc.Logger = nil

	return rc
}

// Open implements Client.
func (c *client) Open(ctx context.Context, fleet Fleet) (Session, error) {
	report, err := c.Probe(ctx)
	if err != nil {
		return nil, fmt.Errorf("githubscale: open: compatibility probe: %w", err)
	}
	if !report.Compatible {
		return nil, fmt.Errorf("githubscale: open: compatibility probe: %w", ErrIncompatibleModuleVersion)
	}
	fleetScopeURL, err := canonicalGitHubScopeURL(fleet.GitHubConfigURL)
	if err != nil {
		return nil, fmt.Errorf("githubscale: open: %w: %v", ErrIdentityMismatch, err)
	}
	if fleetScopeURL != c.configScopeURL {
		return nil, fmt.Errorf("githubscale: open: %w: fleet scope does not match client scope", ErrIdentityMismatch)
	}

	cctx, cancel := withOperationDeadline(ctx, c.opTimeout)
	defer cancel()
	release, err := c.gate.enter(cctx)
	if err != nil {
		return nil, fmt.Errorf("githubscale: open: wait for serialization: %w", err)
	}
	defer release()

	group, err := c.upstream.GetRunnerGroupByName(cctx, scaleset.DefaultRunnerGroup)
	if err != nil {
		return nil, sanitizeUpstreamError(cctx, "open: resolve runner group", err)
	}

	scaleSet, err := c.upstream.GetRunnerScaleSet(cctx, group.ID, fleet.ScaleSetName)
	if err != nil {
		return nil, sanitizeUpstreamError(cctx, "open: resolve scale set", err)
	}
	if scaleSet == nil {
		return nil, fmt.Errorf("githubscale: open: %w: %q", ErrScaleSetNotFound, fleet.ScaleSetName)
	}
	if err := verifyScaleSetIdentity(scaleSet, group, fleet); err != nil {
		return nil, fmt.Errorf("githubscale: open: %w", err)
	}

	compatibility, err := verifyScaleSetCompatibility(scaleSet, fleet.ScaleSetName)
	if err != nil {
		return nil, fmt.Errorf("githubscale: open: %w", err)
	}

	sessionClient, err := c.upstream.MessageSessionClient(cctx, scaleSet.ID, fleet.RepositoryAlias)
	if err != nil {
		return nil, sanitizeUpstreamError(cctx, "open: create message session", err)
	}

	return &v040Session{
		upstreamClient:  c.upstream,
		upstreamSession: sessionClient,
		scaleSetID:      scaleSet.ID,
		opTimeout:       c.opTimeout,
		gate:            c.gate,
		compatibility:   compatibility,
	}, nil
}

func verifyScaleSetIdentity(scaleSet *scaleset.RunnerScaleSet, group *scaleset.RunnerGroup, fleet Fleet) error {
	if group == nil || group.Name != scaleset.DefaultRunnerGroup || !group.IsDefault {
		return fmt.Errorf("%w: resolved runner group does not match requested default group", ErrIdentityMismatch)
	}
	if scaleSet.Name != fleet.ScaleSetName {
		return fmt.Errorf("%w: returned scale-set name %q does not match requested name %q", ErrIdentityMismatch, scaleSet.Name, fleet.ScaleSetName)
	}
	if scaleSet.RunnerGroupID != group.ID || scaleSet.RunnerGroupName != group.Name {
		return fmt.Errorf("%w: returned scale-set runner group does not match resolved group", ErrIdentityMismatch)
	}
	return nil
}

// Probe implements Client. It defers entirely to the package-level Probe
// function (probe.go), which depends only on this binary's own linked
// module version -- never on c.upstream or any live GitHub API call.
func (c *client) Probe(ctx context.Context) (CompatibilityReport, error) {
	return c.probe(ctx)
}

// verifySingleNameLabel enforces the single-name-label rule this adapter
// requires before any acquisition against a scale set is possible: exactly
// one label, and that label's Name equal to the scale set's own
// (Fleet-requested) name. A missing label, an extra label, or a label
// whose name does not match are all rejected -- this check runs inside
// Open, so a rejection means Open returns an error and no Session (and
// therefore no Acquire) is ever produced for that scale set.
func verifySingleNameLabel(scaleSet *scaleset.RunnerScaleSet, name string) error {
	if len(scaleSet.Labels) != 1 {
		return fmt.Errorf("%w: scale set %q carries %d labels, want exactly 1", ErrLabelMismatch, name, len(scaleSet.Labels))
	}
	if scaleSet.Labels[0].Name != name {
		return fmt.Errorf("%w: scale set %q carries label %q, want %q", ErrLabelMismatch, name, scaleSet.Labels[0].Name, name)
	}
	return nil
}

// verifyScaleSetCompatibility validates every live scale-set invariant Open
// needs before creating a message session and constructs the evidence retained
// by the resulting Session from those same checks. Keeping validation and
// evidence construction together prevents the reported state from drifting
// from the state that was actually admitted.
func verifyScaleSetCompatibility(scaleSet *scaleset.RunnerScaleSet, name string) (ScaleSetCompatibilityReport, error) {
	if err := verifySingleNameLabel(scaleSet, name); err != nil {
		return ScaleSetCompatibilityReport{}, err
	}
	if !scaleSet.RunnerSetting.DisableUpdate {
		return ScaleSetCompatibilityReport{}, fmt.Errorf(
			"%w: scale set %q must set RunnerSetting.disableUpdate=true",
			ErrUpdateSettingMismatch,
			name,
		)
	}
	return ScaleSetCompatibilityReport{
		SingleNameLabel: true,
		DisableUpdate:   true,
	}, nil
}
