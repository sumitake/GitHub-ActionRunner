package githubscale

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
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
	upstream  *scaleset.Client
	opTimeout time.Duration
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

	upstream, err := scaleset.NewClientWithPersonalAccessToken(
		scaleset.NewClientWithPersonalAccessTokenConfig{
			GitHubConfigURL:     cfg.GitHubConfigURL,
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
		return nil, fmt.Errorf("githubscale: NewClient: %w", err)
	}

	return &client{upstream: upstream, opTimeout: opTimeout}, nil
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
	cctx, cancel := withOperationDeadline(ctx, c.opTimeout)
	defer cancel()

	group, err := c.upstream.GetRunnerGroupByName(cctx, scaleset.DefaultRunnerGroup)
	if err != nil {
		return nil, fmt.Errorf("githubscale: open: resolve runner group: %w", err)
	}

	scaleSet, err := c.upstream.GetRunnerScaleSet(cctx, group.ID, fleet.ScaleSetName)
	if err != nil {
		return nil, fmt.Errorf("githubscale: open: resolve scale set %q: %w", fleet.ScaleSetName, err)
	}
	if scaleSet == nil {
		return nil, fmt.Errorf("githubscale: open: %w: %q", ErrScaleSetNotFound, fleet.ScaleSetName)
	}

	if err := verifySingleNameLabel(scaleSet, fleet.ScaleSetName); err != nil {
		return nil, fmt.Errorf("githubscale: open: %w", err)
	}

	sessionClient, err := c.upstream.MessageSessionClient(cctx, scaleSet.ID, fleet.RepositoryAlias)
	if err != nil {
		return nil, fmt.Errorf("githubscale: open: create message session: %w", err)
	}

	return &v040Session{
		upstreamClient:  c.upstream,
		upstreamSession: sessionClient,
		scaleSetID:      scaleSet.ID,
		opTimeout:       c.opTimeout,
	}, nil
}

// Probe implements Client. It defers entirely to the package-level Probe
// function (probe.go), which depends only on this binary's own linked
// module version -- never on c.upstream or any live GitHub API call.
func (c *client) Probe(ctx context.Context) (CompatibilityReport, error) {
	return Probe(ctx)
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
