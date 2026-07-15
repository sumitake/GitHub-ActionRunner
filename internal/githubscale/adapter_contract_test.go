package githubscale

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/actions/scaleset"
	"github.com/google/uuid"
	"github.com/sumitake/portable-ghar/internal/buildinfo"
	"github.com/sumitake/portable-ghar/internal/redaction"
)

// ---------------------------------------------------------------------
// Wire-contract assertions (Step 1).
//
// These private interfaces restate the REAL v0.4.0 API surface this
// package's translation depends on, using the EXACT signatures read from
// $(go env GOMODCACHE)/github.com/actions/scaleset@v0.4.0/{client,session_client}.go.
// The var _ assertions below fail to COMPILE -- loudly, before any test
// runs -- the moment v0.4.0's real API differs from what this adapter was
// written against. That is the point: a wire-contract break here means
// STOP and report NEEDS_CONTEXT, not "patch around it."
// ---------------------------------------------------------------------

type upstreamClient interface {
	GetRunnerScaleSet(ctx context.Context, runnerGroupID int, runnerScaleSetName string) (*scaleset.RunnerScaleSet, error)
	GetRunnerScaleSetByID(ctx context.Context, runnerScaleSetID int) (*scaleset.RunnerScaleSet, error)
	GetRunnerGroupByName(ctx context.Context, runnerGroup string) (*scaleset.RunnerGroup, error)
	MessageSessionClient(ctx context.Context, runnerScaleSetID int, owner string, options ...scaleset.HTTPOption) (*scaleset.MessageSessionClient, error)
	GenerateJitRunnerConfig(ctx context.Context, jitRunnerSetting *scaleset.RunnerScaleSetJitRunnerSetting, scaleSetID int) (*scaleset.RunnerScaleSetJitRunnerConfig, error)
	GetRunner(ctx context.Context, runnerID int) (*scaleset.RunnerReference, error)
	GetRunnerByName(ctx context.Context, runnerName string) (*scaleset.RunnerReference, error)
	RemoveRunner(ctx context.Context, runnerID int64) error
}

type upstreamMessageSessionClient interface {
	GetMessage(ctx context.Context, lastMessageID int, maxCapacity int) (*scaleset.RunnerScaleSetMessage, error)
	DeleteMessage(ctx context.Context, messageID int) error
	AcquireJobs(ctx context.Context, requestIDs []int64) ([]int64, error)
	Session() scaleset.RunnerScaleSetSession
	Close(ctx context.Context) error
}

var (
	_ upstreamClient               = (*scaleset.Client)(nil)
	_ upstreamMessageSessionClient = (*scaleset.MessageSessionClient)(nil)
)

func TestContractUpstreamTypesSatisfyPinnedInterfaces(t *testing.T) {
	// The interface satisfaction is already proven at compile time by the
	// package-level var _ assertions above; this test exists so `go test
	// -run TestContract...` (the brief's Step 2 RED command) has a runnable
	// name, and so a future accidental removal of the var _ lines still
	// leaves an explicit, named test asserting the same thing at runtime.
	var c upstreamClient = &scaleset.Client{}
	var s upstreamMessageSessionClient = &scaleset.MessageSessionClient{}
	if c == nil || s == nil {
		t.Fatal("unreachable: nil-checking a non-nil interface value")
	}
}

// ---------------------------------------------------------------------
// Fixture loading helpers.
// ---------------------------------------------------------------------

const fixtureDir = "../../tests/fixtures/scaleset/v0.4.0"

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureDir, name))
	if err != nil {
		t.Fatalf("readFixture(%q): %v", name, err)
	}
	return b
}

// ---------------------------------------------------------------------
// Fixture HTTP server: a single httptest.Server that replays the
// synthetic v0.4.0 wire fixtures under tests/fixtures/scaleset/v0.4.0/,
// with per-endpoint handlers a test can override before issuing calls
// (for example, swapping the message-queue GET handler for one that never
// responds, to prove Poll's deadline behavior).
// ---------------------------------------------------------------------

type fixtureServer struct {
	t   *testing.T
	srv *httptest.Server

	mu             sync.Mutex
	groupBody      []byte
	scaleSetBody   []byte
	jitBody        []byte
	jitStatus      int
	runnerBody     []byte
	runnerStatus   int
	mqGetHandler   http.HandlerFunc
	mqDelHandler   http.HandlerFunc
	acquireHandler http.HandlerFunc

	deleteMessageCalls int32
	acquireCalls       int32
}

// newFixtureServer starts a fixture server preloaded with the "happy path"
// canned responses (default runner group, the single-label example scale
// set, an empty message queue, a valid JIT config, a resolvable runner)
// and returns it started. Tests override individual fields under mu to
// change one endpoint's behavior without rebuilding the whole server.
func newFixtureServer(t *testing.T) *fixtureServer {
	t.Helper()

	fs := &fixtureServer{
		t:            t,
		groupBody:    readFixture(t, "runner_group_default.json"),
		scaleSetBody: readFixture(t, "runner_scale_set_single_label.json"),
		jitBody:      readFixture(t, "jit_config.json"),
		jitStatus:    http.StatusOK,
		runnerBody:   readFixture(t, "runner_reference.json"),
		runnerStatus: http.StatusOK,
	}
	fs.mqGetHandler = fs.defaultEmptyMessageHandler
	fs.mqDelHandler = fs.defaultDeleteMessageHandler
	fs.acquireHandler = fs.defaultAcquireHandler

	fs.srv = httptest.NewServer(http.HandlerFunc(fs.dispatch))
	t.Cleanup(fs.srv.Close)
	return fs
}

func (fs *fixtureServer) configURL(ownerRepo string) string {
	return fs.srv.URL + "/" + ownerRepo
}

func (fs *fixtureServer) mqURL() string {
	return fs.srv.URL + "/mq/42"
}

func (fs *fixtureServer) defaultEmptyMessageHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusAccepted)
}

func (fs *fixtureServer) defaultDeleteMessageHandler(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt32(&fs.deleteMessageCalls, 1)
	w.WriteHeader(http.StatusNoContent)
}

func (fs *fixtureServer) defaultAcquireHandler(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt32(&fs.acquireCalls, 1)
	var ids []int64
	_ = json.NewDecoder(r.Body).Decode(&ids)
	resp := struct {
		Count int     `json:"count"`
		Value []int64 `json:"value"`
	}{Count: len(ids), Value: ids}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// servePinnedMessage returns an mqGetHandler that always serves the given
// fixture envelope bytes verbatim (a real wire response), regardless of
// lastMessageId -- used to model an unacked message being redelivered.
func servePinnedMessage(body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}
}

// stallDuration bounds every "server that never completes a response"
// handler below. It must comfortably exceed every deadline-test client
// timeout (so the client always gives up first) while staying short
// enough that the whole suite -- including a `-count=20` repeat -- stays
// fast.
//
// This fixed bound, rather than `<-r.Context().Done()`, is deliberate: Go's
// net/http server can only detect a client abandoning a REQUEST WITH A
// BODY (POST/PATCH, e.g. AcquireJobs/GenerateJitRunnerConfig) via a
// background connection read, and that mechanism does not activate while
// a handler is blocked without ever reading the body -- so for bodied
// requests, r.Context() is never canceled server-side even after the
// client's own context deadline fires and Do() returns. This is an
// empirically-confirmed net/http behavior (see this task's report), not a
// bug in this adapter: the CLIENT-side call still returns promptly, which
// is what these tests assert. A fixed self-terminating bound is what
// keeps the server's handler goroutine (and therefore
// httptest.Server.Close in test cleanup) from hanging past that bound
// regardless of which HTTP verb is involved.
const stallDuration = 400 * time.Millisecond

// blockLongerThanClientDeadline never writes a meaningful response; it
// blocks for stallDuration (or until the request's own context is done,
// whichever comes first) and then returns. Every deadline test below uses
// a client-side operation timeout well under stallDuration, so the CLIENT
// always gives up first -- this handler's only job is to guarantee it
// does not block the *server* (and therefore test cleanup) indefinitely.
func blockLongerThanClientDeadline(w http.ResponseWriter, r *http.Request) {
	select {
	case <-r.Context().Done():
	case <-time.After(stallDuration):
	}
}

func (fs *fixtureServer) dispatch(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Snapshot the current handler/body configuration under the lock, then
	// release it before invoking anything that might block -- so a
	// deliberately stalling handler on one endpoint never blocks a
	// concurrent request to a different (or the same) endpoint from
	// observing this fixture server's configuration.
	fs.mu.Lock()
	groupBody := fs.groupBody
	scaleSetBody := fs.scaleSetBody
	jitBody := fs.jitBody
	jitStatus := fs.jitStatus
	runnerBody := fs.runnerBody
	runnerStatus := fs.runnerStatus
	mqGetHandler := fs.mqGetHandler
	mqDelHandler := fs.mqDelHandler
	acquireHandler := fs.acquireHandler
	fs.mu.Unlock()

	switch {
	case strings.HasSuffix(path, "/runners/registration-token"):
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"token":"placeholder-registration-token"}`))
		return

	case strings.HasSuffix(path, "/actions/runner-registration"):
		w.Header().Set("Content-Type", "application/json")
		body := fmt.Sprintf(`{"url":%q,"token":%q}`, fs.srv.URL+"/tenant/1", fakeAdminToken(time.Now().Add(time.Hour)))
		_, _ = w.Write([]byte(body))
		return

	case strings.HasSuffix(path, "/_apis/runtime/runnergroups/"):
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(groupBody)
		return

	case strings.Contains(path, "/sessions/"):
		// DELETE closes an existing session (MessageSessionClient.Close).
		w.WriteHeader(http.StatusNoContent)
		return

	case strings.HasSuffix(path, "/sessions"):
		// POST creates a new session; PATCH refreshes an expired one. Both
		// return the same session shape, pointed at this fixture server's
		// own message-queue sub-path.
		session := scaleset.RunnerScaleSetSession{
			SessionID:               uuid.New(),
			OwnerName:               "test-owner",
			MessageQueueURL:         fs.mqURL(),
			MessageQueueAccessToken: "placeholder-mq-token",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(session)
		return

	case strings.HasSuffix(path, "/generatejitconfig"):
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(jitStatus)
		_, _ = w.Write(jitBody)
		return

	case strings.HasSuffix(path, "/acquirejobs"):
		acquireHandler(w, r)
		return

	case strings.HasSuffix(path, "/_apis/runtime/runnerscalesets"):
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(scaleSetBody)
		return

	case strings.Contains(path, "/_apis/distributedtask/pools/0/agents"):
		if r.Method == http.MethodDelete {
			// RemoveRunner expects 204 No Content on success.
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(runnerStatus)
		_, _ = w.Write(runnerBody)
		return

	case strings.HasPrefix(path, "/mq/42"):
		if r.Method == http.MethodDelete {
			mqDelHandler(w, r)
			return
		}
		mqGetHandler(w, r)
		return

	default:
		fs.t.Errorf("fixtureServer: unexpected request %s %s", r.Method, path)
		w.WriteHeader(http.StatusNotFound)
	}
}

// fakeAdminToken builds a syntactically valid (but unsigned/garbage-signed)
// JWT carrying only an "exp" claim, sufficient for
// scaleset's actionsServiceAdminTokenExpiresAt, which decodes claims via
// jwt.Parser.ParseUnverified (no signature check) purely to read the
// expiry. No real signing key or credential is involved.
func fakeAdminToken(expiresAt time.Time) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d,"iss":"123"}`, expiresAt.Unix())))
	sig := base64.RawURLEncoding.EncodeToString([]byte("placeholder-signature"))
	return header + "." + payload + "." + sig
}

// ---------------------------------------------------------------------
// Test-only client/session construction against the fixture server. Uses
// a short OperationTimeout/ResponseHeaderTimeout by default so deadline
// tests stay fast; individual tests override via newTestClient's options.
// ---------------------------------------------------------------------

func newTestClient(t *testing.T, fs *fixtureServer, opTimeout, headerTimeout time.Duration) Client {
	t.Helper()
	c, err := NewClient(ClientConfig{
		GitHubConfigURL:       fs.configURL("owner/repository"),
		PersonalAccessToken:   "placeholder-pat-token",
		System:                "portable-ghar-test",
		OperationTimeout:      opTimeout,
		ResponseHeaderTimeout: headerTimeout,
		retryableHTTPClient:   newRetryableHTTPClient(headerTimeout),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func openTestSession(t *testing.T, c Client) Session {
	t.Helper()
	sess, err := c.Open(context.Background(), Fleet{
		RepositoryAlias: "example-fleet",
		GitHubConfigURL: "https://github.com/owner/repository",
		ScaleSetName:    "example-scaleset",
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close(context.Background()) })
	return sess
}

// ---------------------------------------------------------------------
// Translation tests: all four job-message shapes, statistics
// preservation, nil polls, redelivery, duplicate message IDs, and the
// same job reappearing under a new runner-request ID.
// ---------------------------------------------------------------------

func TestTranslateBatchAllFourMessageTypes(t *testing.T) {
	fs := newFixtureServer(t)
	fs.mqGetHandler = servePinnedMessage(readFixture(t, "message_batch_full.json"))

	c := newTestClient(t, fs, 5*time.Second, 5*time.Second)
	sess := openTestSession(t, c)

	batch, err := sess.Poll(context.Background(), 0, 10)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if batch.Empty {
		t.Fatal("Poll: got Empty batch, want a populated one")
	}
	if batch.MessageID != 101 {
		t.Fatalf("Poll: MessageID = %d, want 101", batch.MessageID)
	}

	if got, want := batch.Statistics.TotalAssignedJobs, 3; got != want {
		t.Fatalf("Statistics.TotalAssignedJobs = %d, want %d (must be preserved unchanged)", got, want)
	}
	if got, want := batch.Statistics.TotalAvailableJobs, 1; got != want {
		t.Fatalf("Statistics.TotalAvailableJobs = %d, want %d", got, want)
	}

	if len(batch.Offers) != 1 {
		t.Fatalf("Offers: got %d, want 1", len(batch.Offers))
	}
	offer := batch.Offers[0]
	if offer.RunnerRequestID != 9001 {
		t.Errorf("Offer.RunnerRequestID = %d, want 9001", offer.RunnerRequestID)
	}
	if offer.JobID != "00000000-0000-4000-8000-000000000001" {
		t.Errorf("Offer.JobID = %q, want the fixture's job 1 GUID", offer.JobID)
	}
	if offer.AcquireJobURL == "" {
		t.Error("Offer.AcquireJobURL is empty, want the fixture's synthetic TEST-NET-2 URL")
	}
	if offer.OwnerName != "owner" || offer.RepositoryName != "repository" {
		t.Errorf("Offer owner/repo = %q/%q, want owner/repository", offer.OwnerName, offer.RepositoryName)
	}

	if len(batch.Assigned) != 1 || batch.Assigned[0].RunnerRequestID != 9002 {
		t.Fatalf("Assigned = %+v, want one event with RunnerRequestID 9002", batch.Assigned)
	}

	if len(batch.Started) != 1 {
		t.Fatalf("Started: got %d, want 1", len(batch.Started))
	}
	started := batch.Started[0]
	if started.RunnerRequestID != 9003 || started.RunnerID != 501 || started.RunnerName != "example-fleet-runner-0001" {
		t.Errorf("Started = %+v, want RunnerRequestID=9003 RunnerID=501 RunnerName=example-fleet-runner-0001", started)
	}

	if len(batch.Completed) != 1 {
		t.Fatalf("Completed: got %d, want 1", len(batch.Completed))
	}
	completed := batch.Completed[0]
	if completed.RunnerRequestID != 9004 || completed.Result != "success" || completed.RunnerID != 502 {
		t.Errorf("Completed = %+v, want RunnerRequestID=9004 Result=success RunnerID=502", completed)
	}

	if atomic.LoadInt32(&fs.deleteMessageCalls) != 0 {
		t.Fatalf("Poll alone must never call DeleteMessage; got %d calls", fs.deleteMessageCalls)
	}
}

func TestNilPollWhenNoMessageAvailable(t *testing.T) {
	fs := newFixtureServer(t)
	// fs.mqGetHandler defaults to defaultEmptyMessageHandler (202 Accepted,
	// no body) -- the upstream API's documented (nil, nil) response.
	c := newTestClient(t, fs, 5*time.Second, 5*time.Second)
	sess := openTestSession(t, c)

	batch, err := sess.Poll(context.Background(), 0, 10)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if !batch.Empty {
		t.Fatalf("Poll: got %+v, want Empty batch for upstream's nil-message response", batch)
	}
	if len(batch.Offers)+len(batch.Assigned)+len(batch.Started)+len(batch.Completed) != 0 {
		t.Fatalf("Poll: empty batch carries non-empty event slices: %+v", batch)
	}
}

func TestRedeliveryUnackedMessageReappearsOnNextPoll(t *testing.T) {
	fs := newFixtureServer(t)
	fs.mqGetHandler = servePinnedMessage(readFixture(t, "message_batch_full.json"))

	c := newTestClient(t, fs, 5*time.Second, 5*time.Second)
	sess := openTestSession(t, c)

	first, err := sess.Poll(context.Background(), 0, 10)
	if err != nil {
		t.Fatalf("Poll #1: %v", err)
	}
	second, err := sess.Poll(context.Background(), 0, 10)
	if err != nil {
		t.Fatalf("Poll #2: %v", err)
	}

	if first.MessageID != second.MessageID {
		t.Fatalf("redelivery: MessageID changed across unacked polls: %d vs %d", first.MessageID, second.MessageID)
	}
	if first.MessageID != 101 {
		t.Fatalf("redelivery: MessageID = %d, want the fixture's 101 (duplicate batch ID across redelivery)", first.MessageID)
	}
	if atomic.LoadInt32(&fs.deleteMessageCalls) != 0 {
		t.Fatalf("redelivery test never called Ack; DeleteMessage must not have been hit, got %d calls", fs.deleteMessageCalls)
	}
}

func TestAckThenPollNoLongerRedelivers(t *testing.T) {
	fs := newFixtureServer(t)
	fs.mqGetHandler = servePinnedMessage(readFixture(t, "message_batch_full.json"))

	c := newTestClient(t, fs, 5*time.Second, 5*time.Second)
	sess := openTestSession(t, c)

	batch, err := sess.Poll(context.Background(), 0, 10)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if err := sess.Ack(context.Background(), batch.MessageID); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if got := atomic.LoadInt32(&fs.deleteMessageCalls); got != 1 {
		t.Fatalf("DeleteMessage calls = %d, want exactly 1 after a single Ack", got)
	}

	// The fixture server always serves the same pinned message regardless
	// of Ack (it is not a stateful queue), so this only re-confirms Ack
	// hit the wire exactly once -- the fake-session test below proves the
	// actual redelivery-on-persist-failure *policy*.
}

func TestSameWorkflowJobReappearsWithNewRunnerRequestID(t *testing.T) {
	fs := newFixtureServer(t)
	fs.mqGetHandler = servePinnedMessage(readFixture(t, "message_batch_requeued_job.json"))

	c := newTestClient(t, fs, 5*time.Second, 5*time.Second)
	sess := openTestSession(t, c)

	batch, err := sess.Poll(context.Background(), 0, 10)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(batch.Offers) != 2 {
		t.Fatalf("Offers: got %d, want 2 (same job re-queued under a new runner-request ID)", len(batch.Offers))
	}
	a, b := batch.Offers[0], batch.Offers[1]
	if a.JobID != b.JobID {
		t.Fatalf("expected both offers to share the same JobID; got %q and %q", a.JobID, b.JobID)
	}
	if a.RunnerRequestID == b.RunnerRequestID {
		t.Fatalf("expected distinct RunnerRequestIDs for the re-queued job; both were %d", a.RunnerRequestID)
	}
	if a.WorkflowRunID != b.WorkflowRunID {
		t.Fatalf("expected both offers to share the same WorkflowRunID; got %d and %d", a.WorkflowRunID, b.WorkflowRunID)
	}
}

// ---------------------------------------------------------------------
// Single-name-label rule (Open).
// ---------------------------------------------------------------------

func TestSingleNameLabelRule(t *testing.T) {
	cases := []struct {
		name     string
		fixture  string
		wantOpen bool
		wantWrap error
	}{
		{name: "exactly one matching label accepts", fixture: "runner_scale_set_single_label.json", wantOpen: true},
		{name: "no labels rejects", fixture: "runner_scale_set_no_label.json", wantOpen: false, wantWrap: ErrLabelMismatch},
		{name: "two labels rejects", fixture: "runner_scale_set_multi_label.json", wantOpen: false, wantWrap: ErrLabelMismatch},
		{name: "one mismatched-name label rejects", fixture: "runner_scale_set_mismatched_label.json", wantOpen: false, wantWrap: ErrLabelMismatch},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := newFixtureServer(t)
			fs.scaleSetBody = readFixture(t, tc.fixture)

			c := newTestClient(t, fs, 5*time.Second, 5*time.Second)
			sess, err := c.Open(context.Background(), Fleet{
				RepositoryAlias: "example-fleet",
				GitHubConfigURL: "https://github.com/owner/repository",
				ScaleSetName:    "example-scaleset",
			})

			if tc.wantOpen {
				if err != nil {
					t.Fatalf("Open: unexpected error: %v", err)
				}
				_ = sess.Close(context.Background())
				return
			}

			if err == nil {
				t.Fatal("Open: got nil error, want a label-mismatch rejection")
			}
			if !errors.Is(err, tc.wantWrap) {
				t.Fatalf("Open: err = %v, want it to wrap %v", err, tc.wantWrap)
			}
		})
	}
}

func TestScaleSetNotFoundRejectsOpen(t *testing.T) {
	fs := newFixtureServer(t)
	fs.scaleSetBody = []byte(`{"count":0,"value":[]}`)

	c := newTestClient(t, fs, 5*time.Second, 5*time.Second)
	_, err := c.Open(context.Background(), Fleet{
		RepositoryAlias: "example-fleet",
		GitHubConfigURL: "https://github.com/owner/repository",
		ScaleSetName:    "example-scaleset",
	})
	if err == nil {
		t.Fatal("Open: got nil error, want ErrScaleSetNotFound")
	}
	if !errors.Is(err, ErrScaleSetNotFound) {
		t.Fatalf("Open: err = %v, want it to wrap ErrScaleSetNotFound", err)
	}
}

// ---------------------------------------------------------------------
// Deadline / cancellation: prove Poll, Acquire, and GenerateJIT never
// hang against a server that never completes a response.
// ---------------------------------------------------------------------

// deadlineTestBudget is how long the CLIENT side of a deadline test may
// take before we consider it "hung." It must comfortably exceed
// opTimeout/headerTimeout below (so normal retries/backoff have room) but
// stay far under stallDuration's server-side bound would ever require.
const deadlineTestBudget = 3 * time.Second

func TestDeadlineExceededNeverHangs(t *testing.T) {
	const opTimeout = 100 * time.Millisecond
	const headerTimeout = 40 * time.Millisecond

	t.Run("Poll", func(t *testing.T) {
		fs := newFixtureServer(t)
		fs.mqGetHandler = blockLongerThanClientDeadline

		c := newTestClient(t, fs, opTimeout, headerTimeout)
		sess := openTestSession(t, c)

		start := time.Now()
		_, err := sess.Poll(context.Background(), 0, 10)
		elapsed := time.Since(start)

		if err == nil {
			t.Fatal("Poll against a stalling server: got nil error, want a deadline error")
		}
		if elapsed > deadlineTestBudget {
			t.Fatalf("Poll took %s, want it bounded well under the %s test budget", elapsed, deadlineTestBudget)
		}
	})

	t.Run("Acquire", func(t *testing.T) {
		fs := newFixtureServer(t)
		fs.acquireHandler = blockLongerThanClientDeadline

		c := newTestClient(t, fs, opTimeout, headerTimeout)
		sess := openTestSession(t, c)

		start := time.Now()
		_, err := sess.Acquire(context.Background(), []int64{9001})
		elapsed := time.Since(start)

		if err == nil {
			t.Fatal("Acquire against a stalling server: got nil error, want a deadline error")
		}
		if elapsed > deadlineTestBudget {
			t.Fatalf("Acquire took %s, want it bounded well under the %s test budget", elapsed, deadlineTestBudget)
		}
	})

	t.Run("GenerateJIT", func(t *testing.T) {
		// generatejitconfig has no dedicated fixtureServer field to swap
		// (unlike mqGetHandler/acquireHandler), so this subtest wraps a
		// second, dedicated server's whole dispatcher instead.
		fs := newFixtureServer(t)
		origDispatch := fs.srv.Config.Handler
		fs.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/generatejitconfig") {
				blockLongerThanClientDeadline(w, r)
				return
			}
			origDispatch.ServeHTTP(w, r)
		})

		c := newTestClient(t, fs, opTimeout, headerTimeout)
		sess := openTestSession(t, c)

		start := time.Now()
		_, err := sess.GenerateJIT(context.Background(), JITRequest{RunnerName: "example-fleet-runner-0001"})
		elapsed := time.Since(start)

		if err == nil {
			t.Fatal("GenerateJIT against a stalling server: got nil error, want a deadline error")
		}
		if elapsed > deadlineTestBudget {
			t.Fatalf("GenerateJIT took %s, want it bounded well under the %s test budget", elapsed, deadlineTestBudget)
		}
	})
}

func TestExplicitCancellationReturnsPromptly(t *testing.T) {
	fs := newFixtureServer(t)
	fs.mqGetHandler = blockLongerThanClientDeadline

	c := newTestClient(t, fs, 30*time.Second, 30*time.Second)
	sess := openTestSession(t, c)

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)

	start := time.Now()
	_, err := sess.Poll(ctx, 0, 10)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Poll: got nil error after caller cancellation, want an error")
	}
	if elapsed > deadlineTestBudget {
		t.Fatalf("Poll took %s after explicit cancellation, want it bounded well under %s", elapsed, deadlineTestBudget)
	}
}

// ---------------------------------------------------------------------
// GenerateJIT: shape mismatch and Secret wrapping.
// ---------------------------------------------------------------------

func TestGenerateJITShapeMismatchRejected(t *testing.T) {
	fs := newFixtureServer(t)
	fs.jitBody = readFixture(t, "jit_config_shape_mismatch.json")

	c := newTestClient(t, fs, 5*time.Second, 5*time.Second)
	sess := openTestSession(t, c)

	cfg, err := sess.GenerateJIT(context.Background(), JITRequest{RunnerName: "example-fleet-runner-0001"})
	if err == nil {
		t.Fatal("GenerateJIT: got nil error for a shape-mismatched response, want ErrJITShapeMismatch")
	}
	if !errors.Is(err, ErrJITShapeMismatch) {
		t.Fatalf("GenerateJIT: err = %v, want it to wrap ErrJITShapeMismatch", err)
	}
	if cfg.Encoded != nil {
		t.Fatal("GenerateJIT: shape-mismatch path must return a zero-value JITConfig (Encoded == nil)")
	}
}

func TestGenerateJITWrapsEncodedConfigIntoSecret(t *testing.T) {
	fs := newFixtureServer(t)
	fs.jitBody = readFixture(t, "jit_config.json")

	c := newTestClient(t, fs, 5*time.Second, 5*time.Second)
	sess := openTestSession(t, c)

	cfg, err := sess.GenerateJIT(context.Background(), JITRequest{RunnerName: "example-fleet-runner-0001"})
	if err != nil {
		t.Fatalf("GenerateJIT: %v", err)
	}
	if cfg.Runner.ID != 501 || cfg.Runner.Name != "example-fleet-runner-0001" || cfg.Runner.RunnerScaleSetID != 42 {
		t.Fatalf("GenerateJIT: Runner = %+v, want the fixture's runner", cfg.Runner)
	}
	if cfg.Encoded == nil {
		t.Fatal("GenerateJIT: Encoded is nil, want a wrapped redaction.Secret")
	}

	// String()/formatting must never reveal the encoded token.
	if formatted := fmt.Sprintf("%v", cfg.Encoded); strings.Contains(formatted, "PLACEHOLDER.JIT.CONFIG.TOKEN") {
		t.Fatalf("Encoded.String() leaked the raw JIT token: %q", formatted)
	}

	// The actual bytes must, within the Use scope, match the fixture's
	// encodedJITConfig value.
	var fixture struct {
		EncodedJITConfig string `json:"encodedJITConfig"`
	}
	if err := json.Unmarshal(readFixture(t, "jit_config.json"), &fixture); err != nil {
		t.Fatalf("re-decoding fixture: %v", err)
	}

	var gotBytes []byte
	err = cfg.Encoded.Use(func(r io.Reader) error {
		buf := make([]byte, 4096)
		n, readErr := r.Read(buf)
		for readErr == nil {
			gotBytes = append(gotBytes, buf[:n]...)
			n, readErr = r.Read(buf)
		}
		if n > 0 {
			gotBytes = append(gotBytes, buf[:n]...)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Encoded.Use: %v", err)
	}
	if string(gotBytes) != fixture.EncodedJITConfig {
		t.Fatalf("Encoded bytes = %q, want the fixture's %q", gotBytes, fixture.EncodedJITConfig)
	}
	cfg.Encoded.Destroy()
}

// ---------------------------------------------------------------------
// GetRunner / GetRunnerByName / RemoveRunner.
// ---------------------------------------------------------------------

func TestGetRunnerByNameNotFound(t *testing.T) {
	fs := newFixtureServer(t)
	fs.runnerBody = readFixture(t, "runner_reference_list_not_found.json")

	c := newTestClient(t, fs, 5*time.Second, 5*time.Second)
	sess := openTestSession(t, c)

	_, err := sess.GetRunnerByName(context.Background(), "does-not-exist")
	if !errors.Is(err, ErrRunnerNotFound) {
		t.Fatalf("GetRunnerByName: err = %v, want it to wrap ErrRunnerNotFound", err)
	}
}

func TestGetRunnerAndRemoveRunner(t *testing.T) {
	fs := newFixtureServer(t)

	c := newTestClient(t, fs, 5*time.Second, 5*time.Second)
	sess := openTestSession(t, c)

	ref, err := sess.GetRunner(context.Background(), 501)
	if err != nil {
		t.Fatalf("GetRunner: %v", err)
	}
	if ref.ID != 501 || ref.Name != "example-fleet-runner-0001" {
		t.Fatalf("GetRunner: got %+v, want the fixture's runner", ref)
	}

	if err := sess.RemoveRunner(context.Background(), 501); err != nil {
		t.Fatalf("RemoveRunner: %v", err)
	}
}

// ---------------------------------------------------------------------
// CompatibilityReport / version gate (Probe).
// ---------------------------------------------------------------------

// TestProbeCompatibleWithPinnedLiveBuild proves Probe's happy path against
// a genuinely COMPILED binary (`go build`), not the `go test` binary.
//
// This distinction is load-bearing: empirically, `go test` binaries in
// this toolchain report an EMPTY runtime/debug.BuildInfo.Deps list even
// when the package under test imports actions/scaleset directly, while an
// ordinary `go build` binary that imports it correctly reports
// `github.com/actions/scaleset v0.4.0` in Deps (verified directly against
// this repo's module graph while diagnosing this test -- see this task's
// report). Calling Probe() in-process here would therefore always
// observe found=false regardless of whether the ADAPTER's logic is
// correct, which is exactly the kind of false negative (or false
// positive, had the test been written to tolerate it) this task must not
// ship. So this test builds and runs a real, tiny helper binary under the
// module tree (required so it can import the internal package) and
// asserts on ITS printed CompatibilityReport -- proving the actual
// runtime/debug.ReadBuildInfo()-based gate a production controller binary
// will see.
func TestProbeCompatibleWithPinnedLiveBuild(t *testing.T) {
	moduleRoot := findModuleRoot(t)
	helperDir := filepath.Join(moduleRoot, "internal", "githubscale", "testdata", "zz_liveprobe_helper")
	if err := os.MkdirAll(helperDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", helperDir, err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(helperDir) })

	helperSrc := `package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/sumitake/portable-ghar/internal/githubscale"
)

func main() {
	report, err := githubscale.Probe(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(report)
}
`

	if err := os.WriteFile(filepath.Join(helperDir, "main.go"), []byte(helperSrc), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	binPath := filepath.Join(t.TempDir(), "zz_liveprobe_helper")
	buildCmd := exec.Command("go", "build", "-o", binPath, "./internal/githubscale/testdata/zz_liveprobe_helper")
	buildCmd.Dir = moduleRoot
	buildCmd.Env = append(os.Environ(), "GOTOOLCHAIN=go1.26.5")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build helper: %v\n%s", err, out)
	}

	runCmd := exec.Command(binPath)
	out, err := runCmd.Output()
	if err != nil {
		t.Fatalf("run helper: %v", err)
	}

	var report CompatibilityReport
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("decode helper output %q: %v", out, err)
	}

	pin := buildinfo.Pins().Scaleset
	if !report.Compatible {
		t.Fatalf("live-build Probe: Compatible = false, report = %+v", report)
	}
	if report.ExpectedVersion != pin.Version {
		t.Errorf("ExpectedVersion = %q, want %q", report.ExpectedVersion, pin.Version)
	}
	if report.LinkedVersion != pin.Version {
		t.Errorf("LinkedVersion = %q, want %q (a real build links the pinned module)", report.LinkedVersion, pin.Version)
	}
	if report.Commit != pin.Commit {
		t.Errorf("Commit = %q, want %q", report.Commit, pin.Commit)
	}
	if report.License != "MIT" {
		t.Errorf("License = %q, want MIT", report.License)
	}
}

// findModuleRoot walks up from the current package directory to find the
// directory containing go.mod, so the live-build helper above can be
// placed under the module tree (required to import the internal package)
// regardless of the working directory `go test` was invoked from.
func findModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("findModuleRoot: no go.mod found walking up from package directory")
		}
		dir = parent
	}
}

func TestProbeRespectsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := Probe(ctx)
	if err == nil {
		t.Fatal("Probe: got nil error for an already-canceled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Probe: err = %v, want it to wrap context.Canceled", err)
	}
}

func TestEvaluateCompatibilityRejectsWrongVersion(t *testing.T) {
	pin := buildinfo.Pins().Scaleset
	report, err := evaluateCompatibility(pin, "v0.3.9", true)
	if err == nil {
		t.Fatal("evaluateCompatibility: got nil error for a mismatched version")
	}
	if !errors.Is(err, ErrIncompatibleModuleVersion) {
		t.Fatalf("evaluateCompatibility: err = %v, want it to wrap ErrIncompatibleModuleVersion", err)
	}
	if report.Compatible {
		t.Fatal("evaluateCompatibility: Compatible = true for a mismatched version")
	}
	if report.LinkedVersion != "v0.3.9" {
		t.Errorf("LinkedVersion = %q, want v0.3.9", report.LinkedVersion)
	}
	if report.Reason == "" {
		t.Error("Reason is empty, want an explanation of the mismatch")
	}
}

func TestEvaluateCompatibilityRejectsMissingDependency(t *testing.T) {
	pin := buildinfo.Pins().Scaleset
	report, err := evaluateCompatibility(pin, "", false)
	if err == nil {
		t.Fatal("evaluateCompatibility: got nil error when the dependency is not linked at all")
	}
	if !errors.Is(err, ErrIncompatibleModuleVersion) {
		t.Fatalf("evaluateCompatibility: err = %v, want it to wrap ErrIncompatibleModuleVersion", err)
	}
	if report.Compatible {
		t.Fatal("evaluateCompatibility: Compatible = true when the dependency is not linked at all")
	}
}

func TestEvaluateCompatibilityAcceptsExactPin(t *testing.T) {
	pin := buildinfo.Pins().Scaleset
	report, err := evaluateCompatibility(pin, pin.Version, true)
	if err != nil {
		t.Fatalf("evaluateCompatibility: unexpected error for an exact pin match: %v", err)
	}
	if !report.Compatible {
		t.Fatalf("evaluateCompatibility: Compatible = false for an exact pin match, report = %+v", report)
	}
}

// ---------------------------------------------------------------------
// JITConfig.Encoded copy-safety: a *redaction.Secret (pointer), never a
// value redaction.Secret. See types.go's JITConfig doc for why: a value
// field would make the ordinary `cfg := session.GenerateJIT(...)`
// assignment at every call site a `go vet` copylocks violation. This test
// exercises the actual intended usage pattern (assign, pass around, read
// via Use) to prove it is copy-and-vet-safe as designed; `go vet
// ./internal/githubscale` (captured in this task's report) is the
// authoritative proof that no copylocks violation exists anywhere in this
// package.
func TestJITConfigEncodedFieldIsPointerForCopySafety(t *testing.T) {
	secret := redaction.SecretFromBytes([]byte("test-only-value"))
	cfg := JITConfig{Runner: RunnerRef{ID: 1, Name: "r"}, Encoded: secret}

	// Ordinary copy/assignment of JITConfig by value must be legal (this
	// is exactly what `cfg, err := session.GenerateJIT(...)` does at every
	// real call site) precisely because Encoded is a pointer.
	cfg2 := cfg
	if cfg2.Encoded != cfg.Encoded {
		t.Fatal("copying JITConfig by value did not preserve the Encoded pointer identity")
	}
	cfg.Encoded.Destroy()
}

// ---------------------------------------------------------------------
// Ack discipline (Step 4): Poll -> (caller persists) -> Ack, proven with a
// fake Session. The real v040Session's half of this contract -- Poll
// itself never calling DeleteMessage -- is proven separately against the
// live fixture server in TestTranslateBatchAllFourMessageTypes and
// TestRedeliveryUnackedMessageReappearsOnNextPoll (both assert
// fs.deleteMessageCalls == 0 after Poll-only activity).
// ---------------------------------------------------------------------

// fakeAckSession is a minimal in-memory Session implementation used only
// to prove the Poll -> persist -> Ack discipline Session's doc requires.
// It holds at most one pending message; Poll redelivers it on every call
// until Ack is called for its MessageID, after which Poll reports Empty.
// It is safe for concurrent use (guarded by mu) so it can also be
// exercised under `go test -race -count=20` per the brief's Step 4.
type fakeAckSession struct {
	mu        sync.Mutex
	pending   *Batch
	acked     []int
	pollCalls int
}

var _ Session = (*fakeAckSession)(nil)

func newFakeAckSession(b Batch) *fakeAckSession {
	cp := b
	return &fakeAckSession{pending: &cp}
}

func (f *fakeAckSession) Poll(ctx context.Context, lastMessageID, maxCapacity int) (Batch, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pollCalls++
	if f.pending == nil {
		return Batch{Empty: true}, nil
	}
	return *f.pending, nil
}

func (f *fakeAckSession) Ack(ctx context.Context, messageID int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acked = append(f.acked, messageID)
	f.pending = nil
	return nil
}

func (f *fakeAckSession) ackedIDs() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int(nil), f.acked...)
}

func (f *fakeAckSession) Acquire(ctx context.Context, requestIDs []int64) ([]int64, error) {
	return nil, fmt.Errorf("fakeAckSession: Acquire not implemented")
}

func (f *fakeAckSession) GenerateJIT(ctx context.Context, req JITRequest) (JITConfig, error) {
	return JITConfig{}, fmt.Errorf("fakeAckSession: GenerateJIT not implemented")
}

func (f *fakeAckSession) GetRunnerByName(ctx context.Context, name string) (RunnerRef, error) {
	return RunnerRef{}, fmt.Errorf("fakeAckSession: GetRunnerByName not implemented")
}

func (f *fakeAckSession) GetRunner(ctx context.Context, id int64) (RunnerRef, error) {
	return RunnerRef{}, fmt.Errorf("fakeAckSession: GetRunner not implemented")
}

func (f *fakeAckSession) RemoveRunner(ctx context.Context, id int64) error {
	return fmt.Errorf("fakeAckSession: RemoveRunner not implemented")
}

func (f *fakeAckSession) Close(ctx context.Context) error {
	return nil
}

// processOnePoll models the discipline every real caller (a later task's
// reconciler) must follow: Poll, then durably persist, and only call Ack
// if persistence succeeded. It returns whether Ack was called.
func processOnePoll(ctx context.Context, sess Session, persistOK bool) (acked bool, err error) {
	batch, err := sess.Poll(ctx, 0, 10)
	if err != nil {
		return false, fmt.Errorf("poll: %w", err)
	}
	if batch.Empty {
		return false, fmt.Errorf("no message to process")
	}
	if !persistOK {
		// Persistence failed: the caller must NOT Ack, so the message is
		// redelivered on the next Poll.
		return false, fmt.Errorf("simulated persistence failure")
	}
	if err := sess.Ack(ctx, batch.MessageID); err != nil {
		return false, fmt.Errorf("ack: %w", err)
	}
	return true, nil
}

func TestAckDisciplinePersistFailureBlocksAckAndRedelivers(t *testing.T) {
	fake := newFakeAckSession(Batch{
		MessageID: 55,
		Offers:    []Offer{{JobRef: JobRef{RunnerRequestID: 1}}},
	})
	ctx := context.Background()

	// Cycle 1: persistence fails -> zero Ack calls, message redelivered.
	if _, err := processOnePoll(ctx, fake, false); err == nil {
		t.Fatal("processOnePoll: expected the simulated persistence failure to propagate")
	}
	if got := fake.ackedIDs(); len(got) != 0 {
		t.Fatalf("Ack calls = %v, want none after a persistence failure", got)
	}

	redelivered, err := fake.Poll(ctx, 0, 10)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if redelivered.Empty || redelivered.MessageID != 55 {
		t.Fatalf("Poll after a failed persist = %+v, want message 55 redelivered", redelivered)
	}

	// Cycle 2: persistence succeeds -> exactly one Ack call, for the same
	// message ID.
	acked, err := processOnePoll(ctx, fake, true)
	if err != nil {
		t.Fatalf("processOnePoll: %v", err)
	}
	if !acked {
		t.Fatal("processOnePoll: expected the message to be acked on a successful persist")
	}
	if got := fake.ackedIDs(); len(got) != 1 || got[0] != 55 {
		t.Fatalf("Ack calls = %v, want exactly [55]", got)
	}

	// No further redelivery once acked.
	final, err := fake.Poll(ctx, 0, 10)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if !final.Empty {
		t.Fatalf("Poll after Ack = %+v, want Empty (no further redelivery)", final)
	}
}
