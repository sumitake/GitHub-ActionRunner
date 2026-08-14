package githubscale

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/actions/scaleset"
	"github.com/google/uuid"
	"github.com/hashicorp/go-retryablehttp"
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

type canonicalRunnerLookup interface {
	GetRunnerByName(context.Context, string) (RunnerRef, bool, error)
	GetRunner(context.Context, int64) (RunnerRef, bool, error)
}

var (
	_ upstreamClient               = (*scaleset.Client)(nil)
	_ upstreamMessageSessionClient = (*scaleset.MessageSessionClient)(nil)
	_ canonicalRunnerLookup        = (Session)(nil)
)

func TestContractUpstreamTypesSatisfyPinnedInterfaces(t *testing.T) {
	// The interface satisfaction is already proven at compile time by the
	// package-level var _ assertions above; this test exists so `go test
	// -run TestContract...` (the brief's Step 2 RED command) has a runnable
	// name, and so a future accidental removal of the var _ lines still
	// leaves explicit, named compile-time assignments here.
	var _ upstreamClient = (*scaleset.Client)(nil)
	var _ upstreamMessageSessionClient = (*scaleset.MessageSessionClient)(nil)
}

// ---------------------------------------------------------------------
// Fixture loading helpers.
// ---------------------------------------------------------------------

const (
	fixtureDir           = "../../tests/fixtures/scaleset/v0.4.0"
	testMaxResponseBytes = int64(1 << 20)
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureDir, name))
	if err != nil {
		t.Fatalf("readFixture(%q): %v", name, err)
	}
	return b
}

func jobIDFromMessageFixture(t *testing.T, name string, index int) string {
	t.Helper()
	var envelope struct {
		Body string `json:"body"`
	}
	if err := json.Unmarshal(readFixture(t, name), &envelope); err != nil {
		t.Fatalf("decode message fixture %q: %v", name, err)
	}
	var messages []struct {
		JobID string `json:"jobId"`
	}
	if err := json.Unmarshal([]byte(envelope.Body), &messages); err != nil {
		t.Fatalf("decode message fixture %q body: %v", name, err)
	}
	if index < 0 || index >= len(messages) {
		t.Fatalf("message fixture %q index %d outside %d messages", name, index, len(messages))
	}
	return messages[index].JobID
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

	mu              sync.Mutex
	groupBody       []byte
	scaleSetBody    []byte
	jitBody         []byte
	jitStatus       int
	jitHandler      http.HandlerFunc
	runnerBody      []byte
	runnerStatus    int
	groupHandler    http.HandlerFunc
	scaleSetHandler http.HandlerFunc
	sessionHandler  http.HandlerFunc
	runnerHandler   http.HandlerFunc
	mqGetHandler    http.HandlerFunc
	mqDelHandler    http.HandlerFunc
	acquireHandler  http.HandlerFunc

	deleteMessageCalls int32
	acquireCalls       int32
	requestCalls       int32
	sessionCreateCalls int32
	maxCapacityHeader  string
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

func serveUntrustedUpstreamError(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(body))
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
	atomic.AddInt32(&fs.requestCalls, 1)
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
	jitHandler := fs.jitHandler
	runnerBody := fs.runnerBody
	runnerStatus := fs.runnerStatus
	groupHandler := fs.groupHandler
	scaleSetHandler := fs.scaleSetHandler
	sessionHandler := fs.sessionHandler
	runnerHandler := fs.runnerHandler
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
		if groupHandler != nil {
			groupHandler(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(groupBody)
		return

	case strings.Contains(path, "/sessions/"):
		if sessionHandler != nil {
			sessionHandler(w, r)
			return
		}
		// DELETE closes an existing session (MessageSessionClient.Close).
		w.WriteHeader(http.StatusNoContent)
		return

	case strings.HasSuffix(path, "/sessions"):
		if sessionHandler != nil {
			sessionHandler(w, r)
			return
		}
		// POST creates a new session; PATCH refreshes an expired one. Both
		// return the same session shape, pointed at this fixture server's
		// own message-queue sub-path.
		atomic.AddInt32(&fs.sessionCreateCalls, 1)
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
		if jitHandler != nil {
			jitHandler(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(jitStatus)
		_, _ = w.Write(jitBody)
		return

	case strings.HasSuffix(path, "/acquirejobs"):
		acquireHandler(w, r)
		return

	case strings.HasSuffix(path, "/_apis/runtime/runnerscalesets"):
		if scaleSetHandler != nil {
			scaleSetHandler(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(scaleSetBody)
		return

	case strings.Contains(path, "/_apis/distributedtask/pools/0/agents"):
		if runnerHandler != nil {
			runnerHandler(w, r)
			return
		}
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
		fs.mu.Lock()
		fs.maxCapacityHeader = r.Header.Get(scaleset.HeaderScaleSetMaxCapacity)
		fs.mu.Unlock()
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
	return newTestClientWithRetryMax(t, fs, opTimeout, headerTimeout, 4)
}

func newTestClientWithRetryMax(t *testing.T, fs *fixtureServer, opTimeout, headerTimeout time.Duration, retryMax int) Client {
	t.Helper()
	return newTestClientWithResponseLimit(t, fs, opTimeout, headerTimeout, testMaxResponseBytes, retryMax)
}

func newTestClientWithResponseLimit(
	t *testing.T,
	fs *fixtureServer,
	opTimeout, headerTimeout time.Duration,
	maxResponseBytes int64,
	retryMax int,
) Client {
	t.Helper()
	retryable := newRetryableHTTPClient(headerTimeout)
	retryable.RetryMax = retryMax
	retryable.RetryWaitMin = time.Millisecond
	retryable.RetryWaitMax = time.Millisecond
	c, err := NewClient(ClientConfig{
		GitHubConfigURL:       fs.configURL("owner/repository"),
		PersonalAccessToken:   "placeholder-pat-token",
		System:                "portable-ghar-test",
		OperationTimeout:      opTimeout,
		ResponseHeaderTimeout: headerTimeout,
		MaxResponseBytes:      maxResponseBytes,
		retryableHTTPClient:   retryable,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	forceCompatibleProbe(t, c)
	return c
}

func forceCompatibleProbe(t *testing.T, c Client) {
	t.Helper()
	impl, ok := c.(*client)
	if !ok {
		t.Fatalf("test client implementation = %T, want *client", c)
	}
	impl.probe = func(context.Context) (CompatibilityReport, error) {
		return CompatibilityReport{Compatible: true}, nil
	}
}

func openTestSession(t *testing.T, c Client) Session {
	t.Helper()
	impl := c.(*client)
	sess, err := c.Open(context.Background(), Fleet{
		RepositoryAlias: "example-fleet",
		GitHubConfigURL: impl.configScopeURL,
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
	if want := jobIDFromMessageFixture(t, "message_batch_full.json", 0); offer.JobID != want {
		t.Errorf("Offer.JobID = %q, want fixture value %q", offer.JobID, want)
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

func TestPollPassesExactMaxCapacityHeader(t *testing.T) {
	fs := newFixtureServer(t)
	c := newTestClient(t, fs, 5*time.Second, 5*time.Second)
	sess := openTestSession(t, c)

	if _, err := sess.Poll(context.Background(), 0, 37); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	fs.mu.Lock()
	got := fs.maxCapacityHeader
	fs.mu.Unlock()
	if got != "37" {
		t.Fatalf("%s = %q, want exact value %q", scaleset.HeaderScaleSetMaxCapacity, got, "37")
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
				GitHubConfigURL: fs.configURL("owner/repository"),
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

func TestOpenRequiresDisableUpdateAndCapturesCompatibility(t *testing.T) {
	explicitTrue := true
	explicitFalse := false
	cases := []struct {
		name        string
		disable     *bool
		wantOpen    bool
		wantSession ScaleSetCompatibilityReport
	}{
		{
			name:        "explicit true accepts and captures live evidence",
			disable:     &explicitTrue,
			wantOpen:    true,
			wantSession: ScaleSetCompatibilityReport{SingleNameLabel: true, DisableUpdate: true},
		},
		{
			name:     "explicit false rejects",
			disable:  &explicitFalse,
			wantOpen: false,
		},
		{
			name:     "omitted setting rejects",
			disable:  nil,
			wantOpen: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := newFixtureServer(t)
			fs.scaleSetBody = withScaleSetDisableUpdate(t, fs.scaleSetBody, tc.disable)
			c := newTestClient(t, fs, 5*time.Second, 5*time.Second)

			sess, err := c.Open(context.Background(), Fleet{
				RepositoryAlias: "example-fleet",
				GitHubConfigURL: fs.configURL("owner/repository"),
				ScaleSetName:    "example-scaleset",
			})

			if tc.wantOpen {
				if err != nil {
					t.Fatalf("Open: unexpected error: %v", err)
				}
				if sess == nil {
					t.Fatal("Open: returned a nil session")
				}
				t.Cleanup(func() { _ = sess.Close(context.Background()) })

				got := sess.Compatibility()
				if got != tc.wantSession {
					t.Fatalf("Compatibility = %+v, want %+v", got, tc.wantSession)
				}

				got.SingleNameLabel = false
				got.DisableUpdate = false
				if second := sess.Compatibility(); second != tc.wantSession {
					t.Fatalf("Compatibility after mutating returned copy = %+v, want immutable %+v", second, tc.wantSession)
				}
				return
			}

			if sess != nil {
				_ = sess.Close(context.Background())
				t.Error("Open: returned a session when in-place runner updates were not disabled")
			}
			if err == nil {
				t.Fatal("Open: got nil error, want an update-setting rejection")
			}
			if !errors.Is(err, ErrUpdateSettingMismatch) {
				t.Fatalf("Open: err = %v, want it to wrap ErrUpdateSettingMismatch", err)
			}
			if got := atomic.LoadInt32(&fs.sessionCreateCalls); got != 0 {
				t.Fatalf("Open: created %d message sessions before rejecting the update setting, want 0", got)
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
		GitHubConfigURL: fs.configURL("owner/repository"),
		ScaleSetName:    "example-scaleset",
	})
	if err == nil {
		t.Fatal("Open: got nil error, want ErrScaleSetNotFound")
	}
	if !errors.Is(err, ErrScaleSetNotFound) {
		t.Fatalf("Open: err = %v, want it to wrap ErrScaleSetNotFound", err)
	}
}

func TestFleetScopeMismatchRejectedBeforeNetwork(t *testing.T) {
	fs := newFixtureServer(t)
	c := newTestClient(t, fs, 5*time.Second, 5*time.Second)

	sess, err := c.Open(context.Background(), Fleet{
		RepositoryAlias: "example-fleet",
		GitHubConfigURL: "https://example.invalid/owner/repository",
		ScaleSetName:    "example-scaleset",
	})
	if sess != nil {
		_ = sess.Close(context.Background())
		t.Error("Open: returned a session for a Fleet in a different GitHub scope")
	}
	if err == nil {
		t.Error("Open: got nil error for a Fleet in a different GitHub scope")
	}
	if !errors.Is(err, ErrIdentityMismatch) {
		t.Errorf("Open: err = %v, want ErrIdentityMismatch", err)
	}
	if got := atomic.LoadInt32(&fs.requestCalls); got != 0 {
		t.Errorf("Open: performed %d network requests before rejecting a Fleet scope mismatch, want 0", got)
	}
}

func TestFleetScopeCanonicalizationAcceptsSameScope(t *testing.T) {
	fs := newFixtureServer(t)
	c, err := NewClient(ClientConfig{
		GitHubConfigURL:       fs.configURL("owner/repository") + "/",
		PersonalAccessToken:   "placeholder-pat-token",
		System:                "portable-ghar-test",
		OperationTimeout:      5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		MaxResponseBytes:      testMaxResponseBytes,
		retryableHTTPClient:   newRetryableHTTPClient(5 * time.Second),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	forceCompatibleProbe(t, c)

	sess, err := c.Open(context.Background(), Fleet{
		RepositoryAlias: "example-fleet",
		GitHubConfigURL: fs.configURL("owner/repository"),
		ScaleSetName:    "example-scaleset",
	})
	if err != nil {
		t.Fatalf("Open: canonical-equivalent scopes were rejected: %v", err)
	}
	if sess == nil {
		t.Fatal("Open: canonical-equivalent scopes returned a nil session")
	}
	if err := sess.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestCanonicalGitHubScopeURLNormalizesDefaultPorts(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "https default",
			raw:  "HTTPS://EXAMPLE.COM:443/owner/repository/",
			want: "https://example.com/owner/repository",
		},
		{
			name: "http default",
			raw:  "HTTP://EXAMPLE.COM:80/owner/repository/",
			want: "http://example.com/owner/repository",
		},
		{
			name: "non-default preserved",
			raw:  "https://EXAMPLE.COM:8443/owner/repository/",
			want: "https://example.com:8443/owner/repository",
		},
		{
			name: "bracketed ipv6 https default",
			raw:  "HTTPS://[2001:DB8::1]:443/owner/repository/",
			want: "https://[2001:db8::1]/owner/repository",
		},
		{
			name: "bracketed ipv6 non-default preserved",
			raw:  "https://[2001:DB8::1]:8443/owner/repository/",
			want: "https://[2001:db8::1]:8443/owner/repository",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := canonicalGitHubScopeURL(tc.raw)
			if err != nil {
				t.Fatalf("canonicalGitHubScopeURL(%q): %v", tc.raw, err)
			}
			if got != tc.want {
				t.Fatalf("canonicalGitHubScopeURL(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestNewClientRequiresMaxResponseBytes(t *testing.T) {
	_, err := NewClient(ClientConfig{
		GitHubConfigURL:     "https://github.com/owner/repository",
		PersonalAccessToken: "placeholder-pat-token",
	})
	if err == nil {
		t.Fatal("NewClient: got nil error without MaxResponseBytes, want required bound rejection")
	}
	if !strings.Contains(err.Error(), "MaxResponseBytes is required") {
		t.Fatalf("NewClient: err = %q, want closed MaxResponseBytes validation", err)
	}
}

func TestScaleSetIdentityMismatchesRejectedBeforeSession(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*scaleset.RunnerScaleSet)
	}{
		{
			name: "scale set name",
			mutate: func(set *scaleset.RunnerScaleSet) {
				set.Name = "different-scaleset"
			},
		},
		{
			name: "runner group id",
			mutate: func(set *scaleset.RunnerScaleSet) {
				set.RunnerGroupID = 99
			},
		},
		{
			name: "runner group name",
			mutate: func(set *scaleset.RunnerScaleSet) {
				set.RunnerGroupName = "different-group"
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := newFixtureServer(t)
			fs.scaleSetBody = mutateScaleSetFixture(t, fs.scaleSetBody, tc.mutate)
			c := newTestClient(t, fs, 5*time.Second, 5*time.Second)

			sess, err := c.Open(context.Background(), Fleet{
				RepositoryAlias: "example-fleet",
				GitHubConfigURL: fs.configURL("owner/repository"),
				ScaleSetName:    "example-scaleset",
			})
			if sess != nil {
				_ = sess.Close(context.Background())
				t.Error("Open: returned a session for a mismatched scale-set identity")
			}
			if err == nil {
				t.Error("Open: got nil error for a mismatched scale-set identity")
			}
			if !errors.Is(err, ErrIdentityMismatch) {
				t.Errorf("Open: err = %v, want ErrIdentityMismatch", err)
			}
			if got := atomic.LoadInt32(&fs.sessionCreateCalls); got != 0 {
				t.Errorf("Open: created %d message sessions for a mismatched scale-set identity, want 0", got)
			}
		})
	}
}

func mutateScaleSetFixture(t *testing.T, body []byte, mutate func(*scaleset.RunnerScaleSet)) []byte {
	t.Helper()
	var response struct {
		Count int                       `json:"count"`
		Value []scaleset.RunnerScaleSet `json:"value"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("decode scale-set fixture: %v", err)
	}
	if len(response.Value) != 1 {
		t.Fatalf("scale-set fixture contains %d values, want 1", len(response.Value))
	}
	mutate(&response.Value[0])
	mutated, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("encode scale-set fixture: %v", err)
	}
	return mutated
}

func withScaleSetDisableUpdate(t *testing.T, body []byte, disable *bool) []byte {
	t.Helper()
	var response struct {
		Count int                          `json:"count"`
		Value []map[string]json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("decode scale-set fixture: %v", err)
	}
	if len(response.Value) != 1 {
		t.Fatalf("scale-set fixture contains %d values, want 1", len(response.Value))
	}
	if disable == nil {
		delete(response.Value[0], "RunnerSetting")
	} else {
		setting, err := json.Marshal(struct {
			DisableUpdate bool `json:"disableUpdate"`
		}{DisableUpdate: *disable})
		if err != nil {
			t.Fatalf("encode runner setting: %v", err)
		}
		response.Value[0]["RunnerSetting"] = setting
	}
	mutated, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("encode scale-set fixture: %v", err)
	}
	return mutated
}

func TestOpenRequiresCompatibleProbeBeforeNetwork(t *testing.T) {
	fs := newFixtureServer(t)
	c, err := NewClient(ClientConfig{
		GitHubConfigURL:       fs.configURL("owner/repository"),
		PersonalAccessToken:   "placeholder-pat-token",
		System:                "portable-ghar-test",
		OperationTimeout:      5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		MaxResponseBytes:      testMaxResponseBytes,
		retryableHTTPClient:   newRetryableHTTPClient(5 * time.Second),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	sess, err := c.Open(context.Background(), Fleet{
		RepositoryAlias: "example-fleet",
		GitHubConfigURL: "https://github.com/owner/repository",
		ScaleSetName:    "example-scaleset",
	})
	if sess != nil {
		_ = sess.Close(context.Background())
		t.Error("Open: returned a session for a build whose compatibility probe is not compatible")
	}
	if !errors.Is(err, ErrIncompatibleModuleVersion) {
		t.Errorf("Open: err = %v, want ErrIncompatibleModuleVersion", err)
	}
	if got := atomic.LoadInt32(&fs.requestCalls); got != 0 {
		t.Errorf("Open: performed %d network requests before obtaining a compatible probe result, want 0", got)
	}
}

func TestOpenProbeFailureModesReturnNoSessionBeforeNetwork(t *testing.T) {
	errSyntheticProbe := errors.New("synthetic probe failure")
	cases := []struct {
		name    string
		probe   func(context.Context) (CompatibilityReport, error)
		wantErr error
	}{
		{
			name: "probe error",
			probe: func(context.Context) (CompatibilityReport, error) {
				return CompatibilityReport{}, errSyntheticProbe
			},
			wantErr: errSyntheticProbe,
		},
		{
			name: "incompatible report without probe error",
			probe: func(context.Context) (CompatibilityReport, error) {
				return CompatibilityReport{Compatible: false, Reason: "synthetic mismatch"}, nil
			},
			wantErr: ErrIncompatibleModuleVersion,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := newFixtureServer(t)
			c := newTestClient(t, fs, 5*time.Second, 5*time.Second)
			c.(*client).probe = tc.probe

			sess, err := c.Open(context.Background(), Fleet{
				RepositoryAlias: "example-fleet",
				GitHubConfigURL: "https://github.com/owner/repository",
				ScaleSetName:    "example-scaleset",
			})
			if sess != nil {
				_ = sess.Close(context.Background())
				t.Error("Open: returned a session after a failed compatibility probe")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("Open: err = %v, want %v", err, tc.wantErr)
			}
			if got := atomic.LoadInt32(&fs.requestCalls); got != 0 {
				t.Errorf("Open: performed %d network requests after a failed compatibility probe, want 0", got)
			}
		})
	}
}

// ---------------------------------------------------------------------
// Deadline / cancellation: prove Poll, Acquire, and GenerateJIT never
// hang against a server that never completes a response.
// ---------------------------------------------------------------------

const operationReturnBound = 250 * time.Millisecond

type stallingOperation struct {
	name  string
	stall func(*fixtureServer)
	call  func(context.Context, Session) error
}

func stallingOperations() []stallingOperation {
	return []stallingOperation{
		{
			name:  "Poll",
			stall: func(fs *fixtureServer) { fs.mqGetHandler = blockLongerThanClientDeadline },
			call: func(ctx context.Context, sess Session) error {
				_, err := sess.Poll(ctx, 0, 10)
				return err
			},
		},
		{
			name:  "Acquire",
			stall: func(fs *fixtureServer) { fs.acquireHandler = blockLongerThanClientDeadline },
			call: func(ctx context.Context, sess Session) error {
				_, err := sess.Acquire(ctx, []int64{9001})
				return err
			},
		},
		{
			name:  "GenerateJIT",
			stall: func(fs *fixtureServer) { fs.jitHandler = blockLongerThanClientDeadline },
			call: func(ctx context.Context, sess Session) error {
				_, err := sess.GenerateJIT(ctx, JITRequest{RunnerName: "example-fleet-runner-0001"})
				return err
			},
		},
	}
}

func TestOperationDeadlineIdentityAndBound(t *testing.T) {
	for _, op := range stallingOperations() {
		t.Run(op.name, func(t *testing.T) {
			fs := newFixtureServer(t)
			op.stall(fs)
			sess := openTestSession(t, newTestClient(t, fs, 5*time.Second, 5*time.Second))
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
			defer cancel()

			start := time.Now()
			err := op.call(ctx, sess)
			elapsed := time.Since(start)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("%s: err = %v, want context.DeadlineExceeded", op.name, err)
			}
			if elapsed > operationReturnBound {
				t.Fatalf("%s: elapsed = %s, want <= %s", op.name, elapsed, operationReturnBound)
			}
		})
	}
}

func TestOperationExplicitCancellationIdentityAndBound(t *testing.T) {
	for _, op := range stallingOperations() {
		t.Run(op.name, func(t *testing.T) {
			fs := newFixtureServer(t)
			op.stall(fs)
			sess := openTestSession(t, newTestClient(t, fs, 5*time.Second, 5*time.Second))
			ctx, cancel := context.WithCancel(context.Background())
			timer := time.AfterFunc(50*time.Millisecond, cancel)
			defer timer.Stop()
			defer cancel()

			start := time.Now()
			err := op.call(ctx, sess)
			elapsed := time.Since(start)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("%s: err = %v, want context.Canceled", op.name, err)
			}
			if elapsed > operationReturnBound {
				t.Fatalf("%s: elapsed = %s, want <= %s", op.name, elapsed, operationReturnBound)
			}
		})
	}
}

func TestTransportResponseHeaderTimeoutIsIndependent(t *testing.T) {
	fs := newFixtureServer(t)
	fs.mqGetHandler = blockLongerThanClientDeadline
	sess := openTestSession(t, newTestClientWithRetryMax(t, fs, 5*time.Second, 50*time.Millisecond, 0))

	start := time.Now()
	_, err := sess.Poll(context.Background(), 0, 10)
	elapsed := time.Since(start)
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("Poll: err = %v, want a transport timeout error", err)
	}
	if !errors.Is(err, ErrUpstreamTimeout) {
		t.Fatalf("Poll: err = %v, want ErrUpstreamTimeout", err)
	}
	if elapsed > operationReturnBound {
		t.Fatalf("Poll response-header timeout: elapsed = %s, want <= %s", elapsed, operationReturnBound)
	}
}

const responseBodyTestLimit = int64(1024)

func paddedEmptyMessage(t *testing.T, size int) []byte {
	t.Helper()
	base := []byte(`{"messageId":101,"messageType":"RunnerScaleSetJobMessages","body":"[]","statistics":{}}`)
	if len(base) > size {
		t.Fatalf("minimal message size = %d, exceeds requested size %d", len(base), size)
	}
	return append(base, bytes.Repeat([]byte(" "), size-len(base))...)
}

func TestResponseBodyBoundExactLimitSucceeds(t *testing.T) {
	fs := newFixtureServer(t)
	body := paddedEmptyMessage(t, int(responseBodyTestLimit))
	var calls int32
	fs.mqGetHandler = func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}
	sess := openTestSession(t, newTestClientWithResponseLimit(
		t, fs, 5*time.Second, 5*time.Second, responseBodyTestLimit, 0,
	))

	batch, err := sess.Poll(context.Background(), 0, 10)
	if err != nil {
		t.Fatalf("Poll exact-limit response: %v", err)
	}
	if batch.MessageID != 101 {
		t.Fatalf("Poll exact-limit response MessageID = %d, want 101", batch.MessageID)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("Poll exact-limit response made %d requests, want 1", got)
	}
}

func TestResponseBodyBoundLimitPlusOneFailsClosedWithoutLeakOrRetry(t *testing.T) {
	const jobControlled = "JOB-CONTROLLED-RESPONSE-MUST-NOT-LEAK"
	fs := newFixtureServer(t)
	body := append([]byte(jobControlled), bytes.Repeat([]byte("x"), int(responseBodyTestLimit)+1-len(jobControlled))...)
	var calls int32
	fs.mqGetHandler = func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}

	retryable := newRetryableHTTPClient(5 * time.Second)
	retryable.RetryMax = 0
	var logs bytes.Buffer
	c, err := NewClient(ClientConfig{
		GitHubConfigURL:       fs.configURL("owner/repository"),
		PersonalAccessToken:   "placeholder-pat-token",
		System:                "portable-ghar-test",
		OperationTimeout:      5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		MaxResponseBytes:      responseBodyTestLimit,
		retryableHTTPClient:   retryable,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	forceCompatibleProbe(t, c)
	sess := openTestSession(t, c)
	// actions/scaleset installs its own discard logger while Open constructs
	// the session client, so attach the capture after Open to observe Poll.
	retryable.Logger = log.New(&logs, "", 0)

	_, err = sess.Poll(context.Background(), 0, 10)
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("Poll limit-plus-one response: err = %v, want ErrResponseTooLarge", err)
	}
	if strings.Contains(err.Error(), jobControlled) {
		t.Fatalf("Poll limit-plus-one error leaked response bytes: %q", err)
	}
	if strings.Contains(logs.String(), jobControlled) {
		t.Fatalf("Poll limit-plus-one logs leaked response bytes: %q", logs.String())
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("Poll limit-plus-one response made %d requests, want 1", got)
	}
}

func TestResponseBodyBoundRejectsChunkedLimitPlusOne(t *testing.T) {
	fs := newFixtureServer(t)
	body := paddedEmptyMessage(t, int(responseBodyTestLimit)+1)
	var calls int32
	fs.mqGetHandler = func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		for offset := 0; offset < len(body); offset += 73 {
			end := offset + 73
			if end > len(body) {
				end = len(body)
			}
			_, _ = w.Write(body[offset:end])
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}
	}
	sess := openTestSession(t, newTestClientWithResponseLimit(
		t, fs, 5*time.Second, 5*time.Second, responseBodyTestLimit, 0,
	))

	_, err := sess.Poll(context.Background(), 0, 10)
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("Poll chunked limit-plus-one response: err = %v, want ErrResponseTooLarge", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("Poll chunked limit-plus-one response made %d requests, want 1", got)
	}
}

func TestResponseBodyBoundAppliesAfterTransparentDecompression(t *testing.T) {
	fs := newFixtureServer(t)
	body := paddedEmptyMessage(t, int(responseBodyTestLimit)+1)
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(body); err != nil {
		t.Fatalf("gzip response body: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip response body: %v", err)
	}
	if int64(compressed.Len()) >= responseBodyTestLimit {
		t.Fatalf("compressed fixture size = %d, want below decompressed limit %d", compressed.Len(), responseBodyTestLimit)
	}

	var calls int32
	fs.mqGetHandler = func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(compressed.Bytes())
	}
	sess := openTestSession(t, newTestClientWithResponseLimit(
		t, fs, 5*time.Second, 5*time.Second, responseBodyTestLimit, 0,
	))

	_, err := sess.Poll(context.Background(), 0, 10)
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("Poll compressed expansion: err = %v, want ErrResponseTooLarge", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("Poll compressed expansion made %d requests, want 1", got)
	}
}

func TestOversizedResponseBodyOnNonSuccessIsTypedAndNotRetried(t *testing.T) {
	const jobControlled = "OVERSIZED-NON-SUCCESS-BODY-MUST-NOT-LEAK"
	fs := newFixtureServer(t)
	body := append([]byte(jobControlled), bytes.Repeat([]byte("y"), int(responseBodyTestLimit)+1-len(jobControlled))...)
	var calls int32
	fs.mqGetHandler = func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write(body)
	}
	sess := openTestSession(t, newTestClientWithResponseLimit(
		t, fs, 5*time.Second, 5*time.Second, responseBodyTestLimit, 1,
	))

	_, err := sess.Poll(context.Background(), 0, 10)
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("Poll oversized non-success response: err = %v, want ErrResponseTooLarge", err)
	}
	if strings.Contains(err.Error(), jobControlled) {
		t.Fatalf("Poll oversized non-success error leaked response bytes: %q", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("Poll oversized non-success response made %d requests, want 1", got)
	}
}

func TestOversizedResponseBodyOnFinalRetryableAttemptIsTyped(t *testing.T) {
	fs := newFixtureServer(t)
	body := bytes.Repeat([]byte("z"), int(responseBodyTestLimit)+1)
	var calls int32
	fs.mqGetHandler = func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write(body)
	}
	sess := openTestSession(t, newTestClientWithResponseLimit(
		t, fs, 5*time.Second, 5*time.Second, responseBodyTestLimit, 0,
	))

	_, err := sess.Poll(context.Background(), 0, 10)
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("Poll oversized final retryable response: err = %v, want ErrResponseTooLarge", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("Poll oversized final retryable response made %d requests, want 1", got)
	}
}

func TestResponseBodyBoundPreservesRetryForBoundedRetryableResponse(t *testing.T) {
	fs := newFixtureServer(t)
	valid := paddedEmptyMessage(t, int(responseBodyTestLimit))
	var calls int32
	fs.mqGetHandler = func(w http.ResponseWriter, _ *http.Request) {
		call := atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		if call == 1 {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("bounded retryable response"))
			return
		}
		_, _ = w.Write(valid)
	}
	sess := openTestSession(t, newTestClientWithResponseLimit(
		t, fs, 5*time.Second, 5*time.Second, responseBodyTestLimit, 1,
	))

	batch, err := sess.Poll(context.Background(), 0, 10)
	if err != nil {
		t.Fatalf("Poll after bounded retryable response: %v", err)
	}
	if batch.MessageID != 101 {
		t.Fatalf("Poll after bounded retryable response MessageID = %d, want 101", batch.MessageID)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("Poll bounded retryable response made %d requests, want 2", got)
	}
}

func TestResponseBodyBoundRestoresRetryStateForNextOperation(t *testing.T) {
	fs := newFixtureServer(t)
	oversized := bytes.Repeat([]byte("z"), int(responseBodyTestLimit)+1)
	valid := paddedEmptyMessage(t, int(responseBodyTestLimit))
	var calls int32
	fs.mqGetHandler = func(w http.ResponseWriter, _ *http.Request) {
		call := atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		switch call {
		case 1:
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write(oversized)
		case 2:
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("bounded retryable response"))
		default:
			_, _ = w.Write(valid)
		}
	}
	sess := openTestSession(t, newTestClientWithResponseLimit(
		t, fs, 5*time.Second, 5*time.Second, responseBodyTestLimit, 1,
	))

	_, err := sess.Poll(context.Background(), 0, 10)
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("first Poll oversized response: err = %v, want ErrResponseTooLarge", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("first Poll made %d requests, want 1", got)
	}

	batch, err := sess.Poll(context.Background(), 0, 10)
	if err != nil {
		t.Fatalf("second Poll after oversized response: %v", err)
	}
	if batch.MessageID != 101 {
		t.Fatalf("second Poll MessageID = %d, want 101", batch.MessageID)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("second Poll total requests = %d, want 3 (bounded retry then success)", got)
	}
}

type closeTrackingReadCloser struct {
	io.Reader
	closeCalls int
}

func (b *closeTrackingReadCloser) Close() error {
	b.closeCalls++
	return nil
}

func TestResponseBodyBoundClosesUnderlyingBodyOnOverflow(t *testing.T) {
	underlying := &closeTrackingReadCloser{Reader: strings.NewReader("four")}
	body := newBoundedResponseBody(underlying, 3)
	_, err := io.ReadAll(body)
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("ReadAll bounded body: err = %v, want ErrResponseTooLarge", err)
	}
	if underlying.closeCalls != 1 {
		t.Fatalf("underlying Close calls after overflow = %d, want 1", underlying.closeCalls)
	}
	if err := body.Close(); err != nil {
		t.Fatalf("Close bounded body: %v", err)
	}
	if underlying.closeCalls != 1 {
		t.Fatalf("underlying Close calls after explicit Close = %d, want still 1", underlying.closeCalls)
	}
}

func TestResponseBodyBoundPrecedesExistingHookAndIgnoresMisleadingContentLength(t *testing.T) {
	underlying := &closeTrackingReadCloser{
		Reader: strings.NewReader(strings.Repeat("x", int(responseBodyTestLimit)+1)),
	}
	resp := &http.Response{
		Body:          underlying,
		ContentLength: 1,
	}
	retryable := newRetryableHTTPClient(5 * time.Second)
	var previousHookErr error
	retryable.ResponseLogHook = func(_ retryablehttp.Logger, got *http.Response) {
		_, previousHookErr = io.ReadAll(got.Body)
	}

	boundRetryableResponseBodies(retryable, responseBodyTestLimit)
	retryable.ResponseLogHook(nil, resp)

	if !errors.Is(previousHookErr, ErrResponseTooLarge) {
		t.Fatalf("existing response hook read: err = %v, want ErrResponseTooLarge", previousHookErr)
	}
	if underlying.closeCalls != 1 {
		t.Fatalf("underlying Close calls after misleading Content-Length overflow = %d, want 1", underlying.closeCalls)
	}
}

func TestContextAwareSerializationGateHonorsWaitingDeadline(t *testing.T) {
	fs := newFixtureServer(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var enterOnce sync.Once
	var releaseOnce sync.Once
	releasePoll := func() { releaseOnce.Do(func() { close(release) }) }
	fs.mqGetHandler = func(http.ResponseWriter, *http.Request) {
		enterOnce.Do(func() { close(entered) })
		<-release
	}

	c := newTestClient(t, fs, 5*time.Second, 5*time.Second)
	sess := openTestSession(t, c)
	pollDone := make(chan error, 1)
	go func() {
		_, err := sess.Poll(context.Background(), 0, 10)
		pollDone <- err
	}()
	<-entered

	releaseTimer := time.AfterFunc(300*time.Millisecond, releasePoll)
	defer releaseTimer.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := sess.Acquire(ctx, []int64{9001})
	elapsed := time.Since(start)
	releasePoll()
	<-pollDone

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Acquire waiting behind Poll: err = %v, want context.DeadlineExceeded", err)
	}
	if elapsed > 180*time.Millisecond {
		t.Fatalf("Acquire waited %s behind an upstream mutex, want return within 180ms", elapsed)
	}
	if got := atomic.LoadInt32(&fs.acquireCalls); got != 0 {
		t.Fatalf("Acquire entered the upstream HTTP operation %d times after its waiting context expired, want 0", got)
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
	if strings.Contains(err.Error(), "PLACEHOLDER.JIT.SHAPE.TOKEN") {
		t.Fatalf("GenerateJIT: shape-mismatch error leaked encoded JIT material: %q", err)
	}
}

func TestGenerateJITErrorDoesNotLeakUpstreamResponse(t *testing.T) {
	fs := newFixtureServer(t)
	fs.jitStatus = http.StatusInternalServerError
	fs.jitBody = readFixture(t, "jit_config_error.json")

	c := newTestClientWithRetryMax(t, fs, 5*time.Second, 5*time.Second, 0)
	sess := openTestSession(t, c)

	_, err := sess.GenerateJIT(context.Background(), JITRequest{RunnerName: "example-fleet-runner-0001"})
	if err == nil {
		t.Fatal("GenerateJIT: got nil error for an upstream error response")
	}
	for _, forbidden := range []string{
		"PLACEHOLDER.JIT.ERROR.TOKEN",
		"raw response content",
	} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("GenerateJIT: error leaked untrusted upstream response content %q: %q", forbidden, err)
		}
	}
}

func TestEveryUpstreamOperationSanitizesUntrustedErrorBodies(t *testing.T) {
	const secret = "PLACEHOLDER.NONJIT.UPSTREAM.ERROR.TOKEN"

	assertSanitized := func(t *testing.T, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("operation returned nil error for an upstream 500 response")
		}
		if !errors.Is(err, ErrUpstreamRequest) {
			t.Fatalf("error = %v, want it to wrap ErrUpstreamRequest", err)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error leaked untrusted upstream response body: %q", err)
		}
	}

	open := func(t *testing.T, c Client, fs *fixtureServer) error {
		t.Helper()
		_, err := c.Open(context.Background(), Fleet{
			RepositoryAlias: "example-fleet",
			GitHubConfigURL: fs.configURL("owner/repository"),
			ScaleSetName:    "example-scaleset",
		})
		return err
	}

	t.Run("Open runner group", func(t *testing.T) {
		fs := newFixtureServer(t)
		fs.groupHandler = serveUntrustedUpstreamError(secret)
		c := newTestClientWithRetryMax(t, fs, 5*time.Second, 5*time.Second, 0)
		assertSanitized(t, open(t, c, fs))
	})

	t.Run("Open scale set", func(t *testing.T) {
		fs := newFixtureServer(t)
		fs.scaleSetHandler = serveUntrustedUpstreamError(secret)
		c := newTestClientWithRetryMax(t, fs, 5*time.Second, 5*time.Second, 0)
		assertSanitized(t, open(t, c, fs))
	})

	t.Run("Open message session", func(t *testing.T) {
		fs := newFixtureServer(t)
		fs.sessionHandler = serveUntrustedUpstreamError(secret)
		c := newTestClientWithRetryMax(t, fs, 5*time.Second, 5*time.Second, 0)
		assertSanitized(t, open(t, c, fs))
	})

	type sessionCase struct {
		name      string
		configure func(*fixtureServer)
		call      func(Session) error
	}
	cases := []sessionCase{
		{
			name:      "Poll",
			configure: func(fs *fixtureServer) { fs.mqGetHandler = serveUntrustedUpstreamError(secret) },
			call: func(sess Session) error {
				_, err := sess.Poll(context.Background(), 0, 1)
				return err
			},
		},
		{
			name:      "Ack",
			configure: func(fs *fixtureServer) { fs.mqDelHandler = serveUntrustedUpstreamError(secret) },
			call:      func(sess Session) error { return sess.Ack(context.Background(), 1) },
		},
		{
			name:      "Acquire",
			configure: func(fs *fixtureServer) { fs.acquireHandler = serveUntrustedUpstreamError(secret) },
			call: func(sess Session) error {
				_, err := sess.Acquire(context.Background(), []int64{1})
				return err
			},
		},
		{
			name:      "GetRunnerByName",
			configure: func(fs *fixtureServer) { fs.runnerHandler = serveUntrustedUpstreamError(secret) },
			call: func(sess Session) error {
				_, _, err := sess.GetRunnerByName(context.Background(), "runner")
				return err
			},
		},
		{
			name:      "GetRunner",
			configure: func(fs *fixtureServer) { fs.runnerHandler = serveUntrustedUpstreamError(secret) },
			call: func(sess Session) error {
				_, _, err := sess.GetRunner(context.Background(), 501)
				return err
			},
		},
		{
			name:      "RemoveRunner lookup",
			configure: func(fs *fixtureServer) { fs.runnerHandler = serveUntrustedUpstreamError(secret) },
			call:      func(sess Session) error { return sess.RemoveRunner(context.Background(), 501) },
		},
		{
			name: "RemoveRunner delete",
			configure: func(fs *fixtureServer) {
				fs.runnerHandler = func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodDelete {
						serveUntrustedUpstreamError(secret)(w, r)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write(fs.runnerBody)
				}
			},
			call: func(sess Session) error { return sess.RemoveRunner(context.Background(), 501) },
		},
		{
			name:      "Close",
			configure: func(fs *fixtureServer) { fs.sessionHandler = serveUntrustedUpstreamError(secret) },
			call:      func(sess Session) error { return sess.Close(context.Background()) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := newFixtureServer(t)
			c := newTestClientWithRetryMax(t, fs, 5*time.Second, 5*time.Second, 0)
			sess := openTestSession(t, c)
			tc.configure(fs)
			assertSanitized(t, tc.call(sess))
		})
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

func TestGenerateJITRunnerIdentityMismatchesRejected(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*scaleset.RunnerReference)
	}{
		{
			name: "runner name",
			mutate: func(ref *scaleset.RunnerReference) {
				ref.Name = "different-runner"
			},
		},
		{
			name: "runner scale set id",
			mutate: func(ref *scaleset.RunnerReference) {
				ref.RunnerScaleSetID = 99
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := newFixtureServer(t)
			var cfg scaleset.RunnerScaleSetJitRunnerConfig
			if err := json.Unmarshal(fs.jitBody, &cfg); err != nil {
				t.Fatalf("decode JIT fixture: %v", err)
			}
			tc.mutate(cfg.Runner)
			var err error
			fs.jitBody, err = json.Marshal(cfg)
			if err != nil {
				t.Fatalf("encode JIT fixture: %v", err)
			}

			c := newTestClient(t, fs, 5*time.Second, 5*time.Second)
			sess := openTestSession(t, c)
			got, err := sess.GenerateJIT(context.Background(), JITRequest{RunnerName: "example-fleet-runner-0001"})
			if got.Encoded != nil {
				got.Encoded.Destroy()
				t.Error("GenerateJIT: returned encoded secret material for a mismatched runner identity")
			}
			if err == nil {
				t.Error("GenerateJIT: got nil error for a mismatched runner identity")
			}
			if !errors.Is(err, ErrIdentityMismatch) {
				t.Errorf("GenerateJIT: err = %v, want ErrIdentityMismatch", err)
			}
		})
	}
}

// ---------------------------------------------------------------------
// GetRunner / GetRunnerByName / RemoveRunner.
// ---------------------------------------------------------------------

func TestGetRunnerByNameNotFound(t *testing.T) {
	fs := newFixtureServer(t)
	fs.runnerBody = readFixture(t, "runner_reference_list_not_found.json")

	c := newTestClient(t, fs, 5*time.Second, 5*time.Second)
	sess := openTestSession(t, c)

	ref, found, err := sess.GetRunnerByName(context.Background(), "does-not-exist")
	if err != nil {
		t.Fatalf("GetRunnerByName: %v", err)
	}
	if found || ref != (RunnerRef{}) {
		t.Fatalf("GetRunnerByName: ref=%+v found=%v, want zero,false,nil for absence", ref, found)
	}
}

func TestGetRunnerByNameFound(t *testing.T) {
	fs := newFixtureServer(t)
	fs.runnerBody = readFixture(t, "runner_reference_list.json")
	c := newTestClient(t, fs, 5*time.Second, 5*time.Second)
	sess := openTestSession(t, c)

	ref, found, err := sess.GetRunnerByName(context.Background(), "example-fleet-runner-0001")
	if err != nil {
		t.Fatalf("GetRunnerByName: %v", err)
	}
	if !found || ref.ID != 501 || ref.Name != "example-fleet-runner-0001" || ref.RunnerScaleSetID != 42 {
		t.Fatalf("GetRunnerByName: ref=%+v found=%v, want the identity-valid fixture runner", ref, found)
	}
}

func TestGetRunnerAndRemoveRunner(t *testing.T) {
	fs := newFixtureServer(t)

	c := newTestClient(t, fs, 5*time.Second, 5*time.Second)
	sess := openTestSession(t, c)

	ref, found, err := sess.GetRunner(context.Background(), 501)
	if err != nil {
		t.Fatalf("GetRunner: %v", err)
	}
	if !found || ref.ID != 501 || ref.Name != "example-fleet-runner-0001" {
		t.Fatalf("GetRunner: got %+v, want the fixture's runner", ref)
	}

	if err := sess.RemoveRunner(context.Background(), 501); err != nil {
		t.Fatalf("RemoveRunner: %v", err)
	}
}

func TestRemoveRunnerVerifiesExactSessionIdentityBeforeDelete(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*scaleset.RunnerReference)
	}{
		{
			name: "runner id",
			mutate: func(ref *scaleset.RunnerReference) {
				ref.ID = 999
			},
		},
		{
			name: "runner scale set",
			mutate: func(ref *scaleset.RunnerReference) {
				ref.RunnerScaleSetID = 99
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := newFixtureServer(t)
			var ref scaleset.RunnerReference
			if err := json.Unmarshal(fs.runnerBody, &ref); err != nil {
				t.Fatalf("decode runner fixture: %v", err)
			}
			tc.mutate(&ref)
			body, err := json.Marshal(ref)
			if err != nil {
				t.Fatalf("encode runner fixture: %v", err)
			}

			var deleteCalls int32
			fs.runnerHandler = func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodDelete {
					atomic.AddInt32(&deleteCalls, 1)
					w.WriteHeader(http.StatusNoContent)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(body)
			}

			c := newTestClient(t, fs, 5*time.Second, 5*time.Second)
			sess := openTestSession(t, c)
			err = sess.RemoveRunner(context.Background(), 501)
			if !errors.Is(err, ErrIdentityMismatch) {
				t.Fatalf("RemoveRunner: err = %v, want ErrIdentityMismatch", err)
			}
			if got := atomic.LoadInt32(&deleteCalls); got != 0 {
				t.Fatalf("RemoveRunner issued %d DELETE requests after identity mismatch, want 0", got)
			}
		})
	}
}

func TestRemoveRunnerTreatsLookupAbsenceAsIdempotentSuccess(t *testing.T) {
	fs := newFixtureServer(t)
	var deleteCalls int32
	fs.runnerHandler = func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			atomic.AddInt32(&deleteCalls, 1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"typeName":"AgentNotFoundException","message":"already absent"}`))
	}

	c := newTestClientWithRetryMax(t, fs, 5*time.Second, 5*time.Second, 0)
	sess := openTestSession(t, c)
	if err := sess.RemoveRunner(context.Background(), 501); err != nil {
		t.Fatalf("RemoveRunner absent runner: %v, want idempotent nil", err)
	}
	if got := atomic.LoadInt32(&deleteCalls); got != 0 {
		t.Fatalf("RemoveRunner issued %d DELETE requests after lookup absence, want 0", got)
	}
}

func TestRemoveRunnerTreatsDeleteRaceAbsenceAsIdempotentSuccess(t *testing.T) {
	fs := newFixtureServer(t)
	var deleteCalls int32
	fs.runnerHandler = func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			atomic.AddInt32(&deleteCalls, 1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"typeName":"AgentNotFoundException","message":"removed concurrently"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fs.runnerBody)
	}

	c := newTestClientWithRetryMax(t, fs, 5*time.Second, 5*time.Second, 0)
	sess := openTestSession(t, c)
	if err := sess.RemoveRunner(context.Background(), 501); err != nil {
		t.Fatalf("RemoveRunner concurrent absence: %v, want idempotent nil", err)
	}
	if got := atomic.LoadInt32(&deleteCalls); got != 1 {
		t.Fatalf("RemoveRunner issued %d DELETE requests, want exactly 1", got)
	}
}

func TestGetRunnerNotFound(t *testing.T) {
	fs := newFixtureServer(t)
	fs.runnerStatus = http.StatusNotFound
	fs.runnerBody = []byte(`{"typeName":"AgentNotFoundException","message":"synthetic runner absent"}`)
	c := newTestClient(t, fs, 5*time.Second, 5*time.Second)
	sess := openTestSession(t, c)

	ref, found, err := sess.GetRunner(context.Background(), 999)
	if err != nil {
		t.Fatalf("GetRunner: %v", err)
	}
	if found || ref != (RunnerRef{}) {
		t.Fatalf("GetRunner: ref=%+v found=%v, want zero,false,nil for absence", ref, found)
	}
}

func TestRunnerLookupIdentityMismatchesRejected(t *testing.T) {
	t.Run("by name", func(t *testing.T) {
		cases := []struct {
			name   string
			mutate func(*scaleset.RunnerReference)
		}{
			{
				name: "returned name",
				mutate: func(ref *scaleset.RunnerReference) {
					ref.Name = "different-runner"
				},
			},
			{
				name: "runner scale set id",
				mutate: func(ref *scaleset.RunnerReference) {
					ref.RunnerScaleSetID = 99
				},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				fs := newFixtureServer(t)
				var list scaleset.RunnerReferenceList
				if err := json.Unmarshal(readFixture(t, "runner_reference_list.json"), &list); err != nil {
					t.Fatalf("decode runner-list fixture: %v", err)
				}
				tc.mutate(&list.RunnerReferences[0])
				var err error
				fs.runnerBody, err = json.Marshal(list)
				if err != nil {
					t.Fatalf("encode runner-list fixture: %v", err)
				}

				c := newTestClient(t, fs, 5*time.Second, 5*time.Second)
				sess := openTestSession(t, c)
				_, _, err = sess.GetRunnerByName(context.Background(), "example-fleet-runner-0001")
				if err == nil {
					t.Error("GetRunnerByName: got nil error for a mismatched runner identity")
				}
				if !errors.Is(err, ErrIdentityMismatch) {
					t.Errorf("GetRunnerByName: err = %v, want ErrIdentityMismatch", err)
				}
			})
		}
	})

	t.Run("by id", func(t *testing.T) {
		cases := []struct {
			name   string
			mutate func(*scaleset.RunnerReference)
		}{
			{
				name: "returned id",
				mutate: func(ref *scaleset.RunnerReference) {
					ref.ID = 999
				},
			},
			{
				name: "runner scale set id",
				mutate: func(ref *scaleset.RunnerReference) {
					ref.RunnerScaleSetID = 99
				},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				fs := newFixtureServer(t)
				var ref scaleset.RunnerReference
				if err := json.Unmarshal(fs.runnerBody, &ref); err != nil {
					t.Fatalf("decode runner fixture: %v", err)
				}
				tc.mutate(&ref)
				var err error
				fs.runnerBody, err = json.Marshal(ref)
				if err != nil {
					t.Fatalf("encode runner fixture: %v", err)
				}

				c := newTestClient(t, fs, 5*time.Second, 5*time.Second)
				sess := openTestSession(t, c)
				_, _, err = sess.GetRunner(context.Background(), 501)
				if err == nil {
					t.Error("GetRunner: got nil error for a mismatched runner identity")
				}
				if !errors.Is(err, ErrIdentityMismatch) {
					t.Errorf("GetRunner: err = %v, want ErrIdentityMismatch", err)
				}
			})
		}
	})
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
	buildCmd.Env = append(os.Environ(), "GOTOOLCHAIN=go1.26.6")
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
	report, err := evaluateCompatibility(pin, linkedScalesetModule{Version: "v0.3.9", Sum: pin.Sum}, true)
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
	report, err := evaluateCompatibility(pin, linkedScalesetModule{}, false)
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
	report, err := evaluateCompatibility(pin, linkedScalesetModule{Version: pin.Version, Sum: pin.Sum}, true)
	if err != nil {
		t.Fatalf("evaluateCompatibility: unexpected error for an exact pin match: %v", err)
	}
	if !report.Compatible {
		t.Fatalf("evaluateCompatibility: Compatible = false for an exact pin match, report = %+v", report)
	}
}

func TestEvaluateCompatibilitySyntheticBuildInfoMatrix(t *testing.T) {
	pin := buildinfo.Pins().Scaleset
	cases := []struct {
		name                string
		info                *debug.BuildInfo
		wantCompatible      bool
		wantLinkedSum       string
		wantReplaced        bool
		wantReplacementPath string
	}{
		{
			name: "exact match",
			info: &debug.BuildInfo{Deps: []*debug.Module{{
				Path: pin.Path, Version: pin.Version, Sum: pin.Sum,
			}}},
			wantCompatible: true,
			wantLinkedSum:  pin.Sum,
		},
		{
			name: "wrong version",
			info: &debug.BuildInfo{Deps: []*debug.Module{{
				Path: pin.Path, Version: "v0.3.9", Sum: pin.Sum,
			}}},
			wantLinkedSum: pin.Sum,
		},
		{
			name: "missing dependency",
			info: &debug.BuildInfo{},
		},
		{
			name: "replacement",
			info: &debug.BuildInfo{Deps: []*debug.Module{{
				Path: pin.Path, Version: pin.Version, Sum: pin.Sum,
				Replace: &debug.Module{
					Path: "example.invalid/replacement", Version: pin.Version, Sum: pin.Sum,
				},
			}}},
			wantLinkedSum:       pin.Sum,
			wantReplaced:        true,
			wantReplacementPath: "example.invalid/replacement",
		},
		{
			name: "wrong sum",
			info: &debug.BuildInfo{Deps: []*debug.Module{{
				Path: pin.Path, Version: pin.Version, Sum: "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			}}},
			wantLinkedSum: "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		},
		{
			name: "empty sum",
			info: &debug.BuildInfo{Deps: []*debug.Module{{
				Path: pin.Path, Version: pin.Version,
			}}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			linked, found := findLinkedScalesetModule(tc.info)
			report, err := evaluateCompatibility(pin, linked, found)
			if report.ExpectedSum != pin.Sum {
				t.Errorf("ExpectedSum = %q, want %q", report.ExpectedSum, pin.Sum)
			}
			if report.LinkedSum != tc.wantLinkedSum {
				t.Errorf("LinkedSum = %q, want %q", report.LinkedSum, tc.wantLinkedSum)
			}
			if report.Replaced != tc.wantReplaced {
				t.Errorf("Replaced = %v, want %v", report.Replaced, tc.wantReplaced)
			}
			if report.ReplacementPath != tc.wantReplacementPath {
				t.Errorf("ReplacementPath = %q, want %q", report.ReplacementPath, tc.wantReplacementPath)
			}
			if tc.wantCompatible {
				if err != nil || !report.Compatible {
					t.Fatalf("evaluateCompatibility: report=%+v err=%v, want compatible", report, err)
				}
				return
			}
			if err == nil || report.Compatible {
				t.Fatalf("evaluateCompatibility: report=%+v err=%v, want fail-closed incompatibility", report, err)
			}
		})
	}
}

func TestOpenRejectsSyntheticCompatibilityFailuresBeforeNetwork(t *testing.T) {
	pin := buildinfo.Pins().Scaleset
	cases := []struct {
		name string
		info *debug.BuildInfo
	}{
		{
			name: "wrong version",
			info: &debug.BuildInfo{Deps: []*debug.Module{{Path: pin.Path, Version: "v0.3.9", Sum: pin.Sum}}},
		},
		{name: "missing dependency", info: &debug.BuildInfo{}},
		{
			name: "replacement",
			info: &debug.BuildInfo{Deps: []*debug.Module{{
				Path: pin.Path, Version: pin.Version, Sum: pin.Sum,
				Replace: &debug.Module{Path: "example.invalid/replacement", Version: pin.Version, Sum: pin.Sum},
			}}},
		},
		{
			name: "sum mismatch",
			info: &debug.BuildInfo{Deps: []*debug.Module{{
				Path: pin.Path, Version: pin.Version, Sum: "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			}}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := newFixtureServer(t)
			c := newTestClient(t, fs, 5*time.Second, 5*time.Second)
			linked, found := findLinkedScalesetModule(tc.info)
			report, probeErr := evaluateCompatibility(pin, linked, found)
			c.(*client).probe = func(context.Context) (CompatibilityReport, error) {
				return report, probeErr
			}

			sess, err := c.Open(context.Background(), Fleet{
				RepositoryAlias: "example-fleet",
				GitHubConfigURL: "https://github.com/owner/repository",
				ScaleSetName:    "example-scaleset",
			})
			if sess != nil {
				_ = sess.Close(context.Background())
				t.Error("Open: returned a session for an incompatible synthetic build")
			}
			if !errors.Is(err, ErrIncompatibleModuleVersion) {
				t.Errorf("Open: err = %v, want ErrIncompatibleModuleVersion", err)
			}
			if got := atomic.LoadInt32(&fs.requestCalls); got != 0 {
				t.Errorf("Open: performed %d network requests for an incompatible synthetic build, want 0", got)
			}
		})
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
	mu      sync.Mutex
	pending *Batch
	acked   []int
	trace   []string
}

var _ Session = (*fakeAckSession)(nil)

func newFakeAckSession(b Batch) *fakeAckSession {
	cp := b
	return &fakeAckSession{pending: &cp}
}

func (f *fakeAckSession) Compatibility() ScaleSetCompatibilityReport {
	return ScaleSetCompatibilityReport{SingleNameLabel: true, DisableUpdate: true}
}

func (f *fakeAckSession) Poll(ctx context.Context, lastMessageID, maxCapacity int) (Batch, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.trace = append(f.trace, "Poll")
	if f.pending == nil {
		return Batch{Empty: true}, nil
	}
	return *f.pending, nil
}

func (f *fakeAckSession) Ack(ctx context.Context, messageID int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.trace = append(f.trace, "Ack")
	f.acked = append(f.acked, messageID)
	f.pending = nil
	return nil
}

func (f *fakeAckSession) recordTrace(event string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.trace = append(f.trace, event)
}

func (f *fakeAckSession) traceSnapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.trace...)
}

func (f *fakeAckSession) resetTrace() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.trace = nil
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

func (f *fakeAckSession) GetRunnerByName(ctx context.Context, name string) (RunnerRef, bool, error) {
	return RunnerRef{}, false, fmt.Errorf("fakeAckSession: GetRunnerByName not implemented")
}

func (f *fakeAckSession) GetRunner(ctx context.Context, id int64) (RunnerRef, bool, error) {
	return RunnerRef{}, false, fmt.Errorf("fakeAckSession: GetRunner not implemented")
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
func processOnePoll(ctx context.Context, sess Session, persist func(Batch) error) (acked bool, err error) {
	batch, err := sess.Poll(ctx, 0, 10)
	if err != nil {
		return false, fmt.Errorf("poll: %w", err)
	}
	if batch.Empty {
		return false, fmt.Errorf("no message to process")
	}
	if err := persist(batch); err != nil {
		return false, fmt.Errorf("persist: %w", err)
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
	errPersist := errors.New("synthetic persistence failure")

	// Cycle 1: Poll -> persistence callback fails -> no Ack.
	if _, err := processOnePoll(ctx, fake, func(Batch) error {
		fake.recordTrace("persist callback")
		return errPersist
	}); !errors.Is(err, errPersist) {
		t.Fatalf("processOnePoll: err = %v, want synthetic persistence failure", err)
	}
	if got := strings.Join(fake.traceSnapshot(), " -> "); got != "Poll -> persist callback" {
		t.Fatalf("persistence-failure trace = %q, want %q", got, "Poll -> persist callback")
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
	if got := strings.Join(fake.traceSnapshot(), " -> "); got != "Poll -> persist callback -> Poll" {
		t.Fatalf("redelivery trace = %q, want %q", got, "Poll -> persist callback -> Poll")
	}

	// Cycle 2: exact success order is Poll -> persistence callback -> Ack.
	fake.resetTrace()
	acked, err := processOnePoll(ctx, fake, func(Batch) error {
		fake.recordTrace("persist callback")
		return nil
	})
	if err != nil {
		t.Fatalf("processOnePoll: %v", err)
	}
	if !acked {
		t.Fatal("processOnePoll: expected the message to be acked on a successful persist")
	}
	if got := fake.ackedIDs(); len(got) != 1 || got[0] != 55 {
		t.Fatalf("Ack calls = %v, want exactly [55]", got)
	}
	if got := strings.Join(fake.traceSnapshot(), " -> "); got != "Poll -> persist callback -> Ack" {
		t.Fatalf("success trace = %q, want %q", got, "Poll -> persist callback -> Ack")
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
