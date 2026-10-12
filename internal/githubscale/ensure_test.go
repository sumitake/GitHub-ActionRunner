package githubscale

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/actions/scaleset"
)

// scaleSetStore serves the scale-set endpoint from an in-memory list: GET
// returns the current list and POST appends the decoded body.
type scaleSetStore struct {
	mu        sync.Mutex
	current   []byte
	afterPost []byte
	posts     []scaleset.RunnerScaleSet
}

func (s *scaleSetStore) handle(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write(s.current)
		case http.MethodPost:
			var body scaleset.RunnerScaleSet
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode create body: %v", err)
			}
			s.posts = append(s.posts, body)
			s.current = s.afterPost
			body.ID = 42
			_ = json.NewEncoder(w).Encode(body)
		default:
			t.Errorf("unexpected %s on scale-set endpoint", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

func (s *scaleSetStore) postCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.posts)
}

const emptyScaleSetList = `{"count":0,"value":[]}`

func ensureFixture(t *testing.T, current []byte, afterPost []byte) (Client, *scaleSetStore, Fleet) {
	t.Helper()
	fs := newFixtureServer(t)
	store := &scaleSetStore{current: current, afterPost: afterPost}
	fs.scaleSetHandler = store.handle(t)
	c := newTestClient(t, fs, 5*time.Second, 5*time.Second)
	return c, store, Fleet{
		RepositoryAlias: "example-fleet",
		GitHubConfigURL: c.(*client).configScopeURL,
		ScaleSetName:    "example-scaleset",
	}
}

func TestEnsureScaleSetCreatesMissingScaleSet(t *testing.T) {
	c, store, fleet := ensureFixture(t,
		[]byte(emptyScaleSetList),
		readFixture(t, "runner_scale_set_single_label.json"),
	)
	report, created, err := c.EnsureScaleSet(context.Background(), fleet)
	if err != nil {
		t.Fatalf("EnsureScaleSet: %v", err)
	}
	if !created || !report.SingleNameLabel || !report.DisableUpdate {
		t.Fatalf("EnsureScaleSet = %+v, created %v; want compatible and created", report, created)
	}
	if store.postCount() != 1 {
		t.Fatalf("create requests = %d, want 1", store.postCount())
	}
	got := store.posts[0]
	if got.Name != "example-scaleset" ||
		got.RunnerGroupID != 1 ||
		len(got.Labels) != 1 ||
		got.Labels[0].Name != "example-scaleset" ||
		!got.RunnerSetting.DisableUpdate {
		t.Fatalf("create body = %+v, want one name label, default group, updates disabled", got)
	}
}

func TestEnsureScaleSetKeepsCompatibleScaleSet(t *testing.T) {
	c, store, fleet := ensureFixture(t, readFixture(t, "runner_scale_set_single_label.json"), nil)
	report, created, err := c.EnsureScaleSet(context.Background(), fleet)
	if err != nil {
		t.Fatalf("EnsureScaleSet: %v", err)
	}
	if created || !report.SingleNameLabel || !report.DisableUpdate {
		t.Fatalf("EnsureScaleSet = %+v, created %v; want compatible and not created", report, created)
	}
	if store.postCount() != 0 {
		t.Fatalf("create requests = %d, want 0", store.postCount())
	}
}

func TestEnsureScaleSetLeavesIncompatibleScaleSetAlone(t *testing.T) {
	c, store, fleet := ensureFixture(t, readFixture(t, "runner_scale_set_multi_label.json"), nil)
	_, created, err := c.EnsureScaleSet(context.Background(), fleet)
	if !errors.Is(err, ErrLabelMismatch) {
		t.Fatalf("EnsureScaleSet error = %v, want ErrLabelMismatch", err)
	}
	if created || store.postCount() != 0 {
		t.Fatalf("created = %v, create requests = %d; want neither", created, store.postCount())
	}
}

func TestEnsureScaleSetFailsWhenCreatedScaleSetIsNotServed(t *testing.T) {
	c, _, fleet := ensureFixture(t, []byte(emptyScaleSetList), []byte(emptyScaleSetList))
	_, created, err := c.EnsureScaleSet(context.Background(), fleet)
	if !errors.Is(err, ErrScaleSetNotFound) || !created {
		t.Fatalf("EnsureScaleSet = created %v, %v; want created and ErrScaleSetNotFound", created, err)
	}
}

func TestEnsureScaleSetRejectsForeignScopeWithoutRequests(t *testing.T) {
	c, store, fleet := ensureFixture(t, []byte(emptyScaleSetList), nil)
	fleet.GitHubConfigURL = "https://example.invalid/other/repository"
	_, _, err := c.EnsureScaleSet(context.Background(), fleet)
	if !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("EnsureScaleSet error = %v, want ErrIdentityMismatch", err)
	}
	if store.postCount() != 0 {
		t.Fatalf("create requests = %d, want 0", store.postCount())
	}
}
