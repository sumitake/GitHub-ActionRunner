package health

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func validSnapshot() Snapshot {
	observedAt := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	return Snapshot{
		ObservedAt:                  observedAt,
		FleetAlias:                  "portable-fleet",
		AcquisitionMode:             AcquisitionEnabled,
		PolicyEpoch:                 8,
		PolicyDigest:                strings.Repeat("a", 64),
		RepositoryPolicyRevision:    4,
		Capacity:                    CapacitySummary{Configured: 6, Effective: 4, Occupied: 2, Available: 2, Queued: 1},
		AssignedJobs:                3,
		RunningJobs:                 2,
		OldestLiveAssignmentAge:     time.Minute,
		UnassignedReleasedListeners: 1,
		LastTerminalAt:              observedAt.Add(-time.Minute),
		HostProfileID:               "qts-capless-root",
		Degraded:                    true,
		BuildID:                     strings.Repeat("b", 64),
	}
}

func TestSnapshotJSONHasExactHeartbeatAllowlist(t *testing.T) {
	encoded, err := json.Marshal(validSnapshot())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	got := make([]string, 0, len(document))
	for key := range document {
		got = append(got, key)
	}
	sortStrings(got)
	want := []string{
		"acquisition_mode",
		"assigned_jobs",
		"build_id",
		"capacity",
		"degraded",
		"fleet_alias",
		"host_profile_id",
		"last_terminal_at",
		"observed_at",
		"oldest_live_assignment_age",
		"policy_digest",
		"policy_epoch",
		"repository_policy_revision",
		"running_jobs",
		"unassigned_released_listeners",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("keys = %v, want %v", got, want)
	}
	for _, forbidden := range []string{
		"repository_name", "assignment_key", "job_id", "runner_name", "message_id",
		"jit", "token", "secret", "path", "route", "command_output",
	} {
		if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
			t.Fatalf("heartbeat contains forbidden %q: %s", forbidden, encoded)
		}
	}
}

func TestSnapshotValidateRequiresClosedIdentityAndArithmetic(t *testing.T) {
	valid := validSnapshot()
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate(valid): %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*Snapshot)
	}{
		{"zero observed time", func(snapshot *Snapshot) { snapshot.ObservedAt = time.Time{} }},
		{"unknown mode", func(snapshot *Snapshot) { snapshot.AcquisitionMode = "other" }},
		{"zero epoch", func(snapshot *Snapshot) { snapshot.PolicyEpoch = 0 }},
		{"bad digest", func(snapshot *Snapshot) { snapshot.PolicyDigest = strings.Repeat("A", 64) }},
		{"bad fleet", func(snapshot *Snapshot) { snapshot.FleetAlias = "repo/controlled" }},
		{"bad profile", func(snapshot *Snapshot) { snapshot.HostProfileID = "custom" }},
		{"bad build", func(snapshot *Snapshot) { snapshot.BuildID = "build" }},
		{"capacity", func(snapshot *Snapshot) { snapshot.Capacity.Available = snapshot.Capacity.Effective + 1 }},
		{"capacity arithmetic", func(snapshot *Snapshot) { snapshot.Capacity.Available-- }},
		{"running exceeds assigned", func(snapshot *Snapshot) { snapshot.RunningJobs = snapshot.AssignedJobs + 1 }},
		{"negative age", func(snapshot *Snapshot) { snapshot.OldestLiveAssignmentAge = -time.Second }},
		{"future terminal", func(snapshot *Snapshot) { snapshot.LastTerminalAt = snapshot.ObservedAt.Add(time.Second) }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			snapshot := valid
			test.mutate(&snapshot)
			if err := snapshot.Validate(); err == nil {
				t.Fatal("Validate succeeded")
			}
		})
	}
}

func TestHistorySnapshotIsSeparateAndClosed(t *testing.T) {
	snapshotType := reflect.TypeOf(Snapshot{})
	historyType := reflect.TypeOf(HistorySnapshot{})
	for _, name := range []string{
		"HistoryRows",
		"HistoryLogicalBytes",
		"NetworkLedgerRows",
		"NetworkLedgerLogicalBytes",
		"UncertainAcknowledgements",
	} {
		if _, ok := snapshotType.FieldByName(name); ok {
			t.Fatalf("heartbeat retains history field %q", name)
		}
		if _, ok := historyType.FieldByName(name); !ok {
			t.Fatalf("history snapshot omitted %q", name)
		}
	}
	valid := HistorySnapshot{
		ObservedAt:        time.Now().UTC(),
		Pressure:          PressureNormal,
		PolicyEpoch:       1,
		OldestRetainedAge: time.Minute,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate(valid history): %v", err)
	}
	valid.Pressure = Pressure(255)
	if err := valid.Validate(); err == nil {
		t.Fatal("unknown history pressure accepted")
	}
}

type recordingSink struct {
	snapshots []Snapshot
	err       error
}

func (s *recordingSink) Publish(_ context.Context, snapshot Snapshot) error {
	s.snapshots = append(s.snapshots, snapshot)
	return s.err
}

func TestPublisherValidatesBeforeSink(t *testing.T) {
	sink := &recordingSink{}
	publisher, err := NewPublisher(sink)
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	invalid := validSnapshot()
	invalid.BuildID = "invalid"
	if err := publisher.Publish(context.Background(), invalid); !errors.Is(err, ErrPublish) {
		t.Fatalf("Publish(invalid) = %v", err)
	}
	if len(sink.snapshots) != 0 {
		t.Fatal("invalid snapshot reached sink")
	}
	valid := validSnapshot()
	if err := publisher.Publish(context.Background(), valid); err != nil {
		t.Fatalf("Publish(valid): %v", err)
	}
	if !reflect.DeepEqual(sink.snapshots, []Snapshot{valid}) {
		t.Fatalf("snapshots = %+v", sink.snapshots)
	}
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
