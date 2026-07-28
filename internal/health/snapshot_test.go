package health

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSnapshotContainsOnlyClosedAggregateFields(t *testing.T) {
	t.Helper()
	assertAggregateType(t, reflect.TypeOf(Snapshot{}), map[reflect.Type]bool{})
}

func TestSnapshotValidateRequiresClosedStatesAndNonnegativeAge(t *testing.T) {
	valid := Snapshot{
		ObservedAt:                time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
		Readiness:                 ReadinessReady,
		Pressure:                  PressureNormal,
		HistoryRows:               1,
		HistoryLogicalBytes:       2,
		NetworkLedgerRows:         3,
		NetworkLedgerLogicalBytes: 4,
		InflightWork:              5,
		UncertainAcknowledgements: 6,
		OldestRetainedAge:         time.Minute,
		EffectiveCapacity:         7,
		PolicyEpoch:               8,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate(valid): %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Snapshot)
	}{
		{"zero observed time", func(snapshot *Snapshot) { snapshot.ObservedAt = time.Time{} }},
		{"unknown readiness", func(snapshot *Snapshot) { snapshot.Readiness = Readiness(255) }},
		{"unknown pressure", func(snapshot *Snapshot) { snapshot.Pressure = Pressure(255) }},
		{"negative age", func(snapshot *Snapshot) { snapshot.OldestRetainedAge = -time.Second }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := valid
			tc.mutate(&snapshot)
			if err := snapshot.Validate(); err == nil {
				t.Fatalf("Validate(%s) succeeded", tc.name)
			}
		})
	}
}

func assertAggregateType(t *testing.T, typ reflect.Type, seen map[reflect.Type]bool) {
	t.Helper()
	if seen[typ] {
		return
	}
	seen[typ] = true
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		name := strings.ToLower(field.Name)
		for _, forbidden := range []string{
			"repository",
			"assignment",
			"job",
			"message",
			"payload",
			"content",
			"matched",
			"identity",
		} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("Snapshot field %q contains forbidden identity-bearing name %q", field.Name, forbidden)
			}
		}
		if field.Type.Kind() == reflect.String {
			t.Fatalf("Snapshot field %q is an arbitrary string", field.Name)
		}
		if field.Type.PkgPath() == "github.com/sumitake/portable-ghar/internal/health" &&
			field.Type.Kind() == reflect.Struct {
			assertAggregateType(t, field.Type, seen)
		}
	}
}
