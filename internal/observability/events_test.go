package observability

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/health"
)

func TestEventContainsOnlyClosedAggregateFields(t *testing.T) {
	assertEventType(t, reflect.TypeOf(Event{}), map[reflect.Type]bool{})
}

func TestHistoryPressureEventValidateRequiresClosedReasonContract(t *testing.T) {
	base := Event{
		Kind: EventHistoryPressureEvaluated,
		Reasons: PressureReasonHistoryRows |
			PressureReasonNetworkLedgerBytes,
		Snapshot: health.Snapshot{
			ObservedAt:          time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
			Readiness:           health.ReadinessReady,
			Pressure:            health.PressureWarning,
			OldestRetainedAge:   time.Minute,
			EffectiveCapacity:   1,
			PolicyEpoch:         9,
			HistoryRows:         10,
			HistoryLogicalBytes: 11,
		},
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("Validate(valid): %v", err)
	}

	invalid := []Event{
		func() Event {
			event := base
			event.Kind = EventKind(255)
			return event
		}(),
		func() Event {
			event := base
			event.Reasons = PressureReason(1 << 15)
			return event
		}(),
		func() Event {
			event := base
			event.Snapshot.Pressure = health.PressureNormal
			return event
		}(),
		func() Event {
			event := base
			event.Reasons = PressureReasonNone
			return event
		}(),
	}
	for i, event := range invalid {
		if err := event.Validate(); err == nil {
			t.Fatalf("Validate(invalid[%d]) succeeded", i)
		}
	}

	normal := base
	normal.Snapshot.Pressure = health.PressureNormal
	normal.Reasons = PressureReasonNone
	if err := normal.Validate(); err != nil {
		t.Fatalf("Validate(normal): %v", err)
	}
}

func assertEventType(t *testing.T, typ reflect.Type, seen map[reflect.Type]bool) {
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
				t.Fatalf("Event field %q contains forbidden identity-bearing name %q", field.Name, forbidden)
			}
		}
		if field.Type.Kind() == reflect.String {
			t.Fatalf("Event field %q is an arbitrary string", field.Name)
		}
		if field.Type.PkgPath() == "github.com/sumitake/portable-ghar/internal/observability" &&
			field.Type.Kind() == reflect.Struct {
			assertEventType(t, field.Type, seen)
		}
	}
}
