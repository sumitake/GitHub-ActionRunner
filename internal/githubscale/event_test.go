package githubscale

import (
	"errors"
	"testing"
)

func TestLifecycleEventConstructorsRejectImpossibleShapes(t *testing.T) {
	validJob := JobRef{
		RunnerRequestID: 41,
		JobID:           "job-a",
	}
	tests := []struct {
		name string
		call func() error
	}{
		{
			name: "assigned missing request",
			call: func() error {
				_, err := NewAssignedEvent(AssignedEvent{
					JobRef: JobRef{JobID: validJob.JobID},
				})
				return err
			},
		},
		{
			name: "started missing runner id",
			call: func() error {
				_, err := NewStartedEvent(StartedEvent{
					JobRef:     validJob,
					RunnerName: "runner-a",
				})
				return err
			},
		},
		{
			name: "started missing runner name",
			call: func() error {
				_, err := NewStartedEvent(StartedEvent{
					JobRef:   validJob,
					RunnerID: 17,
				})
				return err
			},
		},
		{
			name: "completed missing result",
			call: func() error {
				_, err := NewCompletedEvent(CompletedEvent{
					JobRef:     validJob,
					RunnerID:   17,
					RunnerName: "runner-a",
				})
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(); !errors.Is(err, ErrEventShape) {
				t.Fatalf("constructor error = %v, want ErrEventShape", err)
			}
		})
	}
}

func TestLifecycleEventDefensivelyCopiesJobLabels(t *testing.T) {
	labels := []string{"self-hosted", "portable"}
	event, err := NewStartedEvent(StartedEvent{
		JobRef: JobRef{
			RunnerRequestID: 41,
			JobID:           "job-a",
			RequestLabels:   labels,
		},
		RunnerID:   17,
		RunnerName: "runner-a",
	})
	if err != nil {
		t.Fatalf("NewStartedEvent() = %v", err)
	}

	labels[0] = "mutated-input"
	first := event.Job()
	first.RequestLabels[1] = "mutated-output"
	second := event.Job()
	if second.RequestLabels[0] != "self-hosted" ||
		second.RequestLabels[1] != "portable" {
		t.Fatalf("event labels were mutable across copies: %v", second.RequestLabels)
	}
}
