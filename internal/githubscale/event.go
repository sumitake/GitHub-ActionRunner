package githubscale

import "errors"

var ErrEventShape = errors.New("githubscale: lifecycle event shape invalid")

// EventKind is the closed discriminant for the three post-offer lifecycle
// observations translated from a scale-set message.
type EventKind uint8

const (
	EventAssigned EventKind = iota + 1
	EventStarted
	EventCompleted
)

// Event is a closed, immutable-by-copy lifecycle observation. Constructors
// prevent impossible combinations such as an Assigned event carrying a runner
// identity or a Started event carrying a completion result.
type Event struct {
	kind       EventKind
	job        JobRef
	runnerID   int64
	runnerName string
	result     string
}

func NewAssignedEvent(event AssignedEvent) (Event, error) {
	if !validEventJob(event.JobRef) {
		return Event{}, ErrEventShape
	}
	return Event{kind: EventAssigned, job: cloneJobRef(event.JobRef)}, nil
}

func NewStartedEvent(event StartedEvent) (Event, error) {
	if !validEventJob(event.JobRef) || event.RunnerID <= 0 || event.RunnerName == "" {
		return Event{}, ErrEventShape
	}
	return Event{
		kind:       EventStarted,
		job:        cloneJobRef(event.JobRef),
		runnerID:   event.RunnerID,
		runnerName: event.RunnerName,
	}, nil
}

func NewCompletedEvent(event CompletedEvent) (Event, error) {
	if !validEventJob(event.JobRef) ||
		event.RunnerID <= 0 ||
		event.RunnerName == "" ||
		event.Result == "" {
		return Event{}, ErrEventShape
	}
	return Event{
		kind:       EventCompleted,
		job:        cloneJobRef(event.JobRef),
		runnerID:   event.RunnerID,
		runnerName: event.RunnerName,
		result:     event.Result,
	}, nil
}

func (e Event) Kind() EventKind    { return e.kind }
func (e Event) Job() JobRef        { return cloneJobRef(e.job) }
func (e Event) RunnerID() int64    { return e.runnerID }
func (e Event) RunnerName() string { return e.runnerName }
func (e Event) Result() string     { return e.result }

func cloneJobRef(ref JobRef) JobRef {
	ref.RequestLabels = append([]string(nil), ref.RequestLabels...)
	return ref
}

func validEventJob(ref JobRef) bool {
	return ref.RunnerRequestID > 0 && ref.JobID != ""
}
