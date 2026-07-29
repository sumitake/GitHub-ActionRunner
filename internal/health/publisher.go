package health

import (
	"context"
	"errors"
)

var ErrPublish = errors.New("health: publish failed")

// Sink is the final Worker heartbeat transport.
type Sink interface {
	Publish(context.Context, Snapshot) error
}

// Publisher validates every heartbeat before delegating to its sink.
type Publisher struct {
	sink Sink
}

func NewPublisher(sink Sink) (*Publisher, error) {
	if sink == nil {
		return nil, ErrPublish
	}
	return &Publisher{sink: sink}, nil
}

func (p *Publisher) Publish(ctx context.Context, snapshot Snapshot) error {
	if p == nil || p.sink == nil || snapshot.Validate() != nil {
		return ErrPublish
	}
	if err := p.sink.Publish(ctx, snapshot); err != nil {
		return errors.Join(ErrPublish, err)
	}
	return nil
}
