package networkjail

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

type Resolver interface {
	Resolve(context.Context, string) ([]netip.Addr, error)
}

type LiteralDialer interface {
	DialLiteral(context.Context, netip.Addr, uint16) (net.Conn, error)
}

type DialPermitClient interface {
	Request(context.Context, DialPermitRequest) (Permit, error)
}

type BrokerDialer struct {
	graph      DecisionGraph
	slot       CapacitySlotID
	generation JobGeneration
	resolver   Resolver
	literals   LiteralDialer
	permits    DialPermitClient
	sequencer  *PermitSequencer
}

func NewBrokerDialer(
	graph DecisionGraph,
	slot CapacitySlotID,
	generation JobGeneration,
	resolver Resolver,
	literals LiteralDialer,
	permits DialPermitClient,
) (*BrokerDialer, error) {
	if graph.digest == (Digest{}) || slot == 0 || generation == 0 ||
		resolver == nil || literals == nil || permits == nil {
		return nil, errors.New("networkjail: broker dialer unavailable")
	}
	return &BrokerDialer{
		graph:      graph,
		slot:       slot,
		generation: generation,
		resolver:   resolver,
		literals:   literals,
		permits:    permits,
		sequencer:  NewPermitSequencer(),
	}, nil
}

func (dialer *BrokerDialer) DialFrame(
	ctx context.Context,
	frame []byte,
) (net.Conn, error) {
	if ctx == nil || dialer == nil || dialer.sequencer == nil {
		return nil, errors.New("networkjail: dial cancelled")
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.New("networkjail: dial cancelled")
	}
	request, err := DecodeDialRequest(frame, dialer.graph)
	if err != nil {
		return nil, errors.New("networkjail: dial frame rejected")
	}

	var answers []netip.Addr
	if literal, parseErr := netip.ParseAddr(request.Host); parseErr == nil {
		answers = []netip.Addr{literal}
	} else {
		answers, err = dialer.resolver.Resolve(ctx, request.Host)
		if err != nil {
			return nil, errors.New("networkjail: resolution unavailable")
		}
	}
	answers, err = dialer.graph.ValidateAnswers(request, answers)
	if err != nil {
		return nil, errors.New("networkjail: resolved destination rejected")
	}

	for _, address := range answers {
		permit, err := dialer.sequencer.request(ctx, dialer.permits, DialPermitRequest{
			SlotID:        dialer.slot,
			JobGeneration: dialer.generation,
			Class:         DialClassJob,
		})
		if errors.Is(err, ErrPermitSequence) {
			return nil, ErrPermitSequence
		}
		if err != nil || !permit.validFor(dialer.slot, DialClassJob) {
			return nil, errors.New("networkjail: dial permit unavailable")
		}
		connection, dialErr := dialer.literals.DialLiteral(
			ctx,
			address,
			request.Port,
		)
		if dialErr == nil && connection != nil {
			return connection, nil
		}
		if connection != nil {
			_ = connection.Close()
		}
		if err := ctx.Err(); err != nil {
			return nil, errors.New("networkjail: dial cancelled")
		}
	}
	return nil, errors.New("networkjail: upstream unavailable")
}

func (permit Permit) validFor(slot CapacitySlotID, class DialClass) bool {
	return permit.slot == slot && permit.class == class && permit.number != 0
}
