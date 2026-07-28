package networkjail

import (
	"context"
	"errors"
	"net/netip"
	"slices"
)

// ResolverChain tries the fixed policy-ordered DoH resolvers serially. It has
// no environment/system fallback and returns a cloned result from the first
// endpoint that produces a complete validated RRset.
type ResolverChain struct {
	resolvers []Resolver
}

func NewResolverChain(resolvers []Resolver) (*ResolverChain, error) {
	if len(resolvers) == 0 || len(resolvers) > 8 {
		return nil, errors.New("networkjail: resolver chain unavailable")
	}
	owned := slices.Clone(resolvers)
	for _, resolver := range owned {
		if resolver == nil {
			return nil, errors.New("networkjail: resolver chain invalid")
		}
	}
	return &ResolverChain{resolvers: owned}, nil
}

func (chain *ResolverChain) Resolve(
	ctx context.Context,
	name string,
) ([]netip.Addr, error) {
	if chain == nil || ctx == nil || len(chain.resolvers) == 0 {
		return nil, errors.New("networkjail: resolver chain unavailable")
	}
	for _, resolver := range chain.resolvers {
		answers, err := resolver.Resolve(ctx, name)
		if err == nil && len(answers) > 0 {
			return slices.Clone(answers), nil
		}
		if err := ctx.Err(); err != nil {
			return nil, errors.New("networkjail: resolver chain canceled")
		}
	}
	return nil, errors.New("networkjail: all fixed resolvers unavailable")
}

var _ Resolver = (*ResolverChain)(nil)
