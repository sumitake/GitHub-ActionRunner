package networkjail

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func TestResolverChainUsesOnlyFixedSerialOrder(t *testing.T) {
	first := &fakeResolver{err: errors.New("synthetic")}
	second := &fakeResolver{
		answers: []netip.Addr{publicV4(8, 8, 8, 8)},
	}
	chain, err := NewResolverChain([]Resolver{first, second})
	if err != nil {
		t.Fatalf("NewResolverChain: %v", err)
	}
	answers, err := chain.Resolve(context.Background(), "example.com")
	if err != nil || len(answers) != 1 ||
		answers[0] != publicV4(8, 8, 8, 8) ||
		len(first.calls) != 1 || len(second.calls) != 1 {
		t.Fatalf(
			"answers=%v err=%v first=%v second=%v",
			answers,
			err,
			first.calls,
			second.calls,
		)
	}
	answers[0] = publicV4(1, 1, 1, 1)
	if second.answers[0] != publicV4(8, 8, 8, 8) {
		t.Fatal("resolver chain exposed resolver-owned answers")
	}
}

func TestResolverChainRejectsEmptyOrNilMembers(t *testing.T) {
	if _, err := NewResolverChain(nil); err == nil {
		t.Fatal("empty resolver chain accepted")
	}
	if _, err := NewResolverChain([]Resolver{nil}); err == nil {
		t.Fatal("nil resolver accepted")
	}
}
