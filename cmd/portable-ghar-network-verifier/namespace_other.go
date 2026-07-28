//go:build !linux

package main

import (
	"errors"

	"github.com/sumitake/portable-ghar/internal/networkjail"
)

func inspectCurrentNamespace() (networkjail.NamespaceSnapshot, error) {
	return networkjail.NamespaceSnapshot{},
		errors.New("network-verifier: namespace inspection unavailable")
}

func inspectNamespaceIdentity() (networkjail.NamespaceIdentity, error) {
	return networkjail.NamespaceIdentity{},
		errors.New("network-verifier: namespace inspection unavailable")
}
