// Command portable-ghar-network-adapter owns one otherwise-empty network
// namespace and, only after one opaque broker binding, relays bounded loopback
// TCP streams to one verified Unix-domain broker socket.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sumitake/portable-ghar/internal/relaycontract"
)

const (
	defaultControlDirectory = "/run/portable-ghar/state"
	defaultControlSocket    = "/run/portable-ghar/state/adapter.sock"
	defaultBrokerDirectory  = "/run/portable-ghar/broker"
)

type adapterRuntime struct {
	ioTimeout time.Duration
	hold      func() error
	bindPeer  func(context.Context, relaycontract.Binding) error
	namespace func() ([]byte, error)
}

func defaultAdapterRuntime() adapterRuntime {
	config := adapterConfig{
		controlDirectory: defaultControlDirectory,
		controlSocket:    defaultControlSocket,
		brokerDirectory:  defaultBrokerDirectory,
		endpoints: []relayEndpoint{{
			LoopbackAddress: "127.0.0.1:18080",
			SocketName:      relaycontract.HTTPSProxySocket,
		}},
		maxConnections: 32,
		ioTimeout:      30 * time.Second,
		verifyControl:  verifyControlPeer,
		verifyPeer:     verifyUnixPeer,
	}
	return adapterRuntime{
		ioTimeout: 5 * time.Second,
		hold:      func() error { return holdAdapter(config) },
		bindPeer: func(ctx context.Context, binding relaycontract.Binding) error {
			return forwardBinding(ctx, defaultControlSocket, binding, 5*time.Second)
		},
		namespace: currentNetworkNamespace,
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, runtime adapterRuntime) int {
	if len(args) != 1 || stdout == nil || stderr == nil || runtime.ioTimeout <= 0 {
		return adapterUnavailable(stderr, 2)
	}
	switch args[0] {
	case "hold":
		if runtime.hold == nil || requireEmptyInput(stdin) != nil || runtime.hold() != nil {
			return adapterUnavailable(stderr, 1)
		}
		return 0
	case "bind-peer":
		if runtime.bindPeer == nil {
			return adapterUnavailable(stderr, 1)
		}
		binding, err := relaycontract.Load(stdin)
		if err != nil {
			return adapterUnavailable(stderr, 1)
		}
		ctx, cancel := context.WithTimeout(context.Background(), runtime.ioTimeout)
		defer cancel()
		if err := runtime.bindPeer(ctx, binding); err != nil {
			return adapterUnavailable(stderr, 1)
		}
		if _, err := io.WriteString(stdout, "OK\n"); err != nil {
			return adapterUnavailable(stderr, 1)
		}
		return 0
	case "netns-id":
		if runtime.namespace == nil || requireEmptyInput(stdin) != nil {
			return adapterUnavailable(stderr, 1)
		}
		proof, err := runtime.namespace()
		if err != nil || !validNamespaceProof(proof) {
			return adapterUnavailable(stderr, 1)
		}
		if _, err := stdout.Write(proof); err != nil {
			return adapterUnavailable(stderr, 1)
		}
		return 0
	default:
		return adapterUnavailable(stderr, 2)
	}
}

func adapterUnavailable(stderr io.Writer, code int) int {
	if stderr != nil {
		_, _ = fmt.Fprintln(stderr, "portable-ghar-network-adapter: unavailable")
	}
	return code
}

func requireEmptyInput(reader io.Reader) error {
	if reader == nil {
		return nil
	}
	var probe [1]byte
	count, err := reader.Read(probe[:])
	if count != 0 || (err != nil && err != io.EOF) {
		return errors.New("network-adapter: input-free operation received input")
	}
	return nil
}

func validNamespaceProof(document []byte) bool {
	var proof struct {
		Version uint8  `json:"version"`
		Device  uint64 `json:"device"`
		Inode   uint64 `json:"inode"`
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&proof) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		proof.Version != 1 || proof.Device == 0 || proof.Inode == 0 {
		return false
	}
	canonical, err := json.Marshal(proof)
	return err == nil && bytes.Equal(append(canonical, '\n'), document)
}

func canonicalAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && strings.IndexByte(path, 0) < 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, defaultAdapterRuntime()))
}
