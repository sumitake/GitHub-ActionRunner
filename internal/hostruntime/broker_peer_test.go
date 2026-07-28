package hostruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/relaycontract"
)

func TestBindBrokerPeerUsesOpaqueOneUseProofAndClosedExec(t *testing.T) {
	spec, cfg := validAdapterSpec(t)
	adapterID := strings.Repeat("c", 64)
	runner := &scriptedCommandRunner{results: []Result{
		{Stdout: []byte(adapterID + "\n")},
		{Stdout: []byte(managedAdapterInspectJSON(adapterID, spec))},
		{Stdout: []byte("OK\n")},
	}}
	cli, err := NewDockerCLI(cfg, runner)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	adapter, err := cli.CreateNetworkAdapter(context.Background(), spec)
	if err != nil {
		t.Fatalf("CreateNetworkAdapter: %v", err)
	}
	proof := newBrokerPeerProof(
		adapter,
		cli.issuer,
		spec.FleetGeneration,
		brokerDirectoryIdentity{Device: 101, Inode: 102, UID: 65532, GID: 65532, Mode: 0o700},
		brokerSocketIdentity{Name: "https.sock", Device: 101, Inode: 103, UID: 65532, GID: 65532, Mode: 0o600},
		brokerProcessIdentity{PID: 7001, StartTime: 7002},
	)
	if err := cli.BindBrokerPeer(context.Background(), adapter, proof); err != nil {
		t.Fatalf("BindBrokerPeer: %v", err)
	}
	if len(runner.commands) != 3 {
		t.Fatalf("command count=%d, want 3", len(runner.commands))
	}
	command := runner.commands[2]
	wantArgv := []string{cfg.DockerPath, "exec", "-i", adapterID, adapterEntrypoint, "bind-peer"}
	if !equalStrings(command.argv, wantArgv) {
		t.Fatalf("bind argv=%q want=%q", command.argv, wantArgv)
	}
	var wire relaycontract.Binding
	if err := json.Unmarshal(command.stdin, &wire); err != nil {
		t.Fatalf("bind payload: %v", err)
	}
	canonical, err := relaycontract.Encode(wire)
	if err != nil || !bytes.Equal(canonical, command.stdin) {
		t.Fatalf("bind payload is not canonical: err=%v payload=%q", err, command.stdin)
	}
	if wire.Version != 1 || wire.BrokerGeneration != spec.FleetGeneration ||
		wire.Directory.Mode != 0o700 || wire.Socket.Name != "https.sock" ||
		wire.Socket.Mode != 0o600 || wire.Peer.PID != 7001 || wire.Peer.StartTime != 7002 {
		t.Fatalf("bind wire=%+v", wire)
	}
}

func TestBindBrokerPeerRejectsForgedStaleOrRepeatedProof(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(BrokerPeerProof) BrokerPeerProof
	}{
		{"zero proof", func(BrokerPeerProof) BrokerPeerProof { return BrokerPeerProof{} }},
		{"stale generation", func(value BrokerPeerProof) BrokerPeerProof {
			value.brokerGeneration++
			return value
		}},
		{"different adapter", func(value BrokerPeerProof) BrokerPeerProof {
			value.adapterNonce[0] ^= 0xff
			return value
		}},
		{"socket mode", func(value BrokerPeerProof) BrokerPeerProof {
			value.socket.mode = 0o666
			return value
		}},
		{"same uid replacement without peer pid", func(value BrokerPeerProof) BrokerPeerProof {
			value.peer.pid = 0
			return value
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec, cfg := validAdapterSpec(t)
			adapterID := strings.Repeat("c", 64)
			runner := &scriptedCommandRunner{results: []Result{{Stdout: []byte(adapterID + "\n")}}}
			cli, err := NewDockerCLI(cfg, runner)
			if err != nil {
				t.Fatalf("NewDockerCLI: %v", err)
			}
			adapter, err := cli.CreateNetworkAdapter(context.Background(), spec)
			if err != nil {
				t.Fatalf("CreateNetworkAdapter: %v", err)
			}
			proof := newBrokerPeerProof(
				adapter,
				cli.issuer,
				spec.FleetGeneration,
				brokerDirectoryIdentity{Device: 101, Inode: 102, UID: 65532, GID: 65532, Mode: 0o700},
				brokerSocketIdentity{Name: "https.sock", Device: 101, Inode: 103, UID: 65532, GID: 65532, Mode: 0o600},
				brokerProcessIdentity{PID: 7001, StartTime: 7002},
			)
			if err := cli.BindBrokerPeer(context.Background(), adapter, test.mutate(proof)); err == nil {
				t.Fatal("BindBrokerPeer accepted invalid proof")
			}
			if len(runner.commands) != 1 {
				t.Fatalf("command count=%d, want create only", len(runner.commands))
			}
		})
	}

	t.Run("repeated", func(t *testing.T) {
		spec, cfg := validAdapterSpec(t)
		adapterID := strings.Repeat("c", 64)
		runner := &scriptedCommandRunner{results: []Result{
			{Stdout: []byte(adapterID + "\n")},
			{Stdout: []byte(managedAdapterInspectJSON(adapterID, spec))},
			{Stdout: []byte("OK\n")},
			{},
		}}
		cli, err := NewDockerCLI(cfg, runner)
		if err != nil {
			t.Fatalf("NewDockerCLI: %v", err)
		}
		adapter, err := cli.CreateNetworkAdapter(context.Background(), spec)
		if err != nil {
			t.Fatalf("CreateNetworkAdapter: %v", err)
		}
		proof := newBrokerPeerProof(
			adapter,
			cli.issuer,
			spec.FleetGeneration,
			brokerDirectoryIdentity{Device: 101, Inode: 102, UID: 65532, GID: 65532, Mode: 0o700},
			brokerSocketIdentity{Name: "https.sock", Device: 101, Inode: 103, UID: 65532, GID: 65532, Mode: 0o600},
			brokerProcessIdentity{PID: 7001, StartTime: 7002},
		)
		if err := cli.BindBrokerPeer(context.Background(), adapter, proof); err != nil {
			t.Fatalf("first BindBrokerPeer: %v", err)
		}
		if err := cli.BindBrokerPeer(context.Background(), adapter, proof); err == nil {
			t.Fatal("second BindBrokerPeer succeeded")
		}
		if len(runner.commands) != 4 ||
			!equalStrings(runner.commands[3].argv, []string{cfg.DockerPath, "rm", "-f", adapterID}) {
			t.Fatalf("repeat commands=%q", runner.commands)
		}
	})
}
