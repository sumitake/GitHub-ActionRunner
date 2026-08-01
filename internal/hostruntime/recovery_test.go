package hostruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestInspectAndRemoveManagedUsesExactSlotInventoryAndRetainsLedger(t *testing.T) {
	root := t.TempDir()
	relay := filepath.Join(root, "slot-000099", "relay")
	authority := filepath.Join(root, "slot-000099", "authority")
	for _, path := range []string{relay, authority} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatalf("MkdirAll(%q): %v", path, err)
		}
		if err := os.Chmod(path, 0o700); err != nil {
			t.Fatalf("Chmod(%q): %v", path, err)
		}
	}
	ledger := filepath.Join(root, "network-ledger.sqlite")
	if err := os.WriteFile(ledger, []byte("retained"), 0o600); err != nil {
		t.Fatalf("write ledger fixture: %v", err)
	}

	ids := map[string]string{
		"network-adapter":       strings.Repeat("a", 64),
		"network-broker":        strings.Repeat("b", 64),
		"runner":                strings.Repeat("c", 64),
		"network-policy-helper": strings.Repeat("d", 64),
		"network-verifier":      strings.Repeat("e", 64),
	}
	spec := RecoverySpec{
		SlotIdentity:      "slot-000099",
		BuildID:           strings.Repeat("f", 64),
		FleetGeneration:   41,
		AdapterName:       "pghar-adapter-000099",
		BrokerName:        "pghar-broker-000099",
		RunnerName:        "pghar-runner-000099",
		ExpectedAdapterID: ids["network-adapter"],
		ExpectedBrokerID:  ids["network-broker"],
		ExpectedRunnerID:  ids["runner"],
		RelayParent:       relay,
		AuthorityParent:   authority,
	}
	names := map[string]string{
		"network-adapter":       spec.AdapterName,
		"network-broker":        spec.BrokerName,
		"runner":                spec.RunnerName,
		"network-policy-helper": spec.BrokerName + "-policy",
		"network-verifier":      "pghar-verifier-" + strings.Repeat("1", 32) + "-probe",
	}
	inputOrder := []string{
		"network-broker",
		"network-verifier",
		"network-adapter",
		"network-policy-helper",
		"runner",
	}
	results := []Result{{
		Stdout: []byte(
			ids[inputOrder[0]] + "\n" +
				ids[inputOrder[1]] + "\n" +
				ids[inputOrder[2]] + "\n" +
				ids[inputOrder[3]] + "\n" +
				ids[inputOrder[4]] + "\n",
		),
	}}
	for _, kind := range inputOrder {
		results = append(results, Result{Stdout: managedRecoveryInspectJSON(
			ids[kind],
			names[kind],
			kind,
			spec,
			true,
			nil,
		)})
	}
	for range inputOrder {
		results = append(results,
			Result{},
			Result{},
		)
	}
	results = append(results, Result{})
	runner := &scriptedCommandRunner{results: results}
	cli, err := NewDockerCLI(DockerCLIConfig{
		DockerPath:  "/usr/bin/docker",
		BrokerRoot:  root,
		SeccompRoot: root,
	}, runner)
	if err != nil {
		t.Fatalf("NewDockerCLI() = %v", err)
	}

	snapshot, err := cli.InspectManaged(context.Background(), spec)
	if err != nil {
		t.Fatalf("InspectManaged() = %v", err)
	}
	identities := snapshot.Identities()
	if identities.AdapterID != spec.ExpectedAdapterID ||
		identities.BrokerID != spec.ExpectedBrokerID ||
		identities.RunnerID != spec.ExpectedRunnerID {
		t.Fatalf("recovered identities = %+v, want exact persisted identities", identities)
	}
	observation := snapshot.Observation()
	if !observation.AdapterPresent || !observation.BrokerPresent ||
		!observation.RunnerPresent || !observation.RunnerRunning {
		t.Fatalf("managed observation = %+v, want all primary components live", observation)
	}

	if err := cli.RemoveManaged(context.Background(), snapshot); err != nil {
		t.Fatalf("RemoveManaged() = %v", err)
	}
	var removed []string
	for _, command := range runner.commands {
		if len(command.argv) >= 4 &&
			command.argv[1] == "rm" &&
			command.argv[2] == "-f" {
			removed = append(removed, command.argv[3])
		}
	}
	wantRemovalOrder := []string{
		ids["runner"],
		ids["network-verifier"],
		ids["network-policy-helper"],
		ids["network-broker"],
		ids["network-adapter"],
	}
	if !slices.Equal(removed, wantRemovalOrder) {
		t.Fatalf("removal order = %v, want %v", removed, wantRemovalOrder)
	}
	for _, command := range runner.commands {
		if len(command.argv) >= 2 &&
			command.argv[1] == "ps" &&
			!slices.Contains(command.argv, "--no-trunc") {
			t.Fatalf("managed inventory used truncated container IDs: %v", command.argv)
		}
	}
	for _, path := range []string{relay, authority} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("per-job directory %q remains: %v", path, err)
		}
	}
	if data, err := os.ReadFile(ledger); err != nil || string(data) != "retained" {
		t.Fatalf("retained ledger = %q, %v", data, err)
	}
}

func TestRemoveManagedRejectsFailedPositiveAbsenceListing(t *testing.T) {
	root := t.TempDir()
	relay := filepath.Join(root, "slot-000101", "relay")
	authority := filepath.Join(root, "slot-000101", "authority")
	for _, path := range []string{relay, authority} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatalf("MkdirAll(%q): %v", path, err)
		}
		if err := os.Chmod(path, 0o700); err != nil {
			t.Fatalf("Chmod(%q): %v", path, err)
		}
	}
	id := strings.Repeat("c", 64)
	spec := RecoverySpec{
		SlotIdentity:     "slot-000101",
		BuildID:          strings.Repeat("f", 64),
		FleetGeneration:  43,
		AdapterName:      "pghar-adapter-000101",
		BrokerName:       "pghar-broker-000101",
		RunnerName:       "pghar-runner-000101",
		ExpectedRunnerID: id,
		RelayParent:      relay,
		AuthorityParent:  authority,
	}
	runner := &scriptedCommandRunner{results: []Result{
		{Stdout: []byte(id + "\n")},
		{Stdout: managedRecoveryInspectJSON(
			id,
			spec.RunnerName,
			managedKindRunner,
			spec,
			true,
			nil,
		)},
		{},
		{ExitCode: 1, Stderr: []byte("inventory unavailable")},
		{},
	}}
	cli, err := NewDockerCLI(DockerCLIConfig{
		DockerPath:  "/usr/bin/docker",
		BrokerRoot:  root,
		SeccompRoot: root,
	}, runner)
	if err != nil {
		t.Fatalf("NewDockerCLI() = %v", err)
	}
	snapshot, err := cli.InspectManaged(context.Background(), spec)
	if err != nil {
		t.Fatalf("InspectManaged() = %v", err)
	}
	if err := cli.RemoveManaged(context.Background(), snapshot); err == nil {
		t.Fatal("RemoveManaged accepted a failed positive-absence inventory")
	}
}

func TestInspectManagedRejectsUnknownOrDriftedSlotObjects(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"extra label": func(document map[string]any) {
			labels := document["Config"].(map[string]any)["Labels"].(map[string]string)
			labels["job-controlled"] = "forbidden"
		},
		"unknown helper name": func(document map[string]any) {
			document["Name"] = "/wrong-policy-helper"
		},
		"wrong slot": func(document map[string]any) {
			labels := document["Config"].(map[string]any)["Labels"].(map[string]string)
			labels["io.portable-ghar.slot"] = "slot-other"
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			relay := filepath.Join(root, "slot-000100", "relay")
			authority := filepath.Join(root, "slot-000100", "authority")
			for _, path := range []string{relay, authority} {
				if err := os.MkdirAll(path, 0o700); err != nil {
					t.Fatalf("MkdirAll: %v", err)
				}
				if err := os.Chmod(path, 0o700); err != nil {
					t.Fatalf("Chmod: %v", err)
				}
			}
			id := strings.Repeat("a", 64)
			spec := RecoverySpec{
				SlotIdentity:    "slot-000100",
				BuildID:         strings.Repeat("f", 64),
				FleetGeneration: 42,
				AdapterName:     "pghar-adapter-000100",
				BrokerName:      "pghar-broker-000100",
				RunnerName:      "pghar-runner-000100",
				RelayParent:     relay,
				AuthorityParent: authority,
			}
			runner := &scriptedCommandRunner{results: []Result{
				{Stdout: []byte(id + "\n")},
				{Stdout: managedRecoveryInspectJSON(
					id,
					spec.BrokerName+"-policy",
					"network-policy-helper",
					spec,
					false,
					mutate,
				)},
			}}
			cli, err := NewDockerCLI(DockerCLIConfig{
				DockerPath:  "/usr/bin/docker",
				BrokerRoot:  root,
				SeccompRoot: root,
			}, runner)
			if err != nil {
				t.Fatalf("NewDockerCLI() = %v", err)
			}
			if _, err := cli.InspectManaged(context.Background(), spec); err == nil {
				t.Fatal("InspectManaged() accepted drifted slot object")
			}
		})
	}
}

func managedRecoveryInspectJSON(
	id string,
	name string,
	kind string,
	spec RecoverySpec,
	running bool,
	mutate func(map[string]any),
) []byte {
	document := map[string]any{
		"Id":   id,
		"Name": "/" + name,
		"Config": map[string]any{
			"Labels": map[string]string{
				"io.portable-ghar.managed":          "true",
				"io.portable-ghar.kind":             kind,
				"io.portable-ghar.build-id":         spec.BuildID,
				"io.portable-ghar.fleet-generation": fmt.Sprint(spec.FleetGeneration),
				"io.portable-ghar.slot":             spec.SlotIdentity,
			},
		},
		"State": map[string]any{"Running": running},
	}
	switch kind {
	case managedKindAdapter:
		document["Mounts"] = []map[string]any{{
			"Type":        "bind",
			"Source":      spec.RelayParent,
			"Destination": adapterMountDst,
			"RW":          false,
		}}
	case managedKindBroker:
		document["Mounts"] = []map[string]any{
			{
				"Type":        "bind",
				"Source":      spec.RelayParent,
				"Destination": brokerRelayMountDst,
				"RW":          true,
			},
			{
				"Type":        "bind",
				"Source":      spec.AuthorityParent,
				"Destination": brokerAuthorityMountDst,
				"RW":          false,
			},
		}
	default:
		document["Mounts"] = []map[string]any{}
	}
	if mutate != nil {
		mutate(document)
	}
	encoded, err := json.Marshal([]map[string]any{document})
	if err != nil {
		panic(err)
	}
	return append(encoded, '\n')
}
