package relaycontract

import (
	"bytes"
	"strings"
	"testing"
)

func TestBindingCanonicalRoundTrip(t *testing.T) {
	binding := validBinding()
	document, err := Encode(binding)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	loaded, err := Load(bytes.NewReader(document))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded != binding {
		t.Fatalf("loaded=%+v want=%+v", loaded, binding)
	}
}

func TestBindingRejectsUnclosedOrInsufficientIdentity(t *testing.T) {
	valid, err := Encode(validBinding())
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	tests := map[string][]byte{
		"unknown":         bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":1,"unknown":true`), 1),
		"duplicate":       bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1),
		"trailing":        append(append([]byte{}, valid...), []byte("{}")...),
		"noncanonical":    []byte(strings.Replace(string(valid), `{"version":1`, "{\n\"version\":1", 1)),
		"bad directory":   bytes.Replace(valid, []byte(`"mode":448`), []byte(`"mode":511`), 1),
		"bad socket":      bytes.Replace(valid, []byte(`"mode":384`), []byte(`"mode":438`), 1),
		"wrong name":      bytes.Replace(valid, []byte(`"name":"https.sock"`), []byte(`"name":"../https.sock"`), 1),
		"missing pid":     bytes.Replace(valid, []byte(`"pid":7001`), []byte(`"pid":0`), 1),
		"missing start":   bytes.Replace(valid, []byte(`"start_time":7002`), []byte(`"start_time":0`), 1),
		"device mismatch": bytes.Replace(valid, []byte(`"name":"https.sock","device":101`), []byte(`"name":"https.sock","device":999`), 1),
	}
	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(bytes.NewReader(document)); err == nil {
				t.Fatal("Load accepted invalid binding")
			}
		})
	}
}

func FuzzBindingLoadPreservesCanonicalClosedForm(f *testing.F) {
	canonical, err := Encode(validBinding())
	if err != nil {
		f.Fatalf("Encode: %v", err)
	}
	f.Add(canonical)
	f.Add([]byte{})
	f.Add([]byte("{\"version\":1}\n"))
	f.Fuzz(func(t *testing.T, document []byte) {
		binding, err := Load(bytes.NewReader(document))
		if err != nil {
			return
		}
		encoded, err := Encode(binding)
		if err != nil {
			t.Fatalf("accepted binding could not be encoded: %v", err)
		}
		if !bytes.Equal(encoded, document) {
			t.Fatalf("accepted noncanonical binding: got=%q want=%q", document, encoded)
		}
	})
}

func validBinding() Binding {
	return Binding{
		Version:          1,
		BrokerGeneration: 17,
		Directory:        Directory{Device: 101, Inode: 102, UID: 65532, GID: 65532, Mode: 0o700},
		Socket:           Socket{Name: HTTPSProxySocket, Device: 101, Inode: 103, UID: 65532, GID: 65532, Mode: 0o600},
		Peer:             Process{PID: 7001, StartTime: 7002},
	}
}
