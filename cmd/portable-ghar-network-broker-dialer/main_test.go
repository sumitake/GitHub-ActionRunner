package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

func TestBrokerMachineArmsReleasesOnceAndAudits(t *testing.T) {
	token := [32]byte{}
	for index := range token {
		token[index] = byte(index + 1)
	}
	digest := sha256.Sum256(token[:])
	readiness := brokerTestReadiness()
	releases := 0
	audits := 0
	machine := newBrokerMachine(
		func(
			_ context.Context,
			command hostruntime.BrokerReleaseCommand,
		) ([]byte, error) {
			releases++
			if command.ReleaseToken() != token {
				t.Fatal("release token drifted")
			}
			return readiness, nil
		},
		func(context.Context) ([]byte, error) {
			audits++
			return readiness, nil
		},
	)
	response, err := machine.apply(
		context.Background(),
		brokerOpArm,
		brokerArmFrame(digest),
	)
	if err != nil || string(response) != "OK\n" {
		t.Fatalf("arm response=%q err=%v", response, err)
	}
	release := brokerReleaseFrame(t, token)
	response, err = machine.apply(
		context.Background(),
		brokerOpRelease,
		release,
	)
	if err != nil || !bytes.Equal(response, readiness) {
		t.Fatalf("release response=%q err=%v", response, err)
	}
	response, err = machine.apply(context.Background(), brokerOpAudit, nil)
	if err != nil || !bytes.Equal(response, readiness) {
		t.Fatalf("audit response=%q err=%v", response, err)
	}
	if releases != 1 || audits != 1 {
		t.Fatalf("releases=%d audits=%d", releases, audits)
	}
	if _, err := machine.apply(
		context.Background(),
		brokerOpRelease,
		release,
	); err == nil {
		t.Fatal("second release was accepted")
	}
}

func TestBrokerMachineRejectsWrongTokenAndBecomesTerminal(t *testing.T) {
	digest := sha256.Sum256(bytes.Repeat([]byte{7}, 32))
	released := false
	machine := newBrokerMachine(
		func(
			context.Context,
			hostruntime.BrokerReleaseCommand,
		) ([]byte, error) {
			released = true
			return brokerTestReadiness(), nil
		},
		func(context.Context) ([]byte, error) { return nil, errors.New("unused") },
	)
	if _, err := machine.apply(
		context.Background(),
		brokerOpArm,
		brokerArmFrame(digest),
	); err != nil {
		t.Fatalf("arm: %v", err)
	}
	var wrong [32]byte
	for index := range wrong {
		wrong[index] = byte(index + 20)
	}
	if _, err := machine.apply(
		context.Background(),
		brokerOpRelease,
		brokerReleaseFrame(t, wrong),
	); err == nil {
		t.Fatal("wrong release token was accepted")
	}
	if released {
		t.Fatal("wrong token reached release runtime")
	}
	if _, err := machine.apply(
		context.Background(),
		brokerOpAudit,
		nil,
	); err == nil {
		t.Fatal("terminal machine accepted audit")
	}
}

func TestRunRoutesOnlyClosedOperations(t *testing.T) {
	var forwarded []brokerOperation
	runtime := brokerRuntime{
		hold: func(context.Context) error { return nil },
		forward: func(
			_ context.Context,
			operation brokerOperation,
			input io.Reader,
			output io.Writer,
		) error {
			forwarded = append(forwarded, operation)
			if operation == brokerOpAudit && input != nil {
				t.Fatal("audit received input")
			}
			_, err := output.Write([]byte("OK\n"))
			return err
		},
		authorityID: func() ([]byte, error) {
			return []byte("{\"version\":1}\n"), nil
		},
	}
	for _, operation := range []string{"hold", "arm", "release", "audit", "authority-id"} {
		var stdout, stderr bytes.Buffer
		var stdin io.Reader
		if operation == "arm" || operation == "release" {
			stdin = strings.NewReader("fixture")
		}
		if code := run(
			context.Background(),
			[]string{operation},
			stdin,
			&stdout,
			&stderr,
			runtime,
		); code != 0 {
			t.Fatalf("%s code=%d stdout=%q stderr=%q", operation, code, stdout.String(), stderr.String())
		}
	}
	if len(forwarded) != 3 ||
		forwarded[0] != brokerOpArm ||
		forwarded[1] != brokerOpRelease ||
		forwarded[2] != brokerOpAudit {
		t.Fatalf("forwarded=%v", forwarded)
	}
}

func TestRunHeldSocketAuditIsInputFreeAndCanonical(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(
		context.Background(),
		[]string{"socket-audit"},
		nil,
		&stdout,
		&stderr,
		brokerRuntime{
			hold: func(context.Context) error { return nil },
			forward: func(
				context.Context,
				brokerOperation,
				io.Reader,
				io.Writer,
			) error {
				return nil
			},
			authorityID: func() ([]byte, error) {
				return nil, nil
			},
			socketAudit: func() (heldSocketAuditReport, error) {
				return heldSocketAuditReport{Version: 1}, nil
			},
		},
	)
	if code != 0 ||
		stdout.String() != `{"version":1,"tcp4":0,"tcp6":0,"udp4":0,"udp6":0,"raw4":0,"raw6":0}`+"\n" ||
		stderr.Len() != 0 {
		t.Fatalf(
			"code=%d stdout=%q stderr=%q",
			code,
			stdout.String(),
			stderr.String(),
		)
	}
	var rejectedOut, rejectedErr bytes.Buffer
	if code := run(
		context.Background(),
		[]string{"socket-audit"},
		bytes.NewBufferString("x"),
		&rejectedOut,
		&rejectedErr,
		brokerRuntime{
			hold: func(context.Context) error { return nil },
			forward: func(
				context.Context,
				brokerOperation,
				io.Reader,
				io.Writer,
			) error {
				return nil
			},
			authorityID: func() ([]byte, error) { return nil, nil },
			socketAudit: func() (heldSocketAuditReport, error) {
				t.Fatal("socket audit ran with input")
				return heldSocketAuditReport{}, nil
			},
		},
	); code != 1 || rejectedOut.Len() != 0 {
		t.Fatalf(
			"rejected code=%d stdout=%q stderr=%q",
			code,
			rejectedOut.String(),
			rejectedErr.String(),
		)
	}
}

func brokerArmFrame(digest [32]byte) []byte {
	frame := make([]byte, 44)
	copy(frame[:8], "PGHBRARM")
	frame[8] = 1
	frame[9] = 1
	binary.BigEndian.PutUint16(frame[10:12], 32)
	copy(frame[12:], digest[:])
	return frame
}

func brokerReleaseFrame(t *testing.T, token [32]byte) []byte {
	t.Helper()
	authority := []byte(
		`{"version":1,"capacity_slot_id":7,"job_generation":11,` +
			`"ledger_revision":13,"directory":{"device":17,"inode":19,` +
			`"uid":65532,"gid":65532,"mode":448},"socket":{` +
			`"name":"dial-authority.sock","device":17,"inode":23,` +
			`"uid":65532,"gid":65532,"mode":384},"peer":{"pid":29,` +
			`"start_time":31}}` + "\n",
	)
	runtimePolicy := []byte("{\"version\":1}\n")
	policyDigest := sha256.Sum256([]byte("synthetic-policy"))
	runtimeDigest := sha256.Sum256(runtimePolicy)
	frame := make([]byte, 83+32+len(runtimePolicy)+len(authority))
	copy(frame[:8], "PGHBRREL")
	frame[8] = 1
	binary.BigEndian.PutUint16(frame[9:11], 32)
	copy(frame[11:43], policyDigest[:])
	binary.BigEndian.PutUint32(frame[43:47], uint32(len(authority)))
	binary.BigEndian.PutUint32(frame[47:51], uint32(len(runtimePolicy)))
	copy(frame[51:83], runtimeDigest[:])
	copy(frame[83:115], token[:])
	copy(frame[115:115+len(runtimePolicy)], runtimePolicy)
	copy(frame[115+len(runtimePolicy):], authority)
	command, err := hostruntime.DecodeBrokerReleaseCommand(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("fixture release invalid: %v", err)
	}
	command.Destroy()
	return frame
}

func brokerTestReadiness() []byte {
	return []byte("{\"version\":1}\n")
}
