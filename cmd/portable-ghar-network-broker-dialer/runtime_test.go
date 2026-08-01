package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
)

func TestBrokerReadinessEncodingMatchesHostRuntimeWireContract(t *testing.T) {
	digest := strings.Repeat("a", 64)
	proof := brokerReadinessDocument{
		Version:           1,
		ReleaseGeneration: 1,
		PolicyDigest:      digest,
		PolicyIPv6Posture: string(networkjail.DenyViaIP6Tables),
		NamespaceOwner: hostruntime.ProcessIdentity{
			PID: 11, StartTime: 12,
		},
		Parser: brokerChildProcessIdentity{
			PID: 13, PPID: 11, StartTime: 14,
		},
		RelayDirectory: hostruntime.DirectoryIdentity{
			Device: 21, Inode: 22, UID: 23, GID: 24, Mode: 0o700,
		},
		RelaySocket: hostruntime.SocketIdentity{
			Name: "https.sock", Device: 21, Inode: 25,
			UID: 23, GID: 24, Mode: 0o600,
		},
		Control: brokerControlSocketIdentity{
			Device: 31, DialerInode: 32, ParserInode: 33,
		},
		AuthorityDirectory: hostruntime.DirectoryIdentity{
			Device: 41, Inode: 42, UID: 43, GID: 44, Mode: 0o700,
		},
		AuthoritySocket: hostruntime.SocketIdentity{
			Name: "dial-authority.sock", Device: 41, Inode: 45,
			UID: 43, GID: 44, Mode: 0o600,
		},
		AuthorityPeer:       hostruntime.ProcessIdentity{PID: 51, StartTime: 52},
		ParserControlFD:     networkjail.ParserControlFD,
		FilterVersion:       networkjail.ParserFilterVersion,
		FilterTSYNC:         true,
		AFINETErrno:         networkjail.ParserSocketErrno,
		AFINET6Errno:        networkjail.ParserSocketErrno,
		UnexpectedFDs:       0,
		ParserTaskCount:     3,
		ParserTasksVerified: 3,
	}
	document, err := encodeBrokerReadiness(proof)
	if err != nil {
		t.Fatalf("encodeBrokerReadiness: %v", err)
	}
	want := []byte(
		`{"version":1,"release_generation":1,"policy_digest":"` +
			digest +
			`","policy_ipv6_posture":"deny-via-ip6tables",` +
			`"namespace_owner":{"pid":11,"start_time":12},` +
			`"parser":{"pid":13,"ppid":11,"start_time":14},` +
			`"relay_directory":{"device":21,"inode":22,"uid":23,"gid":24,"mode":448},` +
			`"relay_socket":{"name":"https.sock","device":21,"inode":25,"uid":23,"gid":24,"mode":384},` +
			`"control":{"device":31,"dialer_inode":32,"parser_inode":33},` +
			`"authority_directory":{"device":41,"inode":42,"uid":43,"gid":44,"mode":448},` +
			`"authority_socket":{"name":"dial-authority.sock","device":41,"inode":45,"uid":43,"gid":44,"mode":384},` +
			`"authority_peer":{"pid":51,"start_time":52},` +
			`"parser_control_fd":3,"filter_version":1,"filter_tsync":true,` +
			`"af_inet_errno":1,"af_inet6_errno":1,"unexpected_fds":0,` +
			`"parser_task_count":3,"parser_tasks_verified":3}` + "\n",
	)
	if !bytes.Equal(document, want) {
		t.Fatalf("document=%q\nwant=%q", document, want)
	}
}

func TestBrokerReadinessRejectsNoncanonicalDigestAndIdentity(t *testing.T) {
	if _, err := encodeBrokerReadiness(brokerReadinessDocument{
		Version:      1,
		PolicyDigest: strings.Repeat("A", 64),
	}); err == nil {
		t.Fatal("invalid readiness was accepted")
	}
}
