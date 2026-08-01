package productionruntime

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/cli"
	"github.com/sumitake/portable-ghar/internal/fleetfence"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"golang.org/x/sys/unix"
)

func TestSSHTransportProveUsesOneExactPinnedInvocation(t *testing.T) {
	t.Parallel()

	overlay, revision := transportTestOverlay(t)
	target := protocolTestTarget(t, overlay, revision)
	runner := &transportRunner{
		respond: func(request Request) (Response, error) {
			return NewTargetResponse(request, target)
		},
	}
	transport, err := NewSSHTransport(overlay, runner)
	if err != nil {
		t.Fatalf("NewSSHTransport() error = %v", err)
	}
	got, err := transport.ProveTarget(context.Background(), overlay)
	if err != nil {
		t.Fatalf("ProveTarget() error = %v", err)
	}
	if !reflect.DeepEqual(got, target) {
		t.Fatalf("ProveTarget() = %#v, want %#v", got, target)
	}
	if runner.calls != 1 || len(runner.files) != 0 {
		t.Fatalf(
			"runner calls=%d files=%v",
			runner.calls,
			runner.files,
		)
	}
	if !reflect.DeepEqual(runner.argv, expectedSSHArgv(overlay)) {
		t.Fatalf("argv = %#v, want %#v", runner.argv, expectedSSHArgv(overlay))
	}
	if runner.request.Action != ProtocolProveTarget ||
		runner.request.PrivateOverlayRevision != revision {
		t.Fatalf("request = %#v", runner.request)
	}
}

func TestSSHTransportExactArgvIsAcceptedByConfiguredOpenSSH(t *testing.T) {
	t.Parallel()

	overlay, _ := transportTestOverlay(t)
	transport, err := NewSSHTransport(overlay, &transportRunner{})
	if err != nil {
		t.Fatalf("NewSSHTransport() error = %v", err)
	}
	concrete, ok := transport.(*SSHTransport)
	if !ok {
		t.Fatalf("NewSSHTransport() type = %T", transport)
	}
	argv := concrete.argv()
	argv = append([]string{argv[0], "-G"}, argv[1:]...)
	command := exec.Command(argv[0], argv[1:]...)
	command.Env = []string{}
	var stdout, stderr strings.Builder
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil || stderr.Len() != 0 {
		t.Fatalf(
			"OpenSSH argv probe error=%v stderr=%q",
			err,
			stderr.String(),
		)
	}
	for _, expected := range []string{
		"sessiontype subsystem\n",
		"identityfile none\n",
		"identityfile " + transportCredentialPath(overlay) + "\n",
		"userknownhostsfile " +
			overlay.ManagementTransport.KnownHostsFile + "\n",
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("OpenSSH argv probe missing %q", expected)
		}
	}
}

func TestSSHTransportRejectsCanceledContextBeforeRunner(t *testing.T) {
	t.Parallel()

	overlay, _ := transportTestOverlay(t)
	runner := &transportRunner{}
	transport, err := NewSSHTransport(overlay, runner)
	if err != nil {
		t.Fatalf("NewSSHTransport() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := transport.ProveTarget(ctx, overlay); !errors.Is(
		err,
		ErrTransport,
	) {
		t.Fatalf("ProveTarget() error = %v", err)
	}
	if runner.calls != 0 {
		t.Fatalf("runner calls = %d, want 0", runner.calls)
	}
}

func TestSSHTransportRejectsDriftFailureAndAmbiguityWithoutRetry(t *testing.T) {
	t.Parallel()

	tests := map[string]func(
		*testing.T,
		*hostruntime.PrivateOverlay,
		*transportRunner,
	){
		"constructor overlay drift": func(
			_ *testing.T,
			overlay *hostruntime.PrivateOverlay,
			_ *transportRunner,
		) {
			overlay.ManagementTransport.Host = "other.example"
		},
		"stderr": func(
			_ *testing.T,
			_ *hostruntime.PrivateOverlay,
			runner *transportRunner,
		) {
			runner.result.Stderr = []byte("private diagnostic")
		},
		"nonzero": func(
			_ *testing.T,
			_ *hostruntime.PrivateOverlay,
			runner *transportRunner,
		) {
			runner.result.ExitCode = 1
		},
		"signal": func(
			_ *testing.T,
			_ *hostruntime.PrivateOverlay,
			runner *transportRunner,
		) {
			runner.result.ExitCode = -1
			runner.result.Signaled = true
			runner.result.Signal = "killed"
		},
		"stdout truncated": func(
			_ *testing.T,
			_ *hostruntime.PrivateOverlay,
			runner *transportRunner,
		) {
			runner.result.StdoutTruncated = true
		},
		"malformed response": func(
			_ *testing.T,
			_ *hostruntime.PrivateOverlay,
			runner *transportRunner,
		) {
			runner.rawStdout = []byte("{}\n")
		},
		"identity path swap": func(
			t *testing.T,
			overlay *hostruntime.PrivateOverlay,
			runner *transportRunner,
		) {
			identity := transportCredentialPath(*overlay)
			runner.during = func() {
				replaced := identity + ".old"
				if err := os.Rename(identity, replaced); err != nil {
					t.Fatalf("Rename() error = %v", err)
				}
				if err := os.WriteFile(
					identity,
					[]byte("replacement"),
					0o600,
				); err != nil {
					t.Fatalf("WriteFile() error = %v", err)
				}
			}
		},
	}
	for name, configure := range tests {
		name, configure := name, configure
		t.Run(name, func(t *testing.T) {
			overlay, revision := transportTestOverlay(t)
			target := protocolTestTarget(t, overlay, revision)
			runner := &transportRunner{
				respond: func(request Request) (Response, error) {
					return NewTargetResponse(request, target)
				},
			}
			transport, err := NewSSHTransport(overlay, runner)
			if err != nil {
				t.Fatalf("NewSSHTransport() error = %v", err)
			}
			callOverlay := overlay
			configure(t, &callOverlay, runner)
			if _, err := transport.ProveTarget(
				context.Background(),
				callOverlay,
			); !errors.Is(err, ErrTransport) {
				t.Fatalf("ProveTarget() error = %v", err)
			}
			if runner.calls > 1 {
				t.Fatalf("runner calls = %d, want at most 1", runner.calls)
			}
		})
	}
}

func TestSSHTransportRejectsUnsafeCredentialFilesBeforeRunner(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*testing.T, *hostruntime.PrivateOverlay){
		"identity symlink": func(
			t *testing.T,
			overlay *hostruntime.PrivateOverlay,
		) {
			path := transportCredentialPath(*overlay)
			target := path + ".target"
			if err := os.Rename(path, target); err != nil {
				t.Fatalf("Rename() error = %v", err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatalf("Symlink() error = %v", err)
			}
		},
		"identity directory": func(
			t *testing.T,
			overlay *hostruntime.PrivateOverlay,
		) {
			path := transportCredentialPath(*overlay)
			if err := os.Remove(path); err != nil {
				t.Fatalf("Remove() error = %v", err)
			}
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatalf("Mkdir() error = %v", err)
			}
		},
		"identity fifo": func(
			t *testing.T,
			overlay *hostruntime.PrivateOverlay,
		) {
			path := transportCredentialPath(*overlay)
			if err := os.Remove(path); err != nil {
				t.Fatalf("Remove() error = %v", err)
			}
			if err := unix.Mkfifo(path, 0o600); err != nil {
				t.Fatalf("Mkfifo() error = %v", err)
			}
		},
		"identity mode": func(
			t *testing.T,
			overlay *hostruntime.PrivateOverlay,
		) {
			if err := os.Chmod(
				transportCredentialPath(*overlay),
				0o640,
			); err != nil {
				t.Fatalf("Chmod() error = %v", err)
			}
		},
		"mutable known hosts": func(
			t *testing.T,
			overlay *hostruntime.PrivateOverlay,
		) {
			if err := os.Chmod(
				overlay.ManagementTransport.KnownHostsFile,
				0o666,
			); err != nil {
				t.Fatalf("Chmod() error = %v", err)
			}
		},
		"writable identity ancestor": func(
			t *testing.T,
			overlay *hostruntime.PrivateOverlay,
		) {
			if err := os.Chmod(
				filepath.Dir(transportCredentialPath(*overlay)),
				0o770,
			); err != nil {
				t.Fatalf("Chmod() error = %v", err)
			}
		},
		"known hosts symlink ancestor": func(
			t *testing.T,
			overlay *hostruntime.PrivateOverlay,
		) {
			root := filepath.Dir(
				overlay.ManagementTransport.KnownHostsFile,
			)
			realDirectory := filepath.Join(root, "real")
			linkDirectory := filepath.Join(root, "link")
			if err := os.Mkdir(realDirectory, 0o700); err != nil {
				t.Fatalf("Mkdir() error = %v", err)
			}
			knownHosts := filepath.Join(realDirectory, "known_hosts")
			if err := os.Rename(
				overlay.ManagementTransport.KnownHostsFile,
				knownHosts,
			); err != nil {
				t.Fatalf("Rename() error = %v", err)
			}
			if err := os.Symlink(realDirectory, linkDirectory); err != nil {
				t.Fatalf("Symlink() error = %v", err)
			}
			overlay.ManagementTransport.KnownHostsFile =
				filepath.Join(linkDirectory, "known_hosts")
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			overlay, _ := transportTestOverlay(t)
			runner := &transportRunner{}
			mutate(t, &overlay)
			transport, err := NewSSHTransport(overlay, runner)
			if err != nil {
				t.Fatalf("NewSSHTransport() error = %v", err)
			}
			if _, err := transport.ProveTarget(
				context.Background(),
				overlay,
			); !errors.Is(err, ErrTransport) {
				t.Fatalf("ProveTarget() error = %v", err)
			}
			if runner.calls != 0 {
				t.Fatalf("runner calls = %d, want 0", runner.calls)
			}
		})
	}
}

func TestSSHTransportCompletesOneClosedDeploySequence(t *testing.T) {
	t.Parallel()

	overlay, revision := transportTestOverlay(t)
	target := protocolTestTarget(t, overlay, revision)
	manifest := protocolTestManifest()
	manifestDocument, manifestDigest, err :=
		hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalRuntimeManifest() error = %v", err)
	}
	targetManifest := manifestDigest
	operationID, err := hostruntime.DeriveOperationID(
		hostruntime.OperationKindInstall,
		target.InstallDisposition,
		target.FenceGeneration,
		target.CurrentManifestDigest,
		&targetManifest,
		fleetfence.FleetPortable,
		revision,
	)
	if err != nil {
		t.Fatalf("DeriveOperationID() error = %v", err)
	}
	runner := &transportRunner{
		respond: func(request Request) (Response, error) {
			switch request.Action {
			case ProtocolProveTarget:
				return NewTargetResponse(request, target)
			case ProtocolStageRelease:
				stage, sealErr := cli.SealStageProof(cli.StageProof{
					SchemaVersion:          1,
					TargetProofDigest:      request.TargetProofDigest,
					PrivateOverlayRevision: request.PrivateOverlayRevision,
					ManifestDigest:         request.Stage.ManifestDigest,
				})
				if sealErr != nil {
					return Response{}, sealErr
				}
				return NewStageResponse(request, stage)
			case ProtocolInvoke:
				proof := request.TargetProofDigest
				return NewInvokeResponse(
					request,
					hostruntime.HostActionResult{
						SchemaVersion:     1,
						Status:            hostruntime.HostActionComplete,
						OperationID:       operationID,
						JournalDigest:     strings.Repeat("b", 64),
						TargetProofDigest: &proof,
						FenceGeneration:   1,
						ActiveFleet:       fleetfence.FleetPortable,
					},
				)
			default:
				return Response{}, errors.New("unexpected request action")
			}
		},
	}
	dependencies := cli.HostCommandDependencies{
		LoadPrivateOverlay: func(string) (
			hostruntime.PrivateOverlay,
			string,
			error,
		) {
			return overlay, revision, nil
		},
		LoadRuntimeManifest: func(string) (
			hostruntime.RuntimeManifest,
			[]byte,
			string,
			error,
		) {
			return manifest, manifestDocument, manifestDigest, nil
		},
		TransportForOverlay: func(
			loaded hostruntime.PrivateOverlay,
		) (cli.HostTransport, error) {
			return NewSSHTransport(loaded, runner)
		},
	}
	result, err := cli.RunHostCommand(
		context.Background(),
		[]string{
			"deploy", "host", "--private", "/private/runtime.json",
			"--acquisition", "disabled",
		},
		dependencies,
	)
	if err != nil {
		t.Fatalf("RunHostCommand() error = %v", err)
	}
	if runner.calls != 3 ||
		len(runner.requests) != 3 ||
		runner.requests[0].Action != ProtocolProveTarget ||
		runner.requests[1].Action != ProtocolStageRelease ||
		runner.requests[2].Action != ProtocolInvoke ||
		result.OperationID != operationID {
		t.Fatalf(
			"result=%#v calls=%d requests=%#v",
			result,
			runner.calls,
			runner.requests,
		)
	}
	invokeWire, err := MarshalRequest(runner.requests[2])
	if err != nil {
		t.Fatalf("MarshalRequest(invoke) error = %v", err)
	}
	for _, forbidden := range []string{
		"private_path",
		"expected_operation",
		"expected_fence",
		"expected_fleet",
		"environment",
		"argv",
	} {
		if strings.Contains(string(invokeWire), forbidden) {
			t.Fatalf("invoke wire contains forbidden field %q", forbidden)
		}
	}
}

type transportRunner struct {
	calls     int
	argv      []string
	files     []string
	request   Request
	requests  []Request
	result    hostruntime.Result
	rawStdout []byte
	respond   func(Request) (Response, error)
	during    func()
}

func (runner *transportRunner) Run(
	_ context.Context,
	argv []string,
	files []*os.File,
	stdin io.Reader,
) (hostruntime.Result, error) {
	runner.calls++
	runner.argv = append([]string(nil), argv...)
	for _, file := range files {
		runner.files = append(runner.files, file.Name())
	}
	wire, err := io.ReadAll(stdin)
	if err != nil {
		return hostruntime.Result{}, err
	}
	request, err := ParseRequest(wire)
	if err != nil {
		return hostruntime.Result{}, err
	}
	runner.request = request
	runner.requests = append(runner.requests, request)
	if runner.during != nil {
		runner.during()
	}
	result := runner.result
	if result.ExitCode == 0 &&
		result.Stderr == nil &&
		!result.StdoutTruncated &&
		!result.StderrTruncated &&
		!result.Signaled {
		switch {
		case runner.rawStdout != nil:
			result.Stdout = append([]byte(nil), runner.rawStdout...)
		case runner.respond != nil:
			response, responseErr := runner.respond(request)
			if responseErr != nil {
				return hostruntime.Result{}, responseErr
			}
			result.Stdout, responseErr = MarshalResponse(response, request)
			if responseErr != nil {
				return hostruntime.Result{}, responseErr
			}
		}
	}
	return result, nil
}

func transportTestOverlay(
	t *testing.T,
) (hostruntime.PrivateOverlay, string) {
	t.Helper()
	if _, err := os.Stat("/usr/bin/ssh"); err != nil {
		t.Skip("/usr/bin/ssh unavailable")
	}
	overlay, _ := protocolTestOverlay(t)
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	workingDirectory, err = filepath.EvalSymlinks(workingDirectory)
	if err != nil {
		t.Fatalf("EvalSymlinks(working directory) error = %v", err)
	}
	root, err := os.MkdirTemp(workingDirectory, ".transport-test-")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Errorf("RemoveAll(%q) error = %v", root, err)
		}
	})
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("EvalSymlinks() error = %v", err)
	}
	identity := filepath.Join(root, "identity")
	knownHosts := filepath.Join(root, "known_hosts")
	if err := os.WriteFile(identity, []byte("test identity"), 0o600); err != nil {
		t.Fatalf("WriteFile(identity) error = %v", err)
	}
	if err := os.WriteFile(
		knownHosts,
		[]byte("rhonas.example ssh-ed25519 test"),
		0o600,
	); err != nil {
		t.Fatalf("WriteFile(known hosts) error = %v", err)
	}
	overlay.ManagementTransport.OpenSSHBinary = "/usr/bin/ssh"
	overlay.ManagementTransport.KnownHostsFile = knownHosts
	overlay.ManagementTransport.ControlUID = uint32(os.Getuid())
	for index := range overlay.Secrets {
		if overlay.Secrets[index].Name ==
			overlay.ManagementTransport.CredentialName {
			overlay.Secrets[index].Ref.Ref = identity
		}
	}
	_, revision, err := hostruntime.MarshalPrivateOverlay(overlay)
	if err != nil {
		t.Fatalf("MarshalPrivateOverlay() error = %v", err)
	}
	return overlay, revision
}

func transportCredentialPath(overlay hostruntime.PrivateOverlay) string {
	for _, secret := range overlay.Secrets {
		if secret.Name == overlay.ManagementTransport.CredentialName {
			return secret.Ref.Ref
		}
	}
	return ""
}

func expectedSSHArgv(overlay hostruntime.PrivateOverlay) []string {
	transport := overlay.ManagementTransport
	timeout, _ := strconv.Atoi(
		strings.TrimSuffix(transport.ConnectionTimeout, "s"),
	)
	return []string{
		transport.OpenSSHBinary,
		"-F", "none",
		"-o", "BatchMode=yes",
		"-o", "IdentityFile=none",
		"-o", "CertificateFile=none",
		"-o", "IdentitiesOnly=yes",
		"-o", "IdentityAgent=none",
		"-o", "PubkeyAuthentication=yes",
		"-o", "HostbasedAuthentication=no",
		"-o", "GSSAPIAuthentication=no",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "PreferredAuthentications=publickey",
		"-o", "AddKeysToAgent=no",
		"-o", "PKCS11Provider=none",
		"-o", "SecurityKeyProvider=none",
		"-o", "CanonicalizeHostname=no",
		"-o", "CheckHostIP=no",
		"-o", "VerifyHostKeyDNS=no",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UpdateHostKeys=no",
		"-o", "HashKnownHosts=no",
		"-o", "KnownHostsCommand=none",
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "UserKnownHostsFile=" + transport.KnownHostsFile,
		"-o", "ControlMaster=no",
		"-o", "ControlPath=none",
		"-o", "ProxyCommand=none",
		"-o", "ProxyJump=none",
		"-o", "RequestTTY=no",
		"-o", "StdinNull=no",
		"-o", "ClearAllForwardings=yes",
		"-o", "ExitOnForwardFailure=yes",
		"-o", "PermitLocalCommand=no",
		"-o", "EnableEscapeCommandline=no",
		"-o", "ForwardAgent=no",
		"-o", "ForwardX11=no",
		"-o", "NumberOfPasswordPrompts=0",
		"-o", "ConnectionAttempts=1",
		"-o", "ConnectTimeout=" + strconv.Itoa(timeout),
		"-i", transportCredentialPath(overlay),
		"-p", strconv.FormatUint(uint64(transport.Port), 10),
		"-l", transport.User,
		"-s",
		"--",
		transport.Host,
		transport.Subsystem,
	}
}
