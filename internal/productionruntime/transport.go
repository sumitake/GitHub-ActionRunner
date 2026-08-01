package productionruntime

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/sumitake/portable-ghar/internal/cli"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"golang.org/x/sys/unix"
)

var ErrTransport = errors.New("productionruntime: transport failed")

type SSHTransport struct {
	overlay         hostruntime.PrivateOverlay
	overlayDocument []byte
	revision        string
	credentialPath  string
	runner          hostruntime.CommandRunner
}

func NewSSHTransport(
	overlay hostruntime.PrivateOverlay,
	runner hostruntime.CommandRunner,
) (cli.HostTransport, error) {
	if runner == nil {
		return nil, ErrTransport
	}
	document, revision, err := hostruntime.MarshalPrivateOverlay(overlay)
	if err != nil {
		return nil, ErrTransport
	}
	frozen, frozenRevision, err := hostruntime.ParsePrivateOverlay(
		document,
		len(document),
	)
	if err != nil || frozenRevision != revision {
		return nil, ErrTransport
	}
	credentialPath := ""
	for _, secret := range frozen.Secrets {
		if secret.Name == frozen.ManagementTransport.CredentialName {
			credentialPath = secret.Ref.Ref
			break
		}
	}
	if credentialPath == "" {
		return nil, ErrTransport
	}
	if commandRunner, ok := runner.(*hostruntime.ExecCommandRunner); ok {
		commandRunner.StdinLimit = MaxWireBytes
		commandRunner.StdoutLimit = MaxWireBytes
		commandRunner.StderrLimit = MaxWireBytes
	}
	return &SSHTransport{
		overlay:         frozen,
		overlayDocument: append([]byte(nil), document...),
		revision:        revision,
		credentialPath:  credentialPath,
		runner:          runner,
	}, nil
}

func (transport *SSHTransport) ProveTarget(
	ctx context.Context,
	overlay hostruntime.PrivateOverlay,
) (cli.TargetProof, error) {
	if transport == nil || !transport.matchesOverlay(overlay) {
		return cli.TargetProof{}, ErrTransport
	}
	request, err := NewProveRequest(
		transport.overlay,
		transport.revision,
	)
	if err != nil {
		return cli.TargetProof{}, ErrTransport
	}
	response, err := transport.exchange(ctx, request)
	if err != nil || response.Target == nil {
		return cli.TargetProof{}, ErrTransport
	}
	return *response.Target, nil
}

func (transport *SSHTransport) Stage(
	ctx context.Context,
	target cli.TargetProof,
	release cli.StagedRelease,
) (cli.StageProof, error) {
	if transport == nil ||
		release.PrivateOverlayRevision() != transport.revision ||
		release.ManifestDigest() != transport.overlay.Manifest.Digest {
		return cli.StageProof{}, ErrTransport
	}
	canonical, digest, err := hostruntime.MarshalRuntimeManifest(
		release.Manifest(),
	)
	if err != nil ||
		digest != release.ManifestDigest() ||
		!bytes.Equal(canonical, release.ManifestDocument()) {
		return cli.StageProof{}, ErrTransport
	}
	request, err := NewStageRequest(
		transport.overlay,
		transport.revision,
		target,
		release.Manifest(),
		release.ManifestDigest(),
	)
	if err != nil {
		return cli.StageProof{}, ErrTransport
	}
	response, err := transport.exchange(ctx, request)
	if err != nil || response.Stage == nil {
		return cli.StageProof{}, ErrTransport
	}
	return *response.Stage, nil
}

func (transport *SSHTransport) Invoke(
	ctx context.Context,
	target cli.TargetProof,
	action cli.HostAction,
	arguments cli.FixedArguments,
) (cli.ActionResult, error) {
	if transport == nil ||
		arguments.PrivateOverlayRevision() != transport.revision ||
		arguments.ManifestDigest() != transport.overlay.Manifest.Digest ||
		arguments.TargetProofDigest() != target.ProofDigest {
		return cli.ActionResult{}, ErrTransport
	}
	invokeArguments := InvokeArguments{
		Acquisition:        arguments.Acquisition(),
		DrainPolicy:        arguments.DrainPolicy(),
		HostedConfirmation: arguments.HostedConfirmation(),
		RequireZero:        arguments.RequireZeroListeners(),
		ManifestDigest:     arguments.ManifestDigest(),
		StageProofDigest:   arguments.StageProofDigest(),
		TargetProofDigest:  arguments.TargetProofDigest(),
	}
	request, err := NewInvokeRequest(
		transport.overlay,
		transport.revision,
		target,
		action,
		invokeArguments,
	)
	if err != nil {
		return cli.ActionResult{}, ErrTransport
	}
	response, err := transport.exchange(ctx, request)
	if err != nil || response.Invoke == nil {
		return cli.ActionResult{}, ErrTransport
	}
	return cli.ActionResult{Result: *response.Invoke}, nil
}

func (transport *SSHTransport) exchange(
	ctx context.Context,
	request Request,
) (Response, error) {
	if transport == nil ||
		ctx == nil ||
		ctx.Err() != nil {
		return Response{}, ErrTransport
	}
	timeout, err := time.ParseDuration(
		transport.overlay.ManagementTransport.OperationTimeout,
	)
	if err != nil || timeout <= 0 {
		return Response{}, ErrTransport
	}
	wire, err := MarshalRequest(request)
	if err != nil {
		return Response{}, ErrTransport
	}
	files, err := transport.openFiles()
	if err != nil {
		return Response{}, ErrTransport
	}
	operationContext, cancel := context.WithTimeout(ctx, timeout)
	result, runErr := transport.runner.Run(
		operationContext,
		transport.argv(),
		nil,
		bytes.NewReader(wire),
	)
	cancel()
	revalidateErr := files.revalidate()
	closeErr := files.close()
	if runErr != nil ||
		revalidateErr != nil ||
		closeErr != nil ||
		result.ExitCode != 0 ||
		result.Signaled ||
		result.StdoutTruncated ||
		result.StderrTruncated ||
		len(result.Stderr) != 0 {
		return Response{}, ErrTransport
	}
	response, err := ParseResponse(result.Stdout, request)
	if err != nil {
		return Response{}, ErrTransport
	}
	return response, nil
}

func (transport *SSHTransport) matchesOverlay(
	overlay hostruntime.PrivateOverlay,
) bool {
	document, revision, err := hostruntime.MarshalPrivateOverlay(overlay)
	return err == nil &&
		revision == transport.revision &&
		bytes.Equal(document, transport.overlayDocument)
}

func (transport *SSHTransport) argv() []string {
	configuration := transport.overlay.ManagementTransport
	connectionTimeout, _ := time.ParseDuration(
		configuration.ConnectionTimeout,
	)
	return []string{
		configuration.OpenSSHBinary,
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
		"-o", "UserKnownHostsFile=" + configuration.KnownHostsFile,
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
		"-o", "ConnectTimeout=" +
			strconv.FormatInt(int64(connectionTimeout/time.Second), 10),
		"-i", transport.credentialPath,
		"-p", strconv.FormatUint(uint64(configuration.Port), 10),
		"-l", configuration.User,
		"-s",
		"--",
		configuration.Host,
		configuration.Subsystem,
	}
}

type transportFiles struct {
	binary     pinnedFile
	identity   pinnedFile
	knownHosts pinnedFile
}

func (transport *SSHTransport) openFiles() (transportFiles, error) {
	configuration := transport.overlay.ManagementTransport
	binary, err := openPinnedFile(
		configuration.OpenSSHBinary,
		pinnedBinary,
		configuration.ControlUID,
	)
	if err != nil {
		return transportFiles{}, err
	}
	identity, err := openPinnedFile(
		transport.credentialPath,
		pinnedIdentity,
		configuration.ControlUID,
	)
	if err != nil {
		_ = binary.file.Close()
		return transportFiles{}, err
	}
	knownHosts, err := openPinnedFile(
		configuration.KnownHostsFile,
		pinnedKnownHosts,
		configuration.ControlUID,
	)
	if err != nil {
		_ = identity.file.Close()
		_ = binary.file.Close()
		return transportFiles{}, err
	}
	return transportFiles{
		binary:     binary,
		identity:   identity,
		knownHosts: knownHosts,
	}, nil
}

func (files transportFiles) revalidate() error {
	failed := false
	for _, file := range []pinnedFile{
		files.binary,
		files.identity,
		files.knownHosts,
	} {
		if err := file.revalidate(); err != nil {
			failed = true
		}
	}
	if failed {
		return ErrTransport
	}
	return nil
}

func (files transportFiles) close() error {
	var failed bool
	for _, file := range []*os.File{
		files.knownHosts.file,
		files.identity.file,
		files.binary.file,
	} {
		if file != nil && file.Close() != nil {
			failed = true
		}
	}
	if failed {
		return ErrTransport
	}
	return nil
}

type pinnedFileKind uint8

const (
	pinnedBinary pinnedFileKind = iota + 1
	pinnedIdentity
	pinnedKnownHosts
)

type fileIdentity struct {
	device uint64
	inode  uint64
	uid    uint32
	mode   fs.FileMode
}

type pinnedFile struct {
	file       *os.File
	path       string
	identity   fileIdentity
	kind       pinnedFileKind
	controlUID uint32
}

func openPinnedFile(
	path string,
	kind pinnedFileKind,
	controlUID uint32,
) (pinnedFile, error) {
	if securePinnedAncestors(path, kind, controlUID) != nil {
		return pinnedFile{}, ErrTransport
	}
	fd, err := unix.Open(
		path,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK,
		0,
	)
	if err != nil {
		return pinnedFile{}, ErrTransport
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return pinnedFile{}, ErrTransport
	}
	identity, err := identityOfFile(file)
	if err != nil ||
		!validPinnedIdentity(identity, kind, controlUID) {
		_ = file.Close()
		return pinnedFile{}, ErrTransport
	}
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil {
		_ = file.Close()
		return pinnedFile{}, ErrTransport
	}
	if _, err := unix.FcntlInt(
		file.Fd(),
		unix.F_SETFL,
		flags&^unix.O_NONBLOCK,
	); err != nil {
		_ = file.Close()
		return pinnedFile{}, ErrTransport
	}
	pinned := pinnedFile{
		file:       file,
		path:       path,
		identity:   identity,
		kind:       kind,
		controlUID: controlUID,
	}
	if err := pinned.revalidate(); err != nil {
		_ = file.Close()
		return pinnedFile{}, ErrTransport
	}
	return pinned, nil
}

func (file pinnedFile) revalidate() error {
	if file.file == nil ||
		file.path == "" ||
		securePinnedAncestors(
			file.path,
			file.kind,
			file.controlUID,
		) != nil {
		return ErrTransport
	}
	descriptorIdentity, err := identityOfFile(file.file)
	if err != nil ||
		descriptorIdentity != file.identity ||
		!validPinnedIdentity(
			descriptorIdentity,
			file.kind,
			file.controlUID,
		) {
		return ErrTransport
	}
	pathIdentity, err := identityOfPath(file.path)
	if err != nil || pathIdentity != file.identity {
		return ErrTransport
	}
	return nil
}

func identityOfFile(file *os.File) (fileIdentity, error) {
	info, err := file.Stat()
	if err != nil {
		return fileIdentity{}, ErrTransport
	}
	return identityFromInfo(info)
}

func identityOfPath(path string) (fileIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return fileIdentity{}, ErrTransport
	}
	return identityFromInfo(info)
}

func identityFromInfo(info os.FileInfo) (fileIdentity, error) {
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() {
		return fileIdentity{}, ErrTransport
	}
	return fileIdentity{
		device: uint64(status.Dev),
		inode:  uint64(status.Ino),
		uid:    status.Uid,
		mode:   info.Mode(),
	}, nil
}

func validPinnedIdentity(
	identity fileIdentity,
	kind pinnedFileKind,
	controlUID uint32,
) bool {
	permissions := identity.mode.Perm()
	switch kind {
	case pinnedBinary:
		return identity.uid == 0 &&
			permissions&0o111 != 0 &&
			permissions&0o022 == 0
	case pinnedIdentity:
		return identity.uid == controlUID && permissions == 0o600
	case pinnedKnownHosts:
		return (identity.uid == 0 || identity.uid == controlUID) &&
			permissions&0o022 == 0
	default:
		return false
	}
}

func securePinnedAncestors(
	path string,
	kind pinnedFileKind,
	controlUID uint32,
) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrTransport
	}
	for directory := filepath.Dir(path); ; directory = filepath.Dir(directory) {
		info, err := os.Lstat(directory)
		if err != nil ||
			info.Mode()&os.ModeSymlink != 0 ||
			!info.IsDir() ||
			info.Mode().Perm()&0o022 != 0 {
			return ErrTransport
		}
		status, ok := info.Sys().(*syscall.Stat_t)
		if !ok ||
			status.Uid != 0 &&
				(kind == pinnedBinary || status.Uid != controlUID) {
			return ErrTransport
		}
		if directory == string(filepath.Separator) {
			break
		}
	}
	return nil
}

var _ cli.HostTransport = (*SSHTransport)(nil)
