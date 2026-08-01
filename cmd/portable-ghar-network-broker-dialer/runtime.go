package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
	"golang.org/x/sys/unix"
)

const (
	brokerDialerSocketPath = "/run/portable-ghar/state/dialer.sock"
	brokerRelayDirectory   = "/run/portable-ghar/relay"
	brokerRelaySocketPath  = "/run/portable-ghar/relay/https.sock"
	brokerParserBinary     = "/usr/local/bin/portable-ghar-network-broker-parser"
	brokerCABundlePath     = "/etc/ssl/certs/ca-bundle.crt"
	brokerParserStartup    = 15 * time.Second
	brokerDialTimeout      = 10 * time.Second
	brokerPermitTimeout    = 5 * time.Second
)

type brokerChildProcessIdentity struct {
	PID       uint32 `json:"pid"`
	PPID      uint32 `json:"ppid"`
	StartTime uint64 `json:"start_time"`
}

type brokerControlSocketIdentity struct {
	Device      uint64 `json:"device"`
	DialerInode uint64 `json:"dialer_inode"`
	ParserInode uint64 `json:"parser_inode"`
}

type brokerReadinessDocument struct {
	Version             uint8                         `json:"version"`
	ReleaseGeneration   uint64                        `json:"release_generation"`
	PolicyDigest        string                        `json:"policy_digest"`
	PolicyIPv6Posture   string                        `json:"policy_ipv6_posture"`
	NamespaceOwner      hostruntime.ProcessIdentity   `json:"namespace_owner"`
	Parser              brokerChildProcessIdentity    `json:"parser"`
	RelayDirectory      hostruntime.DirectoryIdentity `json:"relay_directory"`
	RelaySocket         hostruntime.SocketIdentity    `json:"relay_socket"`
	Control             brokerControlSocketIdentity   `json:"control"`
	AuthorityDirectory  hostruntime.DirectoryIdentity `json:"authority_directory"`
	AuthoritySocket     hostruntime.SocketIdentity    `json:"authority_socket"`
	AuthorityPeer       hostruntime.ProcessIdentity   `json:"authority_peer"`
	ParserControlFD     uint32                        `json:"parser_control_fd"`
	FilterVersion       uint32                        `json:"filter_version"`
	FilterTSYNC         bool                          `json:"filter_tsync"`
	AFINETErrno         uint32                        `json:"af_inet_errno"`
	AFINET6Errno        uint32                        `json:"af_inet6_errno"`
	UnexpectedFDs       uint32                        `json:"unexpected_fds"`
	ParserTaskCount     uint32                        `json:"parser_task_count"`
	ParserTasksVerified uint32                        `json:"parser_tasks_verified"`
}

type brokerHolder struct {
	mu   sync.Mutex
	live *releasedBroker
}

type releasedBroker struct {
	cancel context.CancelFunc

	parser        *exec.Cmd
	parserControl *os.File
	dialer        *net.UnixListener
	dialerPath    brokerPathIdentity
	serverDone    chan error
	resolvers     []*networkjail.DoHResolver

	readiness []byte
	proof     brokerReadinessDocument
	authority hostruntime.AuthorityBinding
}

type brokerPathIdentity struct {
	device uint64
	inode  uint64
	uid    uint32
	gid    uint32
	mode   uint32
}

func holdBroker(ctx context.Context) error {
	if ctx == nil || !brokerPlatformSupported() {
		return errors.New("broker-dialer: held runtime unavailable")
	}
	holder := &brokerHolder{}
	machine := newBrokerMachine(holder.release, holder.audit)
	defer holder.close()
	return serveBrokerCommands(
		ctx,
		defaultBrokerControlPaths(),
		machine,
	)
}

func (holder *brokerHolder) release(
	ctx context.Context,
	command hostruntime.BrokerReleaseCommand,
) ([]byte, error) {
	if holder == nil || ctx == nil {
		return nil, errors.New("broker-dialer: release unavailable")
	}
	holder.mu.Lock()
	defer holder.mu.Unlock()
	if holder.live != nil {
		return nil, errors.New("broker-dialer: release replay")
	}
	live, err := startReleasedBroker(ctx, command)
	if err != nil {
		return nil, err
	}
	holder.live = live
	return bytes.Clone(live.readiness), nil
}

func (holder *brokerHolder) audit(ctx context.Context) ([]byte, error) {
	if holder == nil || ctx == nil {
		return nil, errors.New("broker-dialer: audit unavailable")
	}
	holder.mu.Lock()
	defer holder.mu.Unlock()
	if holder.live == nil {
		return nil, errors.New("broker-dialer: audit before release")
	}
	return holder.live.audit(ctx)
}

func (holder *brokerHolder) close() {
	if holder == nil {
		return
	}
	holder.mu.Lock()
	live := holder.live
	holder.live = nil
	holder.mu.Unlock()
	if live != nil {
		live.close()
	}
}

func startReleasedBroker(
	parent context.Context,
	command hostruntime.BrokerReleaseCommand,
) (*releasedBroker, error) {
	if parent == nil || !brokerPlatformSupported() {
		return nil, errors.New("broker-dialer: release unsupported")
	}
	runtimePolicy := command.RuntimePolicy()
	defer zero(runtimePolicy)
	graph, err := networkjail.DecodeDecisionGraph(bytes.NewReader(runtimePolicy))
	if err != nil || sha256.Sum256(runtimePolicy) != command.RuntimePolicyDigest() {
		return nil, errors.New("broker-dialer: runtime policy invalid")
	}
	authority := command.Authority()
	directory, socket, err := observeAuthorityObjects(
		brokerAuthoritySocket,
	)
	if err != nil ||
		directory != authority.Directory ||
		socket != authority.Socket ||
		observeAuthorityPeer(brokerAuthoritySocket, authority) != nil {
		return nil, errors.New("broker-dialer: authority binding changed")
	}
	roots, err := loadBrokerRoots(brokerCABundlePath)
	if err != nil {
		return nil, err
	}
	literals, err := networkjail.NewLiteralNetDialer(brokerDialTimeout)
	if err != nil {
		return nil, errors.New("broker-dialer: literal dialer unavailable")
	}
	permits, err := networkjail.NewUnixPermitClient(
		brokerAuthoritySocket,
		brokerPermitTimeout,
	)
	if err != nil {
		return nil, errors.New("broker-dialer: permit client unavailable")
	}
	resolvers := make([]*networkjail.DoHResolver, 0, graph.DoHEndpointCount())
	resolverInterfaces := make([]networkjail.Resolver, 0, graph.DoHEndpointCount())
	dohSequencer := networkjail.NewPermitSequencer()
	for endpoint := 0; endpoint < graph.DoHEndpointCount(); endpoint++ {
		resolver, resolverErr := networkjail.NewDoHResolverWithSequencer(
			graph,
			endpoint,
			roots,
			literals,
			permits,
			networkjail.CapacitySlotID(authority.CapacitySlotID),
			networkjail.JobGeneration(authority.JobGeneration),
			networkjail.DoHRuntimeConfig{
				RequestTimeout:      10 * time.Second,
				TLSHandshakeTimeout: 5 * time.Second,
				ConnectionLifetime:  5 * time.Minute,
				IdleTimeout:         time.Minute,
				MaxResponseBytes:    64 << 10,
				MaxRecords:          64,
				MinTTL:              1,
				MaxTTL:              86_400,
			},
			dohSequencer,
		)
		if resolverErr != nil {
			closeDoHResolvers(resolvers)
			return nil, errors.New("broker-dialer: resolver unavailable")
		}
		resolvers = append(resolvers, resolver)
		resolverInterfaces = append(resolverInterfaces, resolver)
	}
	resolverChain, err := networkjail.NewResolverChain(resolverInterfaces)
	if err != nil {
		closeDoHResolvers(resolvers)
		return nil, errors.New("broker-dialer: resolver chain unavailable")
	}
	dialer, err := networkjail.NewBrokerDialer(
		graph,
		networkjail.CapacitySlotID(authority.CapacitySlotID),
		networkjail.JobGeneration(authority.JobGeneration),
		resolverChain,
		literals,
		permits,
	)
	if err != nil {
		closeDoHResolvers(resolvers)
		return nil, errors.New("broker-dialer: broker dialer unavailable")
	}
	controlServer, err := networkjail.NewBrokerControlServer(
		dialer,
		networkjail.BrokerControlConfig{
			HandshakeTimeout: 10 * time.Second,
			RelayTimeout: time.Duration(
				graph.TailTimeoutSeconds(),
			) * time.Second,
			MaxClients: uint32(graph.JobOpenCap()),
		},
	)
	if err != nil {
		closeDoHResolvers(resolvers)
		return nil, errors.New("broker-dialer: control server unavailable")
	}
	listener, listenerIdentity, err := createDialerListener(
		brokerStateDirectory,
		brokerDialerSocketPath,
	)
	if err != nil {
		closeDoHResolvers(resolvers)
		return nil, err
	}
	liveCtx, cancel := context.WithCancel(parent)
	live := &releasedBroker{
		cancel:     cancel,
		dialer:     listener,
		dialerPath: listenerIdentity,
		serverDone: make(chan error, 1),
		resolvers:  resolvers,
		authority:  authority,
	}
	fail := func(cause error) (*releasedBroker, error) {
		live.close()
		return nil, cause
	}
	go func() {
		live.serverDone <- controlServer.Serve(liveCtx, listener)
	}()

	parentControl, childControl, controlIdentity, err := createParserControlPair()
	if err != nil {
		return fail(err)
	}
	live.parserControl = parentControl
	parser, proof, err := startBrokerParser(
		liveCtx,
		childControl,
		parentControl,
		runtimePolicy,
	)
	_ = childControl.Close()
	if err != nil {
		return fail(err)
	}
	live.parser = parser
	owner, _, err := observeProcessIdentity(os.Getpid())
	if err != nil {
		return fail(err)
	}
	parserIdentity, parserPPID, err := observeProcessIdentity(parser.Process.Pid)
	if err != nil || parserPPID != owner.PID {
		return fail(errors.New("broker-dialer: parser process invalid"))
	}
	controlDevice, parserControlInode, err := observeProcessFDIdentity(
		parser.Process.Pid,
		networkjail.ParserControlFD,
	)
	if err != nil ||
		controlDevice != controlIdentity.Device ||
		parserControlInode != controlIdentity.ParserInode {
		return fail(errors.New("broker-dialer: parser control changed"))
	}
	relayDirectory, relaySocket, err := observeRelayObjects(
		brokerRelayDirectory,
		brokerRelaySocketPath,
	)
	if err != nil {
		return fail(err)
	}
	policyDigest := command.PolicyDigest()
	readiness := brokerReadinessDocument{
		Version:           1,
		ReleaseGeneration: 1,
		PolicyDigest:      hex.EncodeToString(policyDigest[:]),
		PolicyIPv6Posture: string(graph.BrokerIPv6Posture()),
		NamespaceOwner:    owner,
		Parser: brokerChildProcessIdentity{
			PID:       parserIdentity.PID,
			PPID:      parserPPID,
			StartTime: parserIdentity.StartTime,
		},
		RelayDirectory:      relayDirectory,
		RelaySocket:         relaySocket,
		Control:             controlIdentity,
		AuthorityDirectory:  authority.Directory,
		AuthoritySocket:     authority.Socket,
		AuthorityPeer:       authority.Peer,
		ParserControlFD:     proof.ControlFD,
		FilterVersion:       proof.FilterVersion,
		FilterTSYNC:         proof.FilterTSYNC,
		AFINETErrno:         proof.AFINETErrno,
		AFINET6Errno:        proof.AFINET6Errno,
		UnexpectedFDs:       proof.UnexpectedFDs,
		ParserTaskCount:     proof.TaskCount,
		ParserTasksVerified: proof.TasksVerified,
	}
	document, err := encodeBrokerReadiness(readiness)
	if err != nil {
		return fail(err)
	}
	live.proof = readiness
	live.readiness = document
	return live, nil
}

func (live *releasedBroker) audit(ctx context.Context) ([]byte, error) {
	if live == nil || ctx == nil ||
		live.parser == nil || live.parser.Process == nil ||
		live.parserControl == nil || live.dialer == nil ||
		len(live.readiness) == 0 {
		return nil, errors.New("broker-dialer: audit unavailable")
	}
	select {
	case <-ctx.Done():
		return nil, errors.New("broker-dialer: audit canceled")
	case err := <-live.serverDone:
		if err == nil {
			return nil, errors.New("broker-dialer: control server stopped")
		}
		return nil, errors.New("broker-dialer: control server failed")
	default:
	}
	owner, _, err := observeProcessIdentity(os.Getpid())
	if err != nil || owner != live.proof.NamespaceOwner {
		return nil, errors.New("broker-dialer: namespace owner changed")
	}
	parser, ppid, err := observeProcessIdentity(live.parser.Process.Pid)
	if err != nil ||
		parser.PID != live.proof.Parser.PID ||
		parser.StartTime != live.proof.Parser.StartTime ||
		ppid != live.proof.Parser.PPID {
		return nil, errors.New("broker-dialer: parser identity changed")
	}
	device, inode, err := observeFDIdentity(live.parserControl)
	if err != nil ||
		device != live.proof.Control.Device ||
		inode != live.proof.Control.DialerInode {
		return nil, errors.New("broker-dialer: dialer control changed")
	}
	parserDevice, parserInode, err := observeProcessFDIdentity(
		live.parser.Process.Pid,
		networkjail.ParserControlFD,
	)
	if err != nil ||
		parserDevice != live.proof.Control.Device ||
		parserInode != live.proof.Control.ParserInode {
		return nil, errors.New("broker-dialer: parser control changed")
	}
	directory, socket, err := observeRelayObjects(
		brokerRelayDirectory,
		brokerRelaySocketPath,
	)
	if err != nil ||
		directory != live.proof.RelayDirectory ||
		socket != live.proof.RelaySocket {
		return nil, errors.New("broker-dialer: relay identity changed")
	}
	if err := verifyDialerListener(
		brokerDialerSocketPath,
		live.dialerPath,
	); err != nil {
		return nil, err
	}
	authorityDirectory, authoritySocket, err := observeAuthorityObjects(
		brokerAuthoritySocket,
	)
	if err != nil ||
		authorityDirectory != live.proof.AuthorityDirectory ||
		authoritySocket != live.proof.AuthoritySocket ||
		observeAuthorityPeer(
			brokerAuthoritySocket,
			live.authority,
		) != nil {
		return nil, errors.New("broker-dialer: authority identity changed")
	}
	document, err := encodeBrokerReadiness(live.proof)
	if err != nil || !bytes.Equal(document, live.readiness) {
		zero(document)
		return nil, errors.New("broker-dialer: readiness changed")
	}
	zero(document)
	return bytes.Clone(live.readiness), nil
}

func (live *releasedBroker) close() {
	if live == nil {
		return
	}
	if live.cancel != nil {
		live.cancel()
	}
	if live.dialer != nil {
		_ = live.dialer.Close()
	}
	if live.parserControl != nil {
		_ = live.parserControl.Close()
	}
	if live.parser != nil && live.parser.Process != nil {
		_ = live.parser.Process.Signal(os.Interrupt)
		wait := make(chan error, 1)
		go func() { wait <- live.parser.Wait() }()
		select {
		case <-wait:
		case <-time.After(2 * time.Second):
			_ = live.parser.Process.Kill()
			<-wait
		}
	}
	closeDoHResolvers(live.resolvers)
	removeOwnedSocket(brokerDialerSocketPath, live.dialerPath)
	zero(live.readiness)
	live.readiness = nil
}

func startBrokerParser(
	ctx context.Context,
	child,
	parent *os.File,
	policy []byte,
) (*exec.Cmd, networkjail.ParserReadiness, error) {
	if ctx == nil || child == nil || parent == nil || len(policy) == 0 {
		return nil, networkjail.ParserReadiness{},
			errors.New("broker-dialer: parser inputs invalid")
	}
	if err := parent.SetDeadline(time.Now().Add(brokerParserStartup)); err != nil {
		return nil, networkjail.ParserReadiness{},
			errors.New("broker-dialer: parser deadline failed")
	}
	command := exec.CommandContext(ctx, brokerParserBinary, "serve")
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.ExtraFiles = []*os.File{child}
	if err := command.Start(); err != nil {
		return nil, networkjail.ParserReadiness{},
			errors.New("broker-dialer: parser start failed")
	}
	if err := networkjail.WriteParserPolicy(parent, policy); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return nil, networkjail.ParserReadiness{},
			errors.New("broker-dialer: parser policy failed")
	}
	proof, err := networkjail.ReadParserReadiness(parent)
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return nil, networkjail.ParserReadiness{},
			errors.New("broker-dialer: parser readiness failed")
	}
	if err := parent.SetDeadline(time.Time{}); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return nil, networkjail.ParserReadiness{},
			errors.New("broker-dialer: parser deadline reset failed")
	}
	return command, proof, nil
}

func createParserControlPair() (
	*os.File,
	*os.File,
	brokerControlSocketIdentity,
	error,
) {
	descriptors, err := unix.Socketpair(
		unix.AF_UNIX,
		unix.SOCK_STREAM,
		0,
	)
	if err != nil {
		return nil, nil, brokerControlSocketIdentity{},
			errors.New("broker-dialer: parser control unavailable")
	}
	unix.CloseOnExec(descriptors[0])
	unix.CloseOnExec(descriptors[1])
	parent := os.NewFile(uintptr(descriptors[0]), "broker-dialer-control")
	child := os.NewFile(uintptr(descriptors[1]), "broker-parser-control")
	if parent == nil || child == nil {
		if parent != nil {
			_ = parent.Close()
		} else {
			_ = unix.Close(descriptors[0])
		}
		if child != nil {
			_ = child.Close()
		} else {
			_ = unix.Close(descriptors[1])
		}
		return nil, nil, brokerControlSocketIdentity{},
			errors.New("broker-dialer: parser control invalid")
	}
	device, parentInode, err := observeFDIdentity(parent)
	childDevice, childInode, childErr := observeFDIdentity(child)
	if err != nil || childErr != nil || device != childDevice ||
		parentInode == childInode {
		_ = parent.Close()
		_ = child.Close()
		return nil, nil, brokerControlSocketIdentity{},
			errors.New("broker-dialer: parser control identity invalid")
	}
	return parent, child, brokerControlSocketIdentity{
		Device:      device,
		DialerInode: parentInode,
		ParserInode: childInode,
	}, nil
}

func createDialerListener(
	directory,
	socket string,
) (*net.UnixListener, brokerPathIdentity, error) {
	if verifyPrivateDirectory(directory) != nil ||
		socket != filepath.Join(directory, "dialer.sock") {
		return nil, brokerPathIdentity{},
			errors.New("broker-dialer: listener path invalid")
	}
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		return nil, brokerPathIdentity{},
			errors.New("broker-dialer: listener path exists")
	}
	listener, err := net.ListenUnix(
		"unix",
		&net.UnixAddr{Name: socket, Net: "unix"},
	)
	if err != nil {
		return nil, brokerPathIdentity{},
			errors.New("broker-dialer: listener unavailable")
	}
	listener.SetUnlinkOnClose(false)
	if err := os.Chmod(socket, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(socket)
		return nil, brokerPathIdentity{},
			errors.New("broker-dialer: listener mode failed")
	}
	identity, err := observeSocketPath(socket)
	if err != nil {
		_ = listener.Close()
		_ = os.Remove(socket)
		return nil, brokerPathIdentity{}, err
	}
	return listener, identity, nil
}

func observeRelayObjects(
	directory,
	socket string,
) (
	hostruntime.DirectoryIdentity,
	hostruntime.SocketIdentity,
	error,
) {
	if socket != filepath.Join(directory, "https.sock") {
		return hostruntime.DirectoryIdentity{},
			hostruntime.SocketIdentity{},
			errors.New("broker-dialer: relay path invalid")
	}
	var directoryStat unix.Stat_t
	if unix.Lstat(directory, &directoryStat) != nil ||
		uint32(directoryStat.Mode)&unix.S_IFMT != unix.S_IFDIR ||
		uint32(directoryStat.Mode)&0o777 != 0o700 ||
		directoryStat.Uid != uint32(os.Geteuid()) ||
		directoryStat.Gid != uint32(os.Getegid()) ||
		directoryStat.Nlink == 0 {
		return hostruntime.DirectoryIdentity{},
			hostruntime.SocketIdentity{},
			errors.New("broker-dialer: relay directory invalid")
	}
	var socketStat unix.Stat_t
	if unix.Lstat(socket, &socketStat) != nil ||
		uint32(socketStat.Mode)&unix.S_IFMT != unix.S_IFSOCK ||
		uint32(socketStat.Mode)&0o777 != 0o600 ||
		socketStat.Dev != directoryStat.Dev ||
		socketStat.Uid != directoryStat.Uid ||
		socketStat.Gid != directoryStat.Gid ||
		socketStat.Nlink != 1 {
		return hostruntime.DirectoryIdentity{},
			hostruntime.SocketIdentity{},
			errors.New("broker-dialer: relay socket invalid")
	}
	return hostruntime.DirectoryIdentity{
			Device: uint64(directoryStat.Dev),
			Inode:  directoryStat.Ino,
			UID:    directoryStat.Uid,
			GID:    directoryStat.Gid,
			Mode:   uint32(directoryStat.Mode) & 0o777,
		}, hostruntime.SocketIdentity{
			Name:   "https.sock",
			Device: uint64(socketStat.Dev),
			Inode:  socketStat.Ino,
			UID:    socketStat.Uid,
			GID:    socketStat.Gid,
			Mode:   uint32(socketStat.Mode) & 0o777,
		}, nil
}

func observeSocketPath(path string) (brokerPathIdentity, error) {
	var stat unix.Stat_t
	if unix.Lstat(path, &stat) != nil ||
		uint32(stat.Mode)&unix.S_IFMT != unix.S_IFSOCK ||
		uint32(stat.Mode)&0o777 != 0o600 ||
		stat.Uid != uint32(os.Geteuid()) ||
		stat.Gid != uint32(os.Getegid()) ||
		stat.Nlink != 1 {
		return brokerPathIdentity{},
			errors.New("broker-dialer: socket identity invalid")
	}
	return brokerPathIdentity{
		device: uint64(stat.Dev),
		inode:  stat.Ino,
		uid:    stat.Uid,
		gid:    stat.Gid,
		mode:   uint32(stat.Mode),
	}, nil
}

func verifyDialerListener(path string, expected brokerPathIdentity) error {
	current, err := observeSocketPath(path)
	if err != nil || current != expected {
		return errors.New("broker-dialer: listener identity changed")
	}
	return nil
}

func removeOwnedSocket(path string, expected brokerPathIdentity) {
	if expected == (brokerPathIdentity{}) {
		return
	}
	if current, err := observeSocketPath(path); err == nil &&
		current == expected {
		_ = os.Remove(path)
	}
}

func loadBrokerRoots(path string) (*x509.CertPool, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("broker-dialer: trust bundle unavailable")
	}
	const maximum = 2 << 20
	document, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil ||
		len(document) == 0 || len(document) > maximum {
		zero(document)
		return nil, errors.New("broker-dialer: trust bundle invalid")
	}
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(document)
	zero(document)
	if !ok {
		return nil, errors.New("broker-dialer: trust bundle invalid")
	}
	return roots, nil
}

func encodeBrokerReadiness(
	proof brokerReadinessDocument,
) ([]byte, error) {
	if validateBrokerReadiness(proof) != nil {
		return nil, errors.New("broker-dialer: readiness invalid")
	}
	document, err := json.Marshal(proof)
	if err != nil || len(document)+1 > maxBrokerCommandResponse {
		zero(document)
		return nil, errors.New("broker-dialer: readiness unavailable")
	}
	return append(document, '\n'), nil
}

func validateBrokerReadiness(proof brokerReadinessDocument) error {
	if proof.Version != 1 || proof.ReleaseGeneration != 1 ||
		len(proof.PolicyDigest) != sha256.Size*2 ||
		proof.PolicyIPv6Posture != string(networkjail.DenyViaIP6Tables) &&
			proof.PolicyIPv6Posture != string(networkjail.IPv6KernelDisabled) ||
		proof.NamespaceOwner.PID == 0 ||
		proof.NamespaceOwner.StartTime == 0 ||
		proof.Parser.PID == 0 ||
		proof.Parser.PID == proof.NamespaceOwner.PID ||
		proof.Parser.PPID != proof.NamespaceOwner.PID ||
		proof.Parser.StartTime == 0 ||
		proof.RelayDirectory.Device == 0 ||
		proof.RelayDirectory.Inode == 0 ||
		proof.RelayDirectory.Mode != 0o700 ||
		proof.RelaySocket.Name != "https.sock" ||
		proof.RelaySocket.Device != proof.RelayDirectory.Device ||
		proof.RelaySocket.Inode == 0 ||
		proof.RelaySocket.UID != proof.RelayDirectory.UID ||
		proof.RelaySocket.GID != proof.RelayDirectory.GID ||
		proof.RelaySocket.Mode != 0o600 ||
		proof.Control.Device == 0 ||
		proof.Control.DialerInode == 0 ||
		proof.Control.ParserInode == 0 ||
		proof.Control.DialerInode == proof.Control.ParserInode ||
		proof.AuthorityDirectory.Device == 0 ||
		proof.AuthorityDirectory.Inode == 0 ||
		proof.AuthorityDirectory.Mode != 0o700 ||
		proof.AuthoritySocket.Name != "dial-authority.sock" ||
		proof.AuthoritySocket.Device != proof.AuthorityDirectory.Device ||
		proof.AuthoritySocket.Inode == 0 ||
		proof.AuthoritySocket.UID != proof.AuthorityDirectory.UID ||
		proof.AuthoritySocket.GID != proof.AuthorityDirectory.GID ||
		proof.AuthoritySocket.Mode != 0o600 ||
		proof.AuthorityPeer.PID == 0 ||
		proof.AuthorityPeer.StartTime == 0 ||
		proof.ParserControlFD != networkjail.ParserControlFD ||
		proof.FilterVersion != networkjail.ParserFilterVersion ||
		!proof.FilterTSYNC ||
		proof.AFINETErrno != networkjail.ParserSocketErrno ||
		proof.AFINET6Errno != networkjail.ParserSocketErrno ||
		proof.UnexpectedFDs != 0 ||
		proof.ParserTaskCount == 0 ||
		proof.ParserTasksVerified != proof.ParserTaskCount {
		return errors.New("broker-dialer: readiness fields invalid")
	}
	if decoded, err := hex.DecodeString(proof.PolicyDigest); err != nil ||
		len(decoded) != sha256.Size {
		zero(decoded)
		return errors.New("broker-dialer: readiness digest invalid")
	} else {
		zero(decoded)
	}
	return nil
}

func closeDoHResolvers(resolvers []*networkjail.DoHResolver) {
	for _, resolver := range resolvers {
		if resolver != nil {
			resolver.Close()
		}
	}
}
