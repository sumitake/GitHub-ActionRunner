package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sumitake/portable-ghar/internal/buildinfo"
	"github.com/sumitake/portable-ghar/internal/imageverify"
	"github.com/sumitake/portable-ghar/internal/runtimeenv"
	"golang.org/x/sys/unix"
)

const (
	defaultRunnerRoot      = "/runner"
	defaultDiagnosticsPath = "/runner/_diag"
	defaultGateDirectory   = "/runner/.portable-ghar"
	defaultGateSocket      = "/runner/.portable-ghar/gate.sock"
	defaultRunnerWork      = "/runner/_work"
	defaultRuntimeLockPath = "/opt/portable-ghar/runner.runtime-lock.json"
	defaultTreeLockPath    = "/opt/portable-ghar/runner.tree-lock"
	defaultSeedCacheRoot   = "/opt/portable-ghar/seed-cache"
	defaultSeedManifest    = "/opt/portable-ghar/seed-cache.manifest.json"
	defaultSeedTreeLock    = "/opt/portable-ghar/seed-cache.tree-lock"
	defaultSeedReady       = "/opt/portable-ghar/seed-cache.READY"
)

type listenerExecutor func(*os.File, string, []string, []string) error

type gateRuntime struct {
	runnerRoot         string
	diagnosticsPath    string
	workRoot           string
	socketDirectory    string
	socketPath         string
	runtimeLockPath    string
	treeLockPath       string
	seedCacheRoot      string
	seedManifest       string
	seedTreeLock       string
	seedReady          string
	seedUID            uint32
	seedGID            uint32
	ioTimeout          time.Duration
	namespace          func() ([]byte, error)
	execListener       listenerExecutor
	verifyImage        func() error
	verifyImageOverlay func() error
	observeConformance func() (runnerConformanceWire, error)
}

func defaultGateRuntime() gateRuntime {
	return gateRuntime{
		runnerRoot:         defaultRunnerRoot,
		diagnosticsPath:    defaultDiagnosticsPath,
		workRoot:           defaultRunnerWork,
		socketDirectory:    defaultGateDirectory,
		socketPath:         defaultGateSocket,
		runtimeLockPath:    defaultRuntimeLockPath,
		treeLockPath:       defaultTreeLockPath,
		seedCacheRoot:      defaultSeedCacheRoot,
		seedManifest:       defaultSeedManifest,
		seedTreeLock:       defaultSeedTreeLock,
		seedReady:          defaultSeedReady,
		seedUID:            0,
		seedGID:            0,
		ioTimeout:          5 * time.Second,
		namespace:          currentNetworkNamespace,
		execListener:       execListenerProcess,
		verifyImage:        imageverify.VerifyInstalledRunnerImage,
		verifyImageOverlay: imageverify.VerifyInstalledRunnerImageWithRuntimeOverlay,
		observeConformance: defaultRunnerConformance,
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, runtime gateRuntime) int {
	if len(args) != 1 || stdout == nil || stderr == nil {
		return gateUnavailable(stderr, 2)
	}
	if args[0] == "verify-image" || args[0] == "verify-image-overlay" {
		verifier := runtime.verifyImage
		if args[0] == "verify-image-overlay" {
			verifier = runtime.verifyImageOverlay
		}
		if verifier == nil {
			return gateUnavailable(stderr, 1)
		}
		if err := requireEmptyInput(stdin); err != nil {
			return gateUnavailable(stderr, 1)
		}
		if err := verifier(); err != nil {
			return gateUnavailable(stderr, 1)
		}
		version := strings.TrimPrefix(buildinfo.Pins().UpstreamRunner.Version, "v")
		if version == "" {
			return gateUnavailable(stderr, 1)
		}
		if _, err := fmt.Fprintln(stdout, version); err != nil {
			return gateUnavailable(stderr, 1)
		}
		return 0
	}
	if args[0] == "conformance-observe" {
		if requireEmptyInput(stdin) != nil ||
			runtime.observeConformance == nil {
			return gateUnavailable(stderr, 1)
		}
		wire, err := runtime.observeConformance()
		if err != nil ||
			!validRunnerConformanceWire(wire) ||
			writeRunnerConformance(stdout, wire) != nil {
			return gateUnavailable(stderr, 1)
		}
		return 0
	}
	if runtime.ioTimeout <= 0 || !filepath.IsAbs(runtime.socketPath) {
		return gateUnavailable(stderr, 2)
	}
	if args[0] == "hold" {
		if err := holdGate(runtime); err != nil {
			return gateUnavailable(stderr, 1)
		}
		return 0
	}
	var operation gateOperation
	switch args[0] {
	case "hydrate-seeds":
		operation = opHydrateSeeds
	case "netns-id":
		operation = opNetNSID
		if err := requireEmptyInput(stdin); err != nil {
			return gateUnavailable(stderr, 1)
		}
		stdin = nil
	case "arm":
		operation = opArm
	case "release":
		operation = opRelease
	default:
		return gateUnavailable(stderr, 2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), runtime.ioTimeout)
	defer cancel()
	if err := forwardGate(ctx, runtime.socketPath, operation, stdin, stdout, runtime.ioTimeout); err != nil {
		return gateUnavailable(stderr, 1)
	}
	return 0
}

func gateUnavailable(stderr io.Writer, code int) int {
	if stderr != nil {
		_, _ = fmt.Fprintln(stderr, "portable-ghar-runner-gate: unavailable")
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
		return errors.New("runner-gate: input-free operation received input")
	}
	return nil
}

func holdGate(runtime gateRuntime) error {
	if runtime.namespace == nil || runtime.execListener == nil ||
		runtime.verifyImageOverlay == nil ||
		!canonicalRuntimePath(runtime.runnerRoot) ||
		!canonicalRuntimePath(runtime.diagnosticsPath) ||
		!canonicalRuntimePath(runtime.workRoot) ||
		!canonicalRuntimePath(runtime.socketDirectory) ||
		!canonicalRuntimePath(runtime.socketPath) ||
		!canonicalRuntimePath(runtime.runtimeLockPath) ||
		!canonicalRuntimePath(runtime.treeLockPath) ||
		!canonicalRuntimePath(runtime.seedCacheRoot) ||
		!canonicalRuntimePath(runtime.seedManifest) ||
		!canonicalRuntimePath(runtime.seedTreeLock) ||
		!canonicalRuntimePath(runtime.seedReady) ||
		runtime.socketDirectory != filepath.Dir(runtime.socketPath) ||
		runtime.diagnosticsPath != filepath.Join(runtime.runnerRoot, "_diag") ||
		runtime.socketDirectory != filepath.Join(runtime.runnerRoot, ".portable-ghar") ||
		runtime.workRoot != filepath.Join(runtime.runnerRoot, "_work") {
		return errors.New("runner-gate: runtime paths invalid")
	}
	if err := runtime.verifyImageOverlay(); err != nil {
		return err
	}
	listenerIdentity, err := loadGateRuntimeLock(runtime.runtimeLockPath, runtime.treeLockPath)
	if err != nil {
		return err
	}
	catalog, err := loadSeedCatalog(
		runtime.seedCacheRoot,
		runtime.seedManifest,
		runtime.seedTreeLock,
		runtime.seedReady,
		runtime.seedUID,
		runtime.seedGID,
	)
	if err != nil {
		return err
	}
	diagnosticsIdentity, err := prepareDiagnosticsDirectory(
		runtime.runnerRoot,
		runtime.diagnosticsPath,
	)
	if err != nil {
		return err
	}
	if err := prepareGateDirectory(runtime.runnerRoot, runtime.socketDirectory); err != nil {
		return err
	}
	ownedDirectory := true
	defer func() {
		if ownedDirectory {
			_ = os.Remove(runtime.socketDirectory)
		}
	}()
	listener, socketIdentity, err := listenGateSocket(runtime.socketPath)
	if err != nil {
		return err
	}
	machine := newGateMachine(
		func(ids []string) error { return catalog.hydrate(runtime.workRoot, ids) },
		runtime.namespace,
		func(jit []byte) error {
			return executeVerifiedListener(
				listenerIdentity,
				diagnosticsIdentity,
				jit,
				runtime.execListener,
			)
		},
	)
	err = serveGateListener(listener, socketIdentity, machine, runtime.ioTimeout)
	if err == nil {
		// A successful exec never returns. Treat any returning executor as a
		// terminal failure rather than leaving a reusable gate behind.
		return errors.New("runner-gate: listener execution returned")
	}
	return err
}

func canonicalRuntimePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && strings.IndexByte(path, 0) < 0
}

type runtimePathIdentity struct {
	device uint64
	inode  uint64
	uid    uint32
	gid    uint32
	mode   uint32
}

type diagnosticsDirectoryIdentity struct {
	runnerRoot      string
	diagnosticsPath string
	root            runtimePathIdentity
	diagnostics     runtimePathIdentity
}

func prepareDiagnosticsDirectory(
	runnerRoot string,
	diagnosticsPath string,
) (diagnosticsDirectoryIdentity, error) {
	if !canonicalRuntimePath(runnerRoot) ||
		diagnosticsPath != filepath.Join(runnerRoot, "_diag") {
		return diagnosticsDirectoryIdentity{}, errors.New(
			"runner-gate: diagnostics path invalid",
		)
	}
	rootFD, rootStat, err := openRuntimeRunnerRoot(runnerRoot)
	if err != nil {
		return diagnosticsDirectoryIdentity{}, err
	}
	defer unix.Close(rootFD)

	var diagnosticsStat unix.Stat_t
	created := false
	err = unix.Fstatat(
		rootFD,
		"_diag",
		&diagnosticsStat,
		unix.AT_SYMLINK_NOFOLLOW,
	)
	if errors.Is(err, unix.ENOENT) {
		oldMask := unix.Umask(0o077)
		createErr := unix.Mkdirat(rootFD, "_diag", 0o700)
		unix.Umask(oldMask)
		if createErr != nil {
			return diagnosticsDirectoryIdentity{}, errors.New(
				"runner-gate: diagnostics directory create failed",
			)
		}
		created = true
		err = unix.Fstatat(
			rootFD,
			"_diag",
			&diagnosticsStat,
			unix.AT_SYMLINK_NOFOLLOW,
		)
	}
	if err != nil ||
		uint32(diagnosticsStat.Mode)&unix.S_IFMT != unix.S_IFDIR ||
		uint32(diagnosticsStat.Mode)&0o777 != 0o700 ||
		diagnosticsStat.Uid != uint32(os.Geteuid()) ||
		diagnosticsStat.Gid != uint32(os.Getegid()) ||
		uint64(diagnosticsStat.Dev) != uint64(rootStat.Dev) {
		if created {
			_ = unix.Unlinkat(rootFD, "_diag", unix.AT_REMOVEDIR)
		}
		return diagnosticsDirectoryIdentity{}, errors.New(
			"runner-gate: diagnostics directory identity invalid",
		)
	}
	var rootAfter unix.Stat_t
	var pathRoot unix.Stat_t
	if unix.Fstat(rootFD, &rootAfter) != nil ||
		unix.Lstat(runnerRoot, &pathRoot) != nil ||
		!sameRuntimePathIdentity(
			runtimeIdentityFromStat(rootStat),
			runtimeIdentityFromStat(rootAfter),
		) ||
		!sameRuntimePathIdentity(
			runtimeIdentityFromStat(rootStat),
			runtimeIdentityFromStat(pathRoot),
		) {
		if created {
			_ = unix.Unlinkat(rootFD, "_diag", unix.AT_REMOVEDIR)
		}
		return diagnosticsDirectoryIdentity{}, errors.New(
			"runner-gate: runner root changed during diagnostics preparation",
		)
	}
	return diagnosticsDirectoryIdentity{
		runnerRoot:      runnerRoot,
		diagnosticsPath: diagnosticsPath,
		root:            runtimeIdentityFromStat(rootStat),
		diagnostics:     runtimeIdentityFromStat(diagnosticsStat),
	}, nil
}

func revalidateDiagnosticsDirectory(
	want diagnosticsDirectoryIdentity,
) error {
	if !canonicalRuntimePath(want.runnerRoot) ||
		want.diagnosticsPath != filepath.Join(want.runnerRoot, "_diag") {
		return errors.New("runner-gate: diagnostics identity invalid")
	}
	rootFD, rootStat, err := openRuntimeRunnerRoot(want.runnerRoot)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	if !sameRuntimePathIdentity(
		want.root,
		runtimeIdentityFromStat(rootStat),
	) {
		return errors.New("runner-gate: runner root identity changed")
	}
	var diagnosticsStat unix.Stat_t
	if unix.Fstatat(
		rootFD,
		"_diag",
		&diagnosticsStat,
		unix.AT_SYMLINK_NOFOLLOW,
	) != nil ||
		!sameRuntimePathIdentity(
			want.diagnostics,
			runtimeIdentityFromStat(diagnosticsStat),
		) {
		return errors.New("runner-gate: diagnostics directory identity changed")
	}
	return nil
}

func openRuntimeRunnerRoot(
	runnerRoot string,
) (int, unix.Stat_t, error) {
	var empty unix.Stat_t
	resolved, err := filepath.EvalSymlinks(runnerRoot)
	if err != nil || resolved != runnerRoot {
		return -1, empty, errors.New("runner-gate: runner root indirect")
	}
	rootFD, err := unix.Open(
		runnerRoot,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return -1, empty, errors.New("runner-gate: runner root open failed")
	}
	var stat unix.Stat_t
	if unix.Fstat(rootFD, &stat) != nil ||
		uint32(stat.Mode)&unix.S_IFMT != unix.S_IFDIR ||
		uint32(stat.Mode)&0o777 != 0o700 ||
		stat.Uid != uint32(os.Geteuid()) ||
		stat.Gid != uint32(os.Getegid()) {
		_ = unix.Close(rootFD)
		return -1, empty, errors.New(
			"runner-gate: runner root identity invalid",
		)
	}
	return rootFD, stat, nil
}

func runtimeIdentityFromStat(stat unix.Stat_t) runtimePathIdentity {
	return runtimePathIdentity{
		device: uint64(stat.Dev),
		inode:  stat.Ino,
		uid:    stat.Uid,
		gid:    stat.Gid,
		mode:   uint32(stat.Mode),
	}
}

func sameRuntimePathIdentity(
	left runtimePathIdentity,
	right runtimePathIdentity,
) bool {
	return left.device == right.device &&
		left.inode == right.inode &&
		left.uid == right.uid &&
		left.gid == right.gid &&
		left.mode == right.mode
}

func prepareGateDirectory(runnerRoot, gateDirectory string) error {
	resolved, err := filepath.EvalSymlinks(runnerRoot)
	if err != nil || resolved != runnerRoot {
		return errors.New("runner-gate: runner root indirect")
	}
	var rootStat unix.Stat_t
	if unix.Lstat(runnerRoot, &rootStat) != nil ||
		uint32(rootStat.Mode)&unix.S_IFMT != unix.S_IFDIR ||
		uint32(rootStat.Mode)&0o777 != 0o700 ||
		rootStat.Uid != uint32(os.Geteuid()) {
		return errors.New("runner-gate: runner root identity invalid")
	}
	var existing unix.Stat_t
	if err := unix.Lstat(gateDirectory, &existing); err == nil || !errors.Is(err, unix.ENOENT) {
		return errors.New("runner-gate: gate restart or replacement detected")
	}
	oldMask := unix.Umask(0o077)
	err = os.Mkdir(gateDirectory, 0o700)
	unix.Umask(oldMask)
	if err != nil {
		return errors.New("runner-gate: gate directory create failed")
	}
	var directoryStat unix.Stat_t
	if unix.Lstat(gateDirectory, &directoryStat) != nil ||
		uint32(directoryStat.Mode)&unix.S_IFMT != unix.S_IFDIR ||
		uint32(directoryStat.Mode)&0o777 != 0o700 ||
		directoryStat.Uid != uint32(os.Geteuid()) ||
		uint64(directoryStat.Dev) != uint64(rootStat.Dev) {
		_ = os.Remove(gateDirectory)
		return errors.New("runner-gate: gate directory identity invalid")
	}
	return nil
}

func executeVerifiedListener(
	want listenerIdentity,
	diagnostics diagnosticsDirectoryIdentity,
	jit []byte,
	executor listenerExecutor,
) error {
	defer zero(jit)
	if executor == nil || len(jit) == 0 || len(jit) > maxJITLength || strings.IndexByte(string(jit), 0) >= 0 {
		return errors.New("runner-gate: listener execution inputs invalid")
	}
	listener, err := verifyListener(want)
	if err != nil {
		return err
	}
	defer listener.Close()
	if _, err := listener.Seek(0, io.SeekStart); err != nil {
		return errors.New("runner-gate: listener descriptor seek failed")
	}
	descriptorPath := "/proc/self/fd/" + strconv.FormatUint(uint64(listener.Fd()), 10)
	argv := []string{want.Path, "run"}
	env := runtimeenv.Listener(string(jit))
	if err := revalidateDiagnosticsDirectory(diagnostics); err != nil {
		for index := range env {
			env[index] = ""
		}
		return err
	}
	err = executor(listener, descriptorPath, argv, env)
	for index := range env {
		env[index] = ""
	}
	if err == nil {
		return errors.New("runner-gate: listener executor returned")
	}
	return errors.New("runner-gate: listener exec failed")
}
