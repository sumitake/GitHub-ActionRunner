package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/sumitake/portable-ghar/internal/config"
	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

const (
	maxProductionConfigBytes   = 1 << 20
	maxProductionManifestBytes = 1 << 16
)

func dialProductionAdmin(
	ctx context.Context,
) (controller.LiveAdmin, io.Closer, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, nil, errCommandUnavailable
	}
	configPath := os.Getenv("PORTABLE_GHAR_PRIVATE_OVERLAY")
	if !canonicalAbsolutePath(configPath) {
		return nil, nil, errCommandUnavailable
	}
	configDocument, err := readPinnedRootFile(
		configPath,
		0o600,
		maxProductionConfigBytes,
	)
	if err != nil {
		return nil, nil, errCommandUnavailable
	}
	runtimeConfig, err := config.LoadControllerRuntime(
		bytes.NewReader(configDocument),
	)
	if err != nil {
		return nil, nil, errCommandUnavailable
	}
	overlay, _, ok := runtimeConfig.ControllerPrivateOverlay()
	if !ok ||
		runtime.GOOS != overlay.Target.OS ||
		runtime.GOARCH != overlay.Target.Architecture ||
		uint64(os.Geteuid()) != overlay.Target.ExpectedEUID {
		return nil, nil, errCommandUnavailable
	}
	timeout, err := time.ParseDuration(
		overlay.Controller.OperationTimeout,
	)
	if err != nil {
		return nil, nil, errCommandUnavailable
	}
	client, err := newLocalAdminClient(
		overlay.Paths.AdminSocketPath,
		uint32(overlay.Target.ExpectedEUID),
		timeout,
	)
	if err != nil {
		return nil, nil, errCommandUnavailable
	}
	return client, client, nil
}

func openProductionDisabledObserver(
	ctx context.Context,
	configPath string,
	databasePath string,
	ownership controllerOwnershipLease,
) (controllerProcess, error) {
	if ctx == nil ||
		ctx.Err() != nil ||
		ownership == nil ||
		ownership.Validate() != nil ||
		!canonicalAbsolutePath(configPath) ||
		!canonicalAbsolutePath(databasePath) ||
		configPath == databasePath {
		return nil, errCommandUnavailable
	}
	configDocument, err := readPinnedRootFile(
		configPath,
		0o600,
		maxProductionConfigBytes,
	)
	if err != nil {
		return nil, errCommandUnavailable
	}
	runtimeConfig, err := config.LoadControllerRuntime(
		bytes.NewReader(configDocument),
	)
	if err != nil {
		return nil, errCommandUnavailable
	}
	overlay, _, ok := runtimeConfig.ControllerPrivateOverlay()
	if !ok ||
		runtime.GOOS != overlay.Target.OS ||
		runtime.GOARCH != overlay.Target.Architecture ||
		uint64(os.Geteuid()) != overlay.Target.ExpectedEUID ||
		databasePath != overlay.Paths.DatabasePath {
		return nil, errCommandUnavailable
	}
	manifestDocument, err := readPinnedRootFile(
		overlay.Manifest.Path,
		0o600,
		maxProductionManifestBytes,
	)
	if err != nil {
		return nil, errCommandUnavailable
	}
	manifest, manifestDigest, err := hostruntime.ParseRuntimeManifest(
		manifestDocument,
		maxProductionManifestBytes,
	)
	if err != nil ||
		manifestDigest != overlay.Manifest.Digest ||
		!controllerManifestMatchesOverlay(manifest, overlay) {
		return nil, errCommandUnavailable
	}
	executableDigest, err := currentControllerExecutableDigest()
	if err != nil || executableDigest != manifest.ControllerSHA256 {
		return nil, errCommandUnavailable
	}
	// The policy-only observer is not an acceptable production fallback. Until
	// the approval-gated target identity and concrete local cleanup/fleet
	// authorities can construct disabledControllerProcess, fail before opening
	// or mutating the controller database and before creating either socket.
	return nil, errCommandUnavailable
}

func controllerManifestMatchesOverlay(
	manifest hostruntime.RuntimeManifest,
	overlay hostruntime.PrivateOverlay,
) bool {
	return manifest.EgressMode == overlay.Docker.BrokerNetworkID &&
		manifest.PolicyManifestDigest == overlay.Policy.ManifestDigest &&
		imageReferenceMatchesDigest(
			overlay.Docker.RunnerImage,
			manifest.RunnerImageDigest,
		) &&
		imageReferenceMatchesDigest(
			overlay.Docker.AdapterImage,
			manifest.AdapterImageDigest,
		) &&
		imageReferenceMatchesDigest(
			overlay.Docker.BrokerImage,
			manifest.BrokerImageDigest,
		) &&
		imageReferenceMatchesDigest(
			overlay.Docker.HelperImage,
			manifest.HelperImageDigest,
		) &&
		imageReferenceMatchesDigest(
			overlay.Docker.VerifierImage,
			manifest.VerifierImageDigest,
		)
}

func imageReferenceMatchesDigest(reference string, digest string) bool {
	return strings.HasSuffix(reference, "@"+digest) &&
		len(reference) > len(digest)+1
}

func currentControllerExecutableDigest() (string, error) {
	fd, err := unix.Open(
		"/proc/self/exe",
		unix.O_RDONLY|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), "controller-executable")
	if file == nil {
		_ = unix.Close(fd)
		return "", errCommandUnavailable
	}
	defer file.Close()
	before, err := pinnedRootFileIdentity(fd, 0o500)
	if err != nil || before.size <= 0 || before.size > 1<<30 {
		return "", errCommandUnavailable
	}
	document, err := io.ReadAll(io.LimitReader(file, 1<<30+1))
	if err != nil || len(document) == 0 || len(document) > 1<<30 {
		return "", errCommandUnavailable
	}
	after, err := pinnedRootFileIdentity(fd, 0o500)
	if err != nil || before != after || int64(len(document)) != before.size {
		return "", errCommandUnavailable
	}
	sum := sha256.Sum256(document)
	return hex.EncodeToString(sum[:]), nil
}

func readPinnedRootFile(
	path string,
	mode uint32,
	maxBytes int,
) ([]byte, error) {
	if !canonicalAbsolutePath(path) || maxBytes <= 0 {
		return nil, errCommandUnavailable
	}
	fd, err := unix.Open(
		path,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK,
		0,
	)
	if err != nil {
		return nil, errCommandUnavailable
	}
	file := os.NewFile(uintptr(fd), "private-runtime")
	if file == nil {
		_ = unix.Close(fd)
		return nil, errCommandUnavailable
	}
	defer file.Close()
	before, err := pinnedRootFileIdentity(fd, mode)
	if err != nil || before.size <= 0 || before.size > int64(maxBytes) {
		return nil, errCommandUnavailable
	}
	document, err := io.ReadAll(io.LimitReader(file, int64(maxBytes)+1))
	if err != nil || len(document) == 0 || len(document) > maxBytes {
		return nil, errCommandUnavailable
	}
	after, err := pinnedRootFileIdentity(fd, mode)
	if err != nil || before != after || int64(len(document)) != before.size {
		return nil, errCommandUnavailable
	}
	var pathStat unix.Stat_t
	if err := unix.Lstat(path, &pathStat); err != nil {
		return nil, errCommandUnavailable
	}
	pathIdentity, err := validatePinnedRootStat(&pathStat, mode)
	if err != nil || pathIdentity != before {
		return nil, errCommandUnavailable
	}
	return document, nil
}

type pinnedRootIdentity struct {
	device uint64
	inode  uint64
	mode   uint32
	nlink  uint64
	size   int64
}

func pinnedRootFileIdentity(
	fd int,
	mode uint32,
) (pinnedRootIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return pinnedRootIdentity{}, errCommandUnavailable
	}
	return validatePinnedRootStat(&stat, mode)
}

func validatePinnedRootStat(
	stat *unix.Stat_t,
	mode uint32,
) (pinnedRootIdentity, error) {
	statMode := uint32(stat.Mode)
	if statMode&unix.S_IFMT != unix.S_IFREG ||
		statMode&0o777 != mode ||
		stat.Uid != 0 ||
		uint64(stat.Nlink) != 1 ||
		stat.Ino == 0 ||
		int64(stat.Size) < 0 {
		return pinnedRootIdentity{}, errCommandUnavailable
	}
	return pinnedRootIdentity{
		device: uint64(stat.Dev),
		inode:  stat.Ino,
		mode:   statMode,
		nlink:  uint64(stat.Nlink),
		size:   int64(stat.Size),
	}, nil
}

func canonicalAbsolutePath(path string) bool {
	return filepath.IsAbs(path) &&
		filepath.Clean(path) == path &&
		!strings.ContainsRune(path, 0)
}

var _ controllerProcess = (*disabledControllerProcess)(nil)
