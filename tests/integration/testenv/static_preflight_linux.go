//go:build integration && linux

package testenv

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
	"golang.org/x/sys/unix"
)

const (
	maxStaticManifestBytes = 64 << 10
	maxStaticOverlayBytes  = 1 << 20
	maxStaticPolicyBytes   = 128 << 10
	maxStaticCABundleBytes = 1 << 20
	maxStaticSeccompBytes  = 1 << 20
	maxStaticPlanBytes     = 4 << 20
)

type linuxStaticPreflight struct {
	Result   staticPreflightResult
	Manifest hostruntime.RuntimeManifest
	Overlay  hostruntime.PrivateOverlay
	Graph    networkjail.DecisionGraph
	Policy   hostruntime.PolicyArtifact
	Probes   probeMembershipSeal
	Session  *preflightSession
	Seccomp  hostruntime.SeccompBinding
}

func runLinuxStaticPreflight(
	ctx context.Context,
	parsed ParsedConformanceInput,
) (linuxStaticPreflight, error) {
	if ctx == nil || !validateParsedInputEnvelope(parsed) ||
		runtime.GOOS != "linux" {
		return linuxStaticPreflight{}, ErrStaticPreflight
	}
	input := parsed.Input
	owner := input.Target.ExpectedEUID

	manifestDocument, err := readPinnedStaticArtifact(
		input.Runtime.RuntimeManifestPath,
		owner,
		maxStaticManifestBytes,
	)
	if err != nil {
		return linuxStaticPreflight{}, ErrStaticPreflight
	}
	defer zeroLeaseBytes(manifestDocument)
	manifest, manifestDigest, err := hostruntime.ParseRuntimeManifest(
		manifestDocument,
		maxStaticManifestBytes,
	)
	if err != nil {
		return linuxStaticPreflight{}, ErrStaticPreflight
	}

	overlayDocument, err := readPinnedStaticArtifact(
		input.Runtime.PrivateOverlayPath,
		owner,
		maxStaticOverlayBytes,
	)
	if err != nil {
		return linuxStaticPreflight{}, ErrStaticPreflight
	}
	defer zeroLeaseBytes(overlayDocument)
	overlay, overlayDigest, err := hostruntime.ParsePrivateOverlay(
		overlayDocument,
		maxStaticOverlayBytes,
	)
	if err != nil {
		return linuxStaticPreflight{}, ErrStaticPreflight
	}

	policyDocument, err := readPinnedStaticArtifact(
		input.Runtime.PolicyPath,
		owner,
		maxStaticPolicyBytes,
	)
	if err != nil {
		return linuxStaticPreflight{}, ErrStaticPreflight
	}
	defer zeroLeaseBytes(policyDocument)
	policyDocumentDigest := rawStaticDigest(policyDocument)
	graph, err := networkjail.DecodeDecisionGraph(
		bytes.NewReader(policyDocument),
	)
	if err != nil {
		return linuxStaticPreflight{}, ErrStaticPreflight
	}
	policy, err := networkjail.CompilePolicyArtifact(graph)
	if err != nil {
		return linuxStaticPreflight{}, ErrStaticPreflight
	}
	probes, err := newProbeMembershipSeal(input.Sentinels, graph)
	if err != nil {
		return linuxStaticPreflight{}, ErrStaticPreflight
	}

	caDocument, err := readPinnedStaticArtifact(
		input.Runtime.CAPath,
		owner,
		maxStaticCABundleBytes,
	)
	if err != nil || !validateStaticTrustBundle(caDocument) {
		zeroLeaseBytes(caDocument)
		return linuxStaticPreflight{}, ErrStaticPreflight
	}
	caDigest := rawStaticDigest(caDocument)
	zeroLeaseBytes(caDocument)

	seccompDocument, err := readPinnedStaticArtifact(
		input.Runtime.SeccompPath,
		owner,
		maxStaticSeccompBytes,
	)
	if err != nil {
		return linuxStaticPreflight{}, ErrStaticPreflight
	}
	seccompDigest, err := hostruntime.ValidateSeccompProfile(
		seccompDocument,
		maxStaticSeccompBytes,
	)
	zeroLeaseBytes(seccompDocument)
	if err != nil {
		return linuxStaticPreflight{}, ErrStaticPreflight
	}

	planPath, err := currentConformancePlanPath()
	if err != nil {
		return linuxStaticPreflight{}, ErrStaticPreflight
	}
	planDocument, err := readPinnedStaticArtifact(
		planPath,
		owner,
		maxStaticPlanBytes,
	)
	if err != nil {
		return linuxStaticPreflight{}, ErrStaticPreflight
	}
	planDigest := rawStaticDigest(planDocument)
	zeroLeaseBytes(planDocument)

	sourceCommit, err := currentSourceCommit()
	if err != nil {
		return linuxStaticPreflight{}, ErrStaticPreflight
	}
	fixtureRootDigest, err := observeLinuxFixtureRoot(input.Fixture)
	if err != nil {
		return linuxStaticPreflight{}, ErrStaticPreflight
	}
	maximumBytes := input.Limits.MaximumEvidenceBytes
	commandRunner, err := commandRunnerFromConformanceLimits(input.Limits)
	if err != nil {
		return linuxStaticPreflight{}, ErrStaticPreflight
	}
	session, err := newPreflightSession(closedCommandConfig{
		DockerPath:   overlay.Commands.DockerBinary,
		FixtureRoot:  input.Fixture.Root,
		MaximumBytes: maximumBytes,
		Images:       expectedStaticImageBindings(input),
	}, commandRunner)
	if err != nil {
		return linuxStaticPreflight{}, ErrStaticPreflight
	}
	hostDigest, err := observeExecutionHostIdentity(
		ctx,
		executionHostObservationConfig{
			OperatingSystem:       input.Target.OperatingSystem,
			Architecture:          input.Target.Architecture,
			EUID:                  input.Target.ExpectedEUID,
			FixtureParentPath:     filepath.Dir(input.Fixture.Root),
			FixtureParentDevice:   input.Fixture.ParentDevice,
			FixtureParentInode:    input.Fixture.ParentInode,
			DockerBinaryPath:      overlay.Commands.DockerBinary,
			ExpectedTargetDigest:  input.Target.HostIdentityDigest,
			ExpectedControlDigest: input.Target.ControlHostIdentityDigest,
		},
		unixExecutionHostStatSource{},
		session,
	)
	if err != nil {
		return linuxStaticPreflight{}, ErrStaticPreflight
	}
	dockerInfo, err := session.InspectDockerInfo(ctx)
	if err != nil {
		return linuxStaticPreflight{}, ErrStaticPreflight
	}
	images, err := session.InspectImages(ctx)
	if err != nil {
		return linuxStaticPreflight{}, ErrStaticPreflight
	}
	hostCapabilities, err := observeLinuxHostCapabilities()
	if err != nil {
		return linuxStaticPreflight{}, ErrStaticPreflight
	}

	observation := staticPreflightObservation{
		ManifestDigest:          manifestDigest,
		ManifestBuildID:         manifest.BuildID,
		ManifestFleetGeneration: manifest.FleetGeneration,
		ManifestTrustDigest:     manifest.TrustBundleDigest,
		ManifestSeccompDigest:   manifest.SeccompProfileDigest,
		ManifestPolicyDigest:    manifest.PolicyManifestDigest,
		ManifestImageDigests: []string{
			manifest.RunnerImageDigest,
			manifest.AdapterImageDigest,
			manifest.BrokerImageDigest,
			manifest.HelperImageDigest,
			manifest.VerifierImageDigest,
		},
		OverlayDigest:                overlayDigest,
		OverlayManifestPath:          overlay.Manifest.Path,
		OverlayManifestDigest:        overlay.Manifest.Digest,
		OverlayPolicyPath:            overlay.Paths.PolicyPath,
		OverlaySeccompRoot:           overlay.Paths.SeccompRoot,
		OverlayDockerPath:            overlay.Commands.DockerBinary,
		OverlayBrokerRoot:            overlay.Paths.BrokerRoot,
		OverlayBrokerNetwork:         overlay.Docker.BrokerNetworkID,
		OverlayTargetOS:              overlay.Target.OS,
		OverlayTargetArchitecture:    overlay.Target.Architecture,
		OverlayExpectedEUID:          uint32(overlay.Target.ExpectedEUID),
		OverlayProfileID:             overlay.Target.ProfileID,
		OverlayHostIdentityDigest:    overlay.Target.HostIdentityDigest,
		OverlayControlIdentityDigest: overlay.Target.ControlHostIdentityDigest,
		OverlayPolicyManifestDigest:  overlay.Policy.ManifestDigest,
		OverlayPolicyGraphDigest:     overlay.Policy.CompiledGraphDigest,
		OverlayProfileEvidenceDigest: overlay.Profile.ConformanceEvidenceDigest,
		OverlayNetworkEvidenceDigest: overlay.Profile.NetworkEvidenceDigest,
		OverlayImageReferences: []string{
			overlay.Docker.RunnerImage,
			overlay.Docker.AdapterImage,
			overlay.Docker.BrokerImage,
			overlay.Docker.HelperImage,
			overlay.Docker.VerifierImage,
		},
		PolicyDocumentDigest: policyDocumentDigest,
		PolicyGraphDigest:    graph.Digest().String(),
		CADigest:             caDigest,
		SeccompDigest:        seccompDigest,
		PlanDigest:           planDigest,
		SourceCommit:         sourceCommit,
		FixtureRootDigest:    fixtureRootDigest,
		HostFacts: FixtureHostFacts{
			OperatingSystem:           runtime.GOOS,
			Architecture:              runtime.GOARCH,
			EUID:                      uint32(os.Geteuid()),
			HostIdentityDigest:        hostDigest,
			ControlHostIdentityDigest: input.Target.ControlHostIdentityDigest,
		},
		DockerInfo:               dockerInfo,
		HostCapabilitiesObserved: true,
		HostCapabilities:         hostCapabilities,
		Images:                   images,
	}
	result, err := validateStaticPreflight(parsed, observation)
	if err != nil {
		return linuxStaticPreflight{}, err
	}
	return linuxStaticPreflight{
		Result:   result,
		Manifest: manifest,
		Overlay:  overlay,
		Graph:    graph,
		Policy:   policy,
		Probes:   probes,
		Session:  session,
		Seccomp: hostruntime.SeccompBinding{
			Path:   input.Runtime.SeccompPath,
			SHA256: seccompDigest,
		},
	}, nil
}

func observeLinuxHostCapabilities() (
	hostruntime.CapabilitySets,
	error,
) {
	fd, err := unix.Open(
		"/proc/self/status",
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return hostruntime.CapabilitySets{}, ErrStaticPreflight
	}
	file := os.NewFile(uintptr(fd), "proc-self-status")
	if file == nil {
		_ = unix.Close(fd)
		return hostruntime.CapabilitySets{}, ErrStaticPreflight
	}
	defer file.Close()
	document, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil || len(document) > 64<<10 {
		return hostruntime.CapabilitySets{}, ErrStaticPreflight
	}
	defer zeroLeaseBytes(document)
	return parseLinuxCapabilitySets(document)
}

type staticArtifactIdentity struct {
	device uint64
	inode  uint64
	size   int64
	mode   uint32
	uid    uint32
	nlink  uint64
}

func readPinnedStaticArtifact(
	path string,
	expectedOwner uint32,
	maxBytes int64,
) ([]byte, error) {
	if !validAbsolutePath(path) ||
		maxBytes <= 0 ||
		maxBytes == math.MaxInt64 {
		return nil, ErrStaticPreflight
	}
	rootFD, err := unix.Open(
		string(filepath.Separator),
		unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, ErrStaticPreflight
	}
	defer unix.Close(rootFD)
	relative := strings.TrimPrefix(path, string(filepath.Separator))
	fd, err := unix.Openat2(rootFD, relative, &unix.OpenHow{
		Flags: uint64(
			unix.O_RDONLY |
				unix.O_CLOEXEC |
				unix.O_NONBLOCK,
		),
		Resolve: uint64(
			unix.RESOLVE_BENEATH |
				unix.RESOLVE_NO_MAGICLINKS |
				unix.RESOLVE_NO_SYMLINKS,
		),
	})
	if err != nil {
		return nil, ErrStaticPreflight
	}
	file := os.NewFile(uintptr(fd), "static-preflight-artifact")
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrStaticPreflight
	}
	defer file.Close()
	before, err := staticArtifactIdentityFromFD(fd)
	if err != nil ||
		!validStaticArtifactIdentity(before, expectedOwner, maxBytes) {
		return nil, ErrStaticPreflight
	}
	document, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil ||
		int64(len(document)) != before.size ||
		int64(len(document)) > maxBytes {
		zeroLeaseBytes(document)
		return nil, ErrStaticPreflight
	}
	after, err := staticArtifactIdentityFromFD(fd)
	if err != nil || after != before {
		zeroLeaseBytes(document)
		return nil, ErrStaticPreflight
	}
	pathIdentity, err := staticArtifactIdentityFromPath(path)
	if err != nil || pathIdentity != before {
		zeroLeaseBytes(document)
		return nil, ErrStaticPreflight
	}
	return document, nil
}

func staticArtifactIdentityFromFD(
	fd int,
) (staticArtifactIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return staticArtifactIdentity{}, err
	}
	return normalizeStaticArtifactIdentity(stat), nil
}

func staticArtifactIdentityFromPath(
	path string,
) (staticArtifactIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		return staticArtifactIdentity{}, err
	}
	return normalizeStaticArtifactIdentity(stat), nil
}

func normalizeStaticArtifactIdentity(
	stat unix.Stat_t,
) staticArtifactIdentity {
	return staticArtifactIdentity{
		device: uint64(stat.Dev),
		inode:  uint64(stat.Ino),
		size:   stat.Size,
		mode:   uint32(stat.Mode),
		uid:    stat.Uid,
		nlink:  uint64(stat.Nlink),
	}
}

func validStaticArtifactIdentity(
	identity staticArtifactIdentity,
	expectedOwner uint32,
	maxBytes int64,
) bool {
	return identity.device != 0 &&
		identity.inode != 0 &&
		identity.mode&unix.S_IFMT == unix.S_IFREG &&
		identity.mode&0o022 == 0 &&
		identity.uid == expectedOwner &&
		identity.nlink == 1 &&
		identity.size > 0 &&
		identity.size <= maxBytes
}

func rawStaticDigest(document []byte) string {
	sum := sha256.Sum256(document)
	return hex.EncodeToString(sum[:])
}

func validateStaticTrustBundle(document []byte) bool {
	if len(document) == 0 {
		return false
	}
	remaining := document
	count := 0
	pool := x509.NewCertPool()
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil ||
			block.Type != "CERTIFICATE" ||
			len(block.Headers) != 0 ||
			len(block.Bytes) == 0 {
			return false
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return false
		}
		count++
		remaining = rest
	}
	return count > 0 && pool.AppendCertsFromPEM(document)
}

func currentConformancePlanPath() (string, error) {
	_, source, _, ok := runtime.Caller(0)
	if !ok || !filepath.IsAbs(source) {
		return "", ErrStaticPreflight
	}
	root := filepath.Clean(
		filepath.Join(filepath.Dir(source), "..", "..", ".."),
	)
	path := filepath.Join(
		root,
		"docs",
		"superpowers",
		"plans",
		"2026-07-29-task11-implementation.md",
	)
	if !validAbsolutePath(path) {
		return "", ErrStaticPreflight
	}
	return path, nil
}

func currentSourceCommit() (string, error) {
	info, ok := debug.ReadBuildInfo()
	if !ok || info == nil {
		return "", ErrStaticPreflight
	}
	var revision string
	var modified string
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			if revision != "" {
				return "", ErrStaticPreflight
			}
			revision = setting.Value
		case "vcs.modified":
			if modified != "" {
				return "", ErrStaticPreflight
			}
			modified = setting.Value
		}
	}
	if !isLowerHex(revision, 40) ||
		modified != "false" {
		return "", ErrStaticPreflight
	}
	return revision, nil
}
