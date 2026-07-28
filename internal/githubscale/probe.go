package githubscale

import (
	"context"
	"fmt"
	"runtime/debug"

	"github.com/sumitake/portable-ghar/internal/buildinfo"
)

// Probe runs the startup compatibility check for this package's pinned
// actions/scaleset dependency. It reads the ACTUALLY LINKED module version
// out of the running binary's own build info (runtime/debug.ReadBuildInfo)
// and compares it against the exact version this adapter was written
// against (internal/buildinfo.Pins().Scaleset). It depends on no Fleet, no
// live GitHub API call, and no upstream scaleset type -- only on build
// metadata Go itself stamps into every binary built in module mode.
//
// A non-Compatible CompatibilityReport (or a non-nil error) must be
// treated as a hard startup failure by every caller: this package's
// translation logic is verified against the pinned v0.4.0 wire shapes
// only, and has no guarantee of correctness against any other version.
func Probe(ctx context.Context) (CompatibilityReport, error) {
	select {
	case <-ctx.Done():
		return CompatibilityReport{}, fmt.Errorf("githubscale: probe: %w", ctx.Err())
	default:
	}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		pin := buildinfo.Pins().Scaleset
		report := CompatibilityReport{
			ModulePath:      pin.Path,
			ExpectedVersion: pin.Version,
			Commit:          pin.Commit,
			License:         pin.License,
			Reason:          "runtime/debug.ReadBuildInfo reported no build info",
		}
		return report, fmt.Errorf("githubscale: probe: %w", ErrBuildInfoUnavailable)
	}

	linked, found := findLinkedScalesetModule(info)
	return evaluateCompatibility(buildinfo.Pins().Scaleset, linked, found)
}

type linkedScalesetModule struct {
	Version string
	Sum     string

	Replaced           bool
	ReplacementPath    string
	ReplacementVersion string
	ReplacementSum     string
}

// findLinkedScalesetModule retains every provenance field required by the
// compatibility decision. In particular, a requested version is not enough:
// debug.Module.Replace and the linked module sum are both load-bearing.
func findLinkedScalesetModule(info *debug.BuildInfo) (linkedScalesetModule, bool) {
	const modulePath = "github.com/actions/scaleset"

	if info.Main.Path == modulePath {
		return linkedModuleDetails(&info.Main), true
	}
	for _, dep := range info.Deps {
		if dep != nil && dep.Path == modulePath {
			return linkedModuleDetails(dep), true
		}
	}
	return linkedScalesetModule{}, false
}

func linkedModuleDetails(module *debug.Module) linkedScalesetModule {
	linked := linkedScalesetModule{
		Version: module.Version,
		Sum:     module.Sum,
	}
	if module.Replace != nil {
		linked.Replaced = true
		linked.ReplacementPath = module.Replace.Path
		linked.ReplacementVersion = module.Replace.Version
		linked.ReplacementSum = module.Replace.Sum
	}
	return linked
}

// evaluateCompatibility is the pure comparison at the heart of Probe,
// split out so it is unit-testable against synthetic "wrong version"
// input without needing a second real build pinned to a different
// scaleset version (see adapter_contract_test.go's
// TestProbeRejectsIncompatibleLinkedVersion).
func evaluateCompatibility(pin buildinfo.ModulePin, linked linkedScalesetModule, found bool) (CompatibilityReport, error) {
	report := CompatibilityReport{
		ModulePath:         pin.Path,
		ExpectedVersion:    pin.Version,
		LinkedVersion:      linked.Version,
		ExpectedSum:        pin.Sum,
		LinkedSum:          linked.Sum,
		Replaced:           linked.Replaced,
		ReplacementPath:    linked.ReplacementPath,
		ReplacementVersion: linked.ReplacementVersion,
		ReplacementSum:     linked.ReplacementSum,
		Commit:             pin.Commit,
		License:            pin.License,
	}

	if !found {
		report.Reason = fmt.Sprintf("%s is not linked into this binary at all", pin.Path)
		return report, fmt.Errorf("githubscale: probe: %w: %s", ErrIncompatibleModuleVersion, report.Reason)
	}
	if linked.Replaced {
		report.Reason = fmt.Sprintf("linked %s uses a module replacement", pin.Path)
		return report, fmt.Errorf("githubscale: probe: %w: %s", ErrIncompatibleModuleVersion, report.Reason)
	}
	if linked.Version != pin.Version {
		report.Reason = fmt.Sprintf("linked %s@%s, this adapter is pinned to @%s", pin.Path, linked.Version, pin.Version)
		return report, fmt.Errorf("githubscale: probe: %w: %s", ErrIncompatibleModuleVersion, report.Reason)
	}
	if linked.Sum != pin.Sum {
		report.Reason = fmt.Sprintf("linked %s@%s has module sum %q, expected %q", pin.Path, linked.Version, linked.Sum, pin.Sum)
		return report, fmt.Errorf("githubscale: probe: %w: %s", ErrIncompatibleModuleVersion, report.Reason)
	}

	report.Compatible = true
	return report, nil
}
