package githubscale

import (
	"context"
	"fmt"

	"github.com/actions/scaleset"
)

// EnsureScaleSet implements Client. It creates fleet.ScaleSetName in the
// default runner group when no scale set of that name exists, with a single
// name label and in-place updates disabled, then reads it back and applies the
// same identity and compatibility checks as Open. An existing scale set is
// never updated or deleted: if it fails those checks, EnsureScaleSet returns
// the error and leaves it for the operator.
func (c *client) EnsureScaleSet(ctx context.Context, fleet Fleet) (ScaleSetCompatibilityReport, bool, error) {
	report, err := c.Probe(ctx)
	if err != nil {
		return ScaleSetCompatibilityReport{}, false, fmt.Errorf("githubscale: ensure scale set: compatibility probe: %w", err)
	}
	if !report.Compatible {
		return ScaleSetCompatibilityReport{}, false, fmt.Errorf("githubscale: ensure scale set: compatibility probe: %w", ErrIncompatibleModuleVersion)
	}
	fleetScopeURL, err := canonicalGitHubScopeURL(fleet.GitHubConfigURL)
	if err != nil {
		return ScaleSetCompatibilityReport{}, false, fmt.Errorf("githubscale: ensure scale set: %w: %v", ErrIdentityMismatch, err)
	}
	if fleetScopeURL != c.configScopeURL {
		return ScaleSetCompatibilityReport{}, false, fmt.Errorf("githubscale: ensure scale set: %w: fleet scope does not match client scope", ErrIdentityMismatch)
	}
	if fleet.ScaleSetName == "" {
		return ScaleSetCompatibilityReport{}, false, fmt.Errorf("githubscale: ensure scale set: %w: empty scale-set name", ErrIdentityMismatch)
	}

	cctx, cancel := withOperationDeadline(ctx, c.opTimeout)
	defer cancel()
	release, err := c.gate.enter(cctx)
	if err != nil {
		return ScaleSetCompatibilityReport{}, false, fmt.Errorf("githubscale: ensure scale set: wait for serialization: %w", err)
	}
	defer release()

	group, err := c.upstream.GetRunnerGroupByName(cctx, scaleset.DefaultRunnerGroup)
	if err != nil {
		return ScaleSetCompatibilityReport{}, false, sanitizeUpstreamError(cctx, "ensure scale set: resolve runner group", err)
	}
	existing, err := c.upstream.GetRunnerScaleSet(cctx, group.ID, fleet.ScaleSetName)
	if err != nil {
		return ScaleSetCompatibilityReport{}, false, sanitizeUpstreamError(cctx, "ensure scale set: resolve scale set", err)
	}
	created := false
	if existing == nil {
		if _, err := c.upstream.CreateRunnerScaleSet(cctx, &scaleset.RunnerScaleSet{
			Name:          fleet.ScaleSetName,
			RunnerGroupID: group.ID,
			Labels:        []scaleset.Label{{Name: fleet.ScaleSetName, Type: "System"}},
			RunnerSetting: scaleset.RunnerSetting{DisableUpdate: true},
		}); err != nil {
			return ScaleSetCompatibilityReport{}, false, sanitizeUpstreamError(cctx, "ensure scale set: create scale set", err)
		}
		created = true
	}

	// Re-read rather than trust the create response, so the evidence is the
	// state GitHub now serves to Open.
	scaleSet, err := c.upstream.GetRunnerScaleSet(cctx, group.ID, fleet.ScaleSetName)
	if err != nil {
		return ScaleSetCompatibilityReport{}, created, sanitizeUpstreamError(cctx, "ensure scale set: re-read scale set", err)
	}
	if scaleSet == nil {
		return ScaleSetCompatibilityReport{}, created, fmt.Errorf("githubscale: ensure scale set: %w: %q", ErrScaleSetNotFound, fleet.ScaleSetName)
	}
	if err := verifyScaleSetIdentity(scaleSet, group, fleet); err != nil {
		return ScaleSetCompatibilityReport{}, created, fmt.Errorf("githubscale: ensure scale set: %w", err)
	}
	compatibility, err := verifyScaleSetCompatibility(scaleSet, fleet.ScaleSetName)
	if err != nil {
		return ScaleSetCompatibilityReport{}, created, fmt.Errorf("githubscale: ensure scale set: %w", err)
	}
	return compatibility, created, nil
}
