// Package systemd implements the closed standard-Linux host qualification
// profile. It accepts only the strict nonroot profile.
package systemd

import (
	"context"
	"errors"
	"fmt"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

var ErrProfileUnavailable = errors.New("hostruntime/systemd: profile unavailable")

type Source interface {
	Observe(context.Context) (hostruntime.ProfileObservation, error)
	NetworkDocument(context.Context) ([]byte, error)
}

type Config struct {
	ID                      hostruntime.HostProfile
	TargetOS                string
	Architecture            string
	KernelRelease           string
	RuntimeVersion          string
	AllowDegradedRoot       bool
	NetworkDocumentMaxBytes int
}

type Profile struct {
	config Config
	source Source
}

var _ hostruntime.Profile = (*Profile)(nil)

func NewProfile(config Config, source Source) *Profile {
	return &Profile{config: config, source: source}
}

func (p *Profile) ID() hostruntime.HostProfile {
	if p == nil {
		return ""
	}
	return p.config.ID
}

func (p *Profile) Probe(ctx context.Context) (hostruntime.ConformanceReport, error) {
	if err := p.validateBoundary(); err != nil {
		return hostruntime.ConformanceReport{}, err
	}
	observation, err := p.source.Observe(ctx)
	if err != nil {
		return hostruntime.ConformanceReport{}, fmt.Errorf(
			"%w: observe: %w",
			ErrProfileUnavailable,
			err,
		)
	}
	if observation.Platform.OS != p.config.TargetOS ||
		observation.Platform.Architecture != p.config.Architecture ||
		observation.Platform.KernelRelease != p.config.KernelRelease ||
		observation.Platform.RuntimeVersion != p.config.RuntimeVersion {
		return hostruntime.ConformanceReport{}, fmt.Errorf(
			"%w: platform binding",
			ErrProfileUnavailable,
		)
	}
	report, err := hostruntime.EvaluateProfileObservation(
		hostruntime.HostProfileStrictLinux,
		false,
		observation,
	)
	if err != nil {
		return hostruntime.ConformanceReport{}, fmt.Errorf(
			"%w: conformance: %w",
			ErrProfileUnavailable,
			err,
		)
	}
	return report, nil
}

func (p *Profile) DiscoverNetworks(
	ctx context.Context,
) (hostruntime.NetworkSnapshot, error) {
	if err := p.validateBoundary(); err != nil {
		return hostruntime.NetworkSnapshot{}, err
	}
	document, err := p.source.NetworkDocument(ctx)
	if err != nil {
		return hostruntime.NetworkSnapshot{}, fmt.Errorf(
			"%w: discover: %w",
			ErrProfileUnavailable,
			err,
		)
	}
	snapshot, err := parseNetworkDocument(
		document,
		p.config.NetworkDocumentMaxBytes,
	)
	if err != nil {
		return hostruntime.NetworkSnapshot{}, err
	}
	if snapshot.ProfileID != hostruntime.HostProfileStrictLinux {
		return hostruntime.NetworkSnapshot{}, fmt.Errorf(
			"%w: network binding",
			ErrProfileUnavailable,
		)
	}
	return snapshot, nil
}

func (p *Profile) validateBoundary() error {
	if p == nil || p.source == nil ||
		p.config.ID != hostruntime.HostProfileStrictLinux ||
		p.config.AllowDegradedRoot ||
		p.config.TargetOS != "linux" ||
		p.config.Architecture == "" ||
		p.config.KernelRelease == "" ||
		p.config.RuntimeVersion == "" ||
		p.config.NetworkDocumentMaxBytes <= 0 {
		return ErrProfileUnavailable
	}
	return nil
}
