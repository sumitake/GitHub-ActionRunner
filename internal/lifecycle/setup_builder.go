package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
)

var buildIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// SetupConfig is everything a slot's setup needs besides the assignment.
// NewSetupBuilder checks the parts the builder interprets; the orchestrator
// and the container engine validate the rest when they use it.
type SetupConfig struct {
	BuildID           string
	FleetGeneration   uint64
	BrokerRoot        string
	Profile           hostruntime.HostProfile
	Images            SetupImages
	Users             SetupUsers
	Seccomp           hostruntime.SeccompBinding
	Limits            SetupLimits
	Graph             networkjail.DecisionGraph
	Policy            hostruntime.PolicyArtifact
	ConntrackInput    networkjail.Budget
	MaxRunnerCapacity uint64
}

type SetupImages struct {
	Adapter  string
	Broker   string
	Helper   string
	Runner   string
	Verifier string
}

// SetupUsers are numeric "uid:gid" container users. The adapter and broker
// share one user.
type SetupUsers struct {
	AdapterBroker string
	Runner        string
	Verifier      string
}

type SetupLimits struct {
	Adapter  hostruntime.ContainerLimits
	Broker   hostruntime.BrokerLimits
	Helper   hostruntime.OneShotLimits
	Runner   hostruntime.RunnerLimits
	Verifier hostruntime.OneShotLimits
}

type setupBuilder struct {
	config SetupConfig
}

// NewSetupBuilder returns the production SetupBuilder. Build is a pure
// function of the configuration and the assignment: lifecycle also calls it
// during recovery to recompute a slot's RecoverySpec, so it must not touch
// the host. WithSlotDirectories creates the directories at Prepare.
func NewSetupBuilder(config SetupConfig) (SetupBuilder, error) {
	if err := validSetupConfig(config); err != nil {
		return nil, fmt.Errorf("%w: setup config: %w", ErrLifecycle, err)
	}
	return &setupBuilder{config: config}, nil
}

func validSetupConfig(config SetupConfig) error {
	if !buildIDPattern.MatchString(config.BuildID) || config.FleetGeneration == 0 {
		return fmt.Errorf("build identity")
	}
	if !filepath.IsAbs(config.BrokerRoot) || filepath.Clean(config.BrokerRoot) != config.BrokerRoot {
		return fmt.Errorf("broker root")
	}
	for _, image := range []string{
		config.Images.Adapter, config.Images.Broker, config.Images.Helper,
		config.Images.Runner, config.Images.Verifier,
	} {
		if image == "" {
			return fmt.Errorf("image")
		}
	}
	for _, user := range []string{config.Users.AdapterBroker, config.Users.Verifier} {
		if uid, _, err := hostruntime.ParseNumericUser(user); err != nil || uid == 0 {
			return fmt.Errorf("broker and verifier users must be non-root")
		}
	}
	runnerUID, runnerGID, err := hostruntime.ParseNumericUser(config.Users.Runner)
	if err != nil {
		return fmt.Errorf("runner user")
	}
	switch config.Profile {
	case hostruntime.HostProfileStrictLinux:
		if runnerUID == 0 {
			return fmt.Errorf("strict-linux runner must be non-root")
		}
	case hostruntime.HostProfileQTSCaplessRoot:
		if runnerUID != 0 || runnerGID != 0 {
			return fmt.Errorf("qts-capless-root runner must be 0:0")
		}
	default:
		return fmt.Errorf("profile")
	}
	if !filepath.IsAbs(config.Seccomp.Path) || config.Seccomp.SHA256 == "" {
		return fmt.Errorf("seccomp")
	}
	if !config.Policy.Valid() || config.MaxRunnerCapacity == 0 {
		return fmt.Errorf("policy")
	}
	return nil
}

func (builder *setupBuilder) Build(
	ctx context.Context,
	assignment controller.Assignment,
) (networkjail.PreparedSetupRequest, hostruntime.RecoverySpec, error) {
	if ctx == nil || ctx.Err() != nil {
		return networkjail.PreparedSetupRequest{}, hostruntime.RecoverySpec{}, ErrLifecycle
	}
	if err := assignment.Validate(); err != nil {
		return networkjail.PreparedSetupRequest{}, hostruntime.RecoverySpec{}, fmt.Errorf("%w: assignment: %w", ErrLifecycle, err)
	}
	config := builder.config
	recovery, err := RecoverySpecFor(assignment.Slot, config.BuildID, config.FleetGeneration, config.BrokerRoot)
	if err != nil {
		return networkjail.PreparedSetupRequest{}, hostruntime.RecoverySpec{}, err
	}
	generation, err := JobGeneration(assignment.Key)
	if err != nil {
		return networkjail.PreparedSetupRequest{}, hostruntime.RecoverySpec{}, err
	}
	slotIdentity := assignment.Slot.OpaqueName
	return networkjail.PreparedSetupRequest{
		Key: assignment.Key,
		Adapter: hostruntime.AdapterSpec{
			Name:            recovery.AdapterName,
			Image:           config.Images.Adapter,
			BuildID:         config.BuildID,
			FleetGeneration: config.FleetGeneration,
			SlotIdentity:    slotIdentity,
			BrokerParent:    recovery.RelayParent,
			User:            config.Users.AdapterBroker,
			Seccomp:         config.Seccomp,
			Limits:          config.Limits.Adapter,
		},
		Broker: hostruntime.BrokerSpec{
			Name:              recovery.BrokerName,
			Image:             config.Images.Broker,
			HelperImage:       config.Images.Helper,
			PolicyIPv6Posture: config.Policy.IPv6Posture(),
			BuildID:           config.BuildID,
			FleetGeneration:   config.FleetGeneration,
			SlotIdentity:      slotIdentity,
			CapacitySlotID:    assignment.Slot.CapacitySlotID,
			JobGeneration:     generation,
			RelayParent:       recovery.RelayParent,
			AuthorityParent:   recovery.AuthorityParent,
			User:              config.Users.AdapterBroker,
			Seccomp:           config.Seccomp,
			Limits:            config.Limits.Broker,
			HelperLimits:      config.Limits.Helper,
		},
		Runner: hostruntime.RunnerSpec{
			Name:            recovery.RunnerName,
			Image:           config.Images.Runner,
			BuildID:         config.BuildID,
			FleetGeneration: config.FleetGeneration,
			SlotIdentity:    slotIdentity,
			Profile:         config.Profile,
			User:            config.Users.Runner,
			Seccomp:         config.Seccomp,
			Limits:          config.Limits.Runner,
		},
		Verifier: hostruntime.VerifierSpec{
			Image:           config.Images.Verifier,
			BuildID:         config.BuildID,
			FleetGeneration: config.FleetGeneration,
			SlotIdentity:    slotIdentity,
			User:            config.Users.Verifier,
			Seccomp:         config.Seccomp,
			Limits:          config.Limits.Verifier,
		},
		Graph:             config.Graph,
		Policy:            config.Policy,
		ConntrackInput:    config.ConntrackInput,
		MaxRunnerCapacity: config.MaxRunnerCapacity,
		SeedIDs:           []string{},
	}, recovery, nil
}

// RecoverySpecFor derives a slot's container names and directories from its
// opaque name: pghar-{adapter,broker,runner}-<suffix>, and
// <brokerRoot>/<opaque name>/{relay,authority}. The expected container IDs
// are the ones the slot has recorded, empty before creation.
func RecoverySpecFor(
	slot controller.RunnerSlot,
	buildID string,
	fleetGeneration uint64,
	brokerRoot string,
) (hostruntime.RecoverySpec, error) {
	adapterName, brokerName, runnerName, err := componentNames(slot.OpaqueName)
	if err != nil {
		return hostruntime.RecoverySpec{}, err
	}
	return hostruntime.RecoverySpec{
		SlotIdentity:      slot.OpaqueName,
		BuildID:           buildID,
		FleetGeneration:   fleetGeneration,
		AdapterName:       adapterName,
		BrokerName:        brokerName,
		RunnerName:        runnerName,
		ExpectedAdapterID: slot.AdapterContainerID,
		ExpectedBrokerID:  slot.BrokerContainerID,
		ExpectedRunnerID:  slot.RunnerContainerID,
		RelayParent:       filepath.Join(brokerRoot, slot.OpaqueName, "relay"),
		AuthorityParent:   filepath.Join(brokerRoot, slot.OpaqueName, "authority"),
	}, nil
}

// JobGeneration is the permit-ledger generation for one assignment. It is a
// hash of the assignment key, so re-preparing the same assignment after a
// crash activates the same ledger generation, and a different assignment on
// the same slot cannot reuse it.
func JobGeneration(key controller.AssignmentKey) (uint64, error) {
	if key.RepositoryAlias == "" || key.RunnerRequestID <= 0 {
		return 0, fmt.Errorf("%w: assignment key", ErrLifecycle)
	}
	digest := sha256.Sum256([]byte(
		"portable-ghar.job-generation.v1\x00" +
			key.RepositoryAlias + "\x00" +
			strconv.FormatInt(key.RunnerRequestID, 10) + "\x00" +
			strconv.FormatUint(uint64(key.Attempt), 10),
	))
	generation := binary.BigEndian.Uint64(digest[:8])
	if generation == 0 {
		return 0, fmt.Errorf("%w: zero job generation", ErrLifecycle)
	}
	return generation, nil
}

// slotDirectoryJails creates a slot's relay and authority directories just
// before the jail is prepared.
type slotDirectoryJails struct {
	JailOrchestrator
	brokerRoot string
	create     func(brokerRoot, slotIdentity string, brokerUID, brokerGID uint32) error
}

// WithSlotDirectories wraps jails so Prepare first creates the slot's
// directories with hostruntime.CreateSlotDirectories, owned by the broker
// user named in the request. The request's directories must sit directly
// under brokerRoot.
func WithSlotDirectories(jails JailOrchestrator, brokerRoot string) (JailOrchestrator, error) {
	if jails == nil || !filepath.IsAbs(brokerRoot) || filepath.Clean(brokerRoot) != brokerRoot {
		return nil, fmt.Errorf("%w: slot directories", ErrLifecycle)
	}
	return &slotDirectoryJails{
		JailOrchestrator: jails,
		brokerRoot:       brokerRoot,
		create:           hostruntime.CreateSlotDirectories,
	}, nil
}

func (jails *slotDirectoryJails) Prepare(
	ctx context.Context,
	request networkjail.PreparedSetupRequest,
) (networkjail.HeldJail, error) {
	slotIdentity := request.Broker.SlotIdentity
	slotDirectory := filepath.Join(jails.brokerRoot, slotIdentity)
	uid, gid, err := hostruntime.ParseNumericUser(request.Broker.User)
	if err != nil ||
		filepath.Dir(slotDirectory) != jails.brokerRoot ||
		request.Broker.RelayParent != filepath.Join(slotDirectory, "relay") ||
		request.Broker.AuthorityParent != filepath.Join(slotDirectory, "authority") {
		return networkjail.HeldJail{}, fmt.Errorf("%w: slot directories", ErrLifecycle)
	}
	if err := jails.create(jails.brokerRoot, slotIdentity, uid, gid); err != nil {
		return networkjail.HeldJail{}, fmt.Errorf("%w: slot directories: %w", ErrLifecycle, err)
	}
	return jails.JailOrchestrator.Prepare(ctx, request)
}
