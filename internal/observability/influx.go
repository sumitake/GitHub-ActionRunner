package observability

import (
	"errors"
	"fmt"
	"strings"

	"github.com/sumitake/portable-ghar/internal/health"
)

var ErrInfluxLine = errors.New("observability: influx line")

// EncodeHealthLine writes one one-way portable_ghar_health line. The
// controller never receives Influx credentials through this adapter.
func EncodeHealthLine(export health.Export) (string, error) {
	if err := export.Validate(); err != nil {
		return "", err
	}
	snapshot := export.Snapshot
	if strings.ContainsAny(snapshot.FleetAlias, " \n,=") {
		return "", fmt.Errorf("%w: tag", ErrInfluxLine)
	}
	return fmt.Sprintf(
		"portable_ghar_health,fleet=%s schema_version=%di,policy_epoch=%di,assigned_jobs=%di,running_jobs=%di,unassigned_released_listeners=%di,degraded=%t",
		snapshot.FleetAlias,
		export.SchemaVersion,
		snapshot.PolicyEpoch,
		snapshot.AssignedJobs,
		snapshot.RunningJobs,
		snapshot.UnassignedReleasedListeners,
		snapshot.Degraded,
	), nil
}
