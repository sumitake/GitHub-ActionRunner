package hostruntime

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
)

var (
	ErrTargetHostUsage  = errors.New("hostruntime: invalid target host command")
	ErrTargetHostFailed = errors.New("hostruntime: target host command failed")
)

type TargetHostAction string

const (
	TargetInstall           TargetHostAction = "install"
	TargetVerify            TargetHostAction = "verify"
	TargetSuspend           TargetHostAction = "suspend"
	TargetResume            TargetHostAction = "resume"
	TargetRollback          TargetHostAction = "rollback"
	TargetUninstall         TargetHostAction = "uninstall"
	TargetWatchdogInstall   TargetHostAction = "watchdog-install"
	TargetWatchdogUninstall TargetHostAction = "watchdog-uninstall"
)

type TargetHostRequest struct {
	Action             TargetHostAction
	PrivatePath        string
	ManifestPath       string
	DrainPolicy        string
	HostedConfirmation string
	LegacyCommandFile  string
	ExpectedGeneration uint64
	RequireZero        bool
	RetainState        bool
}

// TargetHostExecutor receives only a closed action and fields parsed from that
// action's exact grammar. It has no shell, argv, environment, destination, or
// stdin surface.
type TargetHostExecutor interface {
	ExecuteTargetHost(
		context.Context,
		TargetHostRequest,
	) (HostActionResult, error)
}

func ParseTargetHostCommand(args []string) (TargetHostRequest, error) {
	var request TargetHostRequest
	switch {
	case len(args) == 7 &&
		args[0] == "install" &&
		args[1] == "--private" &&
		args[3] == "--manifest" &&
		args[5] == "--acquisition" &&
		args[6] == "disabled":
		request = TargetHostRequest{
			Action:       TargetInstall,
			PrivatePath:  args[2],
			ManifestPath: args[4],
		}
	case len(args) == 6 &&
		args[0] == "verify" &&
		args[1] == "--private" &&
		args[3] == "--manifest" &&
		args[5] == "--require-zero-listeners":
		request = TargetHostRequest{
			Action:       TargetVerify,
			PrivatePath:  args[2],
			ManifestPath: args[4],
			RequireZero:  true,
		}
	case len(args) == 7 &&
		args[0] == "suspend" &&
		args[1] == "--private" &&
		(args[3] == "--drain-policy=wait" ||
			args[3] == "--drain-policy=cancel") &&
		args[4] == "--hosted-confirmation":
		request = TargetHostRequest{
			Action:             TargetSuspend,
			PrivatePath:        args[2],
			DrainPolicy:        strings.TrimPrefix(args[3], "--drain-policy="),
			HostedConfirmation: args[5],
		}
		if args[6] != "--require-zero-listeners" {
			return TargetHostRequest{}, ErrTargetHostUsage
		}
		request.RequireZero = true
	case len(args) == 5 &&
		args[0] == "resume" &&
		args[1] == "--private" &&
		args[3] == "--acquisition" &&
		args[4] == "disabled":
		request = TargetHostRequest{
			Action:      TargetResume,
			PrivatePath: args[2],
		}
	case len(args) == 9 &&
		args[0] == "rollback" &&
		args[1] == "--private" &&
		args[3] == "--expected-generation" &&
		args[5] == "--hosted-confirmation" &&
		args[7] == "--legacy-command-file":
		generation, ok := parseTargetGeneration(args[4])
		if !ok {
			return TargetHostRequest{}, ErrTargetHostUsage
		}
		request = TargetHostRequest{
			Action:             TargetRollback,
			PrivatePath:        args[2],
			ExpectedGeneration: generation,
			HostedConfirmation: args[6],
			LegacyCommandFile:  args[8],
		}
	case len(args) == 4 &&
		args[0] == "uninstall" &&
		args[1] == "--private" &&
		args[3] == "--retain-state":
		request = TargetHostRequest{
			Action:      TargetUninstall,
			PrivatePath: args[2],
			RetainState: true,
		}
	case len(args) == 5 &&
		args[0] == "watchdog-install" &&
		args[1] == "--private" &&
		args[3] == "--manifest":
		request = TargetHostRequest{
			Action:       TargetWatchdogInstall,
			PrivatePath:  args[2],
			ManifestPath: args[4],
		}
	case len(args) == 3 &&
		args[0] == "watchdog-uninstall" &&
		args[1] == "--private":
		request = TargetHostRequest{
			Action:      TargetWatchdogUninstall,
			PrivatePath: args[2],
		}
	default:
		return TargetHostRequest{}, ErrTargetHostUsage
	}
	if !canonicalTargetPath(request.PrivatePath) ||
		request.ManifestPath != "" &&
			(!canonicalTargetPath(request.ManifestPath) ||
				request.ManifestPath == request.PrivatePath) ||
		request.HostedConfirmation != "" &&
			(!canonicalTargetPath(request.HostedConfirmation) ||
				request.HostedConfirmation == request.PrivatePath ||
				request.HostedConfirmation == request.ManifestPath) ||
		request.LegacyCommandFile != "" &&
			(!canonicalTargetPath(request.LegacyCommandFile) ||
				request.LegacyCommandFile == request.PrivatePath ||
				request.LegacyCommandFile == request.HostedConfirmation) {
		return TargetHostRequest{}, ErrTargetHostUsage
	}
	return request, nil
}

func RunTargetHostCommand(
	ctx context.Context,
	args []string,
	executor TargetHostExecutor,
) (HostActionResult, error) {
	if ctx == nil || executor == nil {
		return HostActionResult{}, ErrTargetHostFailed
	}
	request, err := ParseTargetHostCommand(args)
	if err != nil {
		return HostActionResult{}, err
	}
	result, err := executor.ExecuteTargetHost(ctx, request)
	if err != nil {
		return HostActionResult{}, ErrTargetHostFailed
	}
	if _, _, err := MarshalHostActionResult(result); err != nil ||
		result.Status != HostActionComplete ||
		result.TargetProofDigest == nil {
		return HostActionResult{}, ErrTargetHostFailed
	}
	return result, nil
}

func canonicalTargetPath(path string) bool {
	return filepath.IsAbs(path) &&
		filepath.Clean(path) == path &&
		!strings.ContainsRune(path, 0)
}

func parseTargetGeneration(value string) (uint64, bool) {
	if value == "" ||
		value == "0" ||
		len(value) > 1 && value[0] == '0' ||
		strings.HasPrefix(value, "+") ||
		len(value) > 20 {
		return 0, false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return 0, false
		}
	}
	generation, err := strconv.ParseUint(value, 10, 64)
	return generation, err == nil && generation != 0
}
