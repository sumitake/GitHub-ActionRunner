package testenv

import (
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/task11synthetic"
)

type task11SyntheticContainerExit struct {
	Running   bool   `json:"running"`
	OOMKilled bool   `json:"oom_killed"`
	Error     string `json:"error"`
	ExitCode  int    `json:"exit_code"`
}

func task11SyntheticAttachArgv(
	dockerPath string,
	runnerID string,
) ([]string, error) {
	if !filepath.IsAbs(dockerPath) ||
		filepath.Clean(dockerPath) != dockerPath ||
		!isLowerHex(runnerID, 64) {
		return nil, ErrFixtureStart
	}
	return []string{
		dockerPath,
		"attach",
		"--no-stdin",
		"--sig-proxy=false",
		runnerID,
	}, nil
}

func parseTask11SyntheticContainerExit(
	document []byte,
) (task11SyntheticContainerExit, error) {
	if len(document) == 0 ||
		document[len(document)-1] != '\n' {
		return task11SyntheticContainerExit{}, ErrFixtureStart
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var observation task11SyntheticContainerExit
	if err := decoder.Decode(&observation); err != nil {
		return task11SyntheticContainerExit{}, ErrFixtureStart
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF ||
		!validTask11SyntheticExitStatus(observation.ExitCode) {
		return task11SyntheticContainerExit{}, ErrFixtureStart
	}
	canonical, err := json.Marshal(observation)
	if err != nil {
		return task11SyntheticContainerExit{}, ErrFixtureStart
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(canonical, document) {
		return task11SyntheticContainerExit{}, ErrFixtureStart
	}
	return observation, nil
}

func validateTask11SyntheticAttachResult(
	result hostruntime.Result,
	inspect task11SyntheticContainerExit,
	binding task11synthetic.StreamBinding,
	maximumBytes uint64,
) (task11synthetic.Stream, error) {
	expectedExit, ok := task11SyntheticExpectedExit(binding.Scenario)
	if !ok ||
		maximumBytes == 0 ||
		uint64(len(result.Stdout)) > maximumBytes ||
		len(result.Stdout) == 0 ||
		len(result.Stderr) != 0 ||
		result.StdoutTruncated ||
		result.StderrTruncated ||
		result.Signaled ||
		result.Signal != "" ||
		result.ExitCode != expectedExit ||
		inspect.Running ||
		inspect.OOMKilled ||
		inspect.Error != "" ||
		inspect.ExitCode != expectedExit ||
		inspect.ExitCode != result.ExitCode {
		return task11synthetic.Stream{}, ErrFixtureStart
	}
	stream, err := task11synthetic.ParseStream(result.Stdout, binding)
	if err != nil {
		return task11synthetic.Stream{}, ErrFixtureStart
	}
	if expectedExit == task11synthetic.NormalExitStatus {
		if stream.Terminal == nil {
			return task11synthetic.Stream{}, ErrFixtureStart
		}
	} else if stream.Terminal != nil {
		return task11synthetic.Stream{}, ErrFixtureStart
	}
	return stream, nil
}

func task11SyntheticExpectedExit(
	scenario task11synthetic.Scenario,
) (int, bool) {
	switch scenario {
	case task11synthetic.ScenarioOneJob,
		task11synthetic.ScenarioCleanupSuccess,
		task11synthetic.ScenarioReclamation,
		task11synthetic.ScenarioSeedFirst,
		task11synthetic.ScenarioSeedSecond:
		return task11synthetic.NormalExitStatus, true
	case task11synthetic.ScenarioCleanupListenerCrash:
		return task11synthetic.ListenerCrashExitStatus, true
	case task11synthetic.ScenarioCleanupUpgradeInterruption:
		return task11synthetic.UpgradeInterruptionExitStatus, true
	default:
		return 0, false
	}
}

func validTask11SyntheticExitStatus(status int) bool {
	return status == task11synthetic.NormalExitStatus ||
		status == task11synthetic.ListenerCrashExitStatus ||
		status == task11synthetic.UpgradeInterruptionExitStatus
}
