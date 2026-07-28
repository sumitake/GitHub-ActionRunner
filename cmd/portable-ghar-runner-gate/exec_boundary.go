package main

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sumitake/portable-ghar/internal/runtimeenv"
)

func validateListenerExecBoundary(file *os.File, path string, argv, env []string) error {
	if file == nil || int(file.Fd()) < 3 ||
		path != "/proc/self/fd/"+strconv.FormatUint(uint64(file.Fd()), 10) ||
		len(argv) != 2 || !filepath.IsAbs(argv[0]) || filepath.Clean(argv[0]) != argv[0] ||
		strings.IndexByte(argv[0], 0) >= 0 || argv[1] != "run" ||
		!runtimeenv.MatchesListener(env) {
		return errors.New("runner-gate: exec boundary invalid")
	}
	return nil
}
