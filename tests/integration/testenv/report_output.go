package testenv

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

var ErrReportOutput = errors.New("testenv: conformance report output unavailable")

// ReportOutput is where a target run writes its canonical report. It is
// checked at startup, before the run consumes its input, so a bad path never
// costs a run.
type ReportOutput struct {
	path string
}

// OpenReportOutput accepts an absolute path whose file does not exist yet and
// whose parent is a real directory owned by euid that no group or other user
// can write.
func OpenReportOutput(path string, euid int) (ReportOutput, error) {
	if !validAbsolutePath(path) || path == "/" {
		return ReportOutput{}, ErrReportOutput
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0o022 != 0 {
		return ReportOutput{}, ErrReportOutput
	}
	stat, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != euid {
		return ReportOutput{}, ErrReportOutput
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return ReportOutput{}, ErrReportOutput
	}
	return ReportOutput{path: path}, nil
}

// Write stores the report's exact canonical bytes in a new mode 0600 file.
// It never replaces an existing file or follows a symlink.
func (output ReportOutput) Write(report conformance.Report) error {
	if output.path == "" {
		return ErrReportOutput
	}
	document, err := conformance.MarshalReport(report)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(
		output.path,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW,
		0o600,
	)
	if err != nil {
		return errors.Join(ErrReportOutput, err)
	}
	_, writeErr := file.Write(document)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return errors.Join(ErrReportOutput, err)
	}
	return nil
}
