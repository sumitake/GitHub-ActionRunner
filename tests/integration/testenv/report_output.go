package testenv

import (
	"errors"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

var ErrReportOutput = errors.New("testenv: conformance report output unavailable")

// ReportOutput is where a target run writes its canonical report. Its parent
// directory is opened and checked at startup, before the run consumes its
// input, and the report is later created relative to that open directory, so
// a bad path never costs a run and the directory cannot be swapped in between.
type ReportOutput struct {
	mu   sync.Mutex
	dir  int
	name string
}

// OpenReportOutput accepts an absolute path whose file does not exist yet and
// whose parent is a real directory owned by euid that no group or other user
// can write. The caller must Close the result.
func OpenReportOutput(path string, euid int) (*ReportOutput, error) {
	if !validAbsolutePath(path) || path == "/" {
		return nil, ErrReportOutput
	}
	dir, err := unix.Open(
		filepath.Dir(path),
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, ErrReportOutput
	}
	var stat unix.Stat_t
	if unix.Fstat(dir, &stat) != nil ||
		stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		stat.Mode&0o022 != 0 ||
		int(stat.Uid) != euid {
		_ = unix.Close(dir)
		return nil, ErrReportOutput
	}
	name := filepath.Base(path)
	var existing unix.Stat_t
	if err := unix.Fstatat(dir, name, &existing, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		_ = unix.Close(dir)
		return nil, ErrReportOutput
	}
	return &ReportOutput{dir: dir, name: name}, nil
}

// Write stores the report's exact canonical bytes in a new mode 0600 file in
// the directory opened at startup. It never replaces an existing file or
// follows a symlink.
func (output *ReportOutput) Write(report conformance.Report) error {
	if output == nil {
		return ErrReportOutput
	}
	output.mu.Lock()
	defer output.mu.Unlock()
	if output.dir < 0 || output.name == "" {
		return ErrReportOutput
	}
	document, err := conformance.MarshalReport(report)
	if err != nil {
		return err
	}
	fd, err := unix.Openat(
		output.dir,
		output.name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0o600,
	)
	if err != nil {
		return errors.Join(ErrReportOutput, err)
	}
	file := os.NewFile(uintptr(fd), output.name)
	_, writeErr := file.Write(document)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return errors.Join(ErrReportOutput, err)
	}
	return nil
}

// Close releases the directory opened at startup.
func (output *ReportOutput) Close() error {
	if output == nil {
		return nil
	}
	output.mu.Lock()
	defer output.mu.Unlock()
	if output.dir < 0 {
		return nil
	}
	err := unix.Close(output.dir)
	output.dir = -1
	return err
}
