//go:build linux

package upgrade

import "golang.org/x/sys/unix"

func renameJournalNoReplace(
	rootFD int,
	source string,
	target string,
) error {
	return unix.Renameat2(
		rootFD,
		source,
		rootFD,
		target,
		unix.RENAME_NOREPLACE,
	)
}
