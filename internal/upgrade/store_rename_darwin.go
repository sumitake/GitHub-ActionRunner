//go:build darwin

package upgrade

import "golang.org/x/sys/unix"

func renameJournalNoReplace(
	rootFD int,
	source string,
	target string,
) error {
	return unix.RenameatxNp(
		rootFD,
		source,
		rootFD,
		target,
		unix.RENAME_EXCL,
	)
}
