package archive

type fileIdentity struct {
	device    uint64
	inode     uint64
	nlink     uint64
	uid       uint32
	gid       uint32
	size      int64
	mode      uint32
	mtimeSec  int64
	mtimeNsec int64
	ctimeSec  int64
	ctimeNsec int64
	blocks    int64
}

func (a fileIdentity) stableEqual(b fileIdentity) bool {
	return a.device == b.device && a.inode == b.inode && a.nlink == b.nlink &&
		a.uid == b.uid && a.gid == b.gid &&
		a.size == b.size && a.mode == b.mode && a.mtimeSec == b.mtimeSec &&
		a.mtimeNsec == b.mtimeNsec && a.ctimeSec == b.ctimeSec && a.ctimeNsec == b.ctimeNsec
}

func (a fileIdentity) sparse() bool {
	return a.size > 0 && a.blocks >= 0 && uint64(a.blocks)*512 < uint64(a.size)
}
