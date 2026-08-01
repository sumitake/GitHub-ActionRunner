package imageverify

type lockedFileIdentity struct {
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
}

func (identity lockedFileIdentity) stableEqual(other lockedFileIdentity) bool {
	return identity.device == other.device &&
		identity.inode == other.inode &&
		identity.nlink == other.nlink &&
		identity.uid == other.uid &&
		identity.gid == other.gid &&
		identity.size == other.size &&
		identity.mode == other.mode &&
		identity.mtimeSec == other.mtimeSec &&
		identity.mtimeNsec == other.mtimeNsec &&
		identity.ctimeSec == other.ctimeSec &&
		identity.ctimeNsec == other.ctimeNsec
}
