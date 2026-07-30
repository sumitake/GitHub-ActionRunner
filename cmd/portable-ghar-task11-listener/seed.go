package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"

	"github.com/sumitake/portable-ghar/internal/task11synthetic"
	"golang.org/x/sys/unix"
)

type seedFileContract struct {
	sourcePath string
	copyPath   string

	sourceUID  uint32
	sourceGID  uint32
	copyUID    uint32
	copyGID    uint32
	sourceMode uint32
	copyMode   uint32

	requireSourceWriteDeny bool
}

type seedFileSnapshot struct {
	identity listenerFileIdentity
	document []byte
}

type fixedSeedSession struct {
	scenario task11synthetic.Scenario
	contract seedFileContract
	source   listenerFileIdentity
	copy     listenerFileIdentity
	used     bool
}

func prepareSeed(
	scenario task11synthetic.Scenario,
) (seedSession, error) {
	return prepareSeedWithContract(
		scenario,
		seedFileContract{
			sourcePath: task11synthetic.SeedSourceAbsolutePath,
			copyPath:   task11synthetic.SeedCopyAbsolutePath,
			sourceUID:  0,
			sourceGID:  0,
			copyUID:    uint32(os.Geteuid()),
			copyGID:    uint32(os.Getegid()),
			sourceMode: 0o644,
			copyMode:   0o644,

			requireSourceWriteDeny: true,
		},
	)
}

func prepareSeedWithContract(
	scenario task11synthetic.Scenario,
	contract seedFileContract,
) (seedSession, error) {
	if (scenario != task11synthetic.ScenarioSeedFirst &&
		scenario != task11synthetic.ScenarioSeedSecond) ||
		!validSeedContract(contract) {
		return nil, errors.New("task11 listener seed unavailable")
	}
	source, err := readSeedFile(
		contract.sourcePath,
		contract.sourceUID,
		contract.sourceGID,
		contract.sourceMode,
		len(task11synthetic.SeedSourceBytes()),
	)
	if err != nil {
		return nil, errors.New("task11 listener seed unavailable")
	}
	copySnapshot, err := readSeedFile(
		contract.copyPath,
		contract.copyUID,
		contract.copyGID,
		contract.copyMode,
		len(task11synthetic.SeedSourceBytes()),
	)
	if err != nil {
		zero(source.document)
		return nil, errors.New("task11 listener seed unavailable")
	}
	defer zero(source.document)
	defer zero(copySnapshot.document)
	sourceBytes := task11synthetic.SeedSourceBytes()
	defer zero(sourceBytes)
	if !bytes.Equal(source.document, sourceBytes) ||
		!bytes.Equal(copySnapshot.document, sourceBytes) ||
		bytes.Contains(source.document, task11synthetic.SeedMutationSuffix()) ||
		bytes.Contains(copySnapshot.document, task11synthetic.SeedMutationSuffix()) ||
		task11synthetic.SeedSourceDigest(source.document) !=
			task11synthetic.SeedSourceSHA256 ||
		task11synthetic.SeedCopyDigest(copySnapshot.document) !=
			task11synthetic.SeedSourceSHA256 ||
		contract.requireSourceWriteDeny &&
			!seedSourceWriteDenied(contract.sourcePath) {
		return nil, errors.New("task11 listener seed unavailable")
	}
	return &fixedSeedSession{
		scenario: scenario,
		contract: contract,
		source:   source.identity,
		copy:     copySnapshot.identity,
	}, nil
}

func (session *fixedSeedSession) Finalize() (
	task11synthetic.SeedProof,
	error,
) {
	if session == nil || session.used || !validSeedContract(session.contract) {
		return task11synthetic.SeedProof{},
			errors.New("task11 listener seed unavailable")
	}
	session.used = true
	sourceMaximum := len(task11synthetic.SeedSourceBytes())
	copyMaximum := sourceMaximum
	if session.scenario == task11synthetic.ScenarioSeedFirst {
		suffix := task11synthetic.SeedMutationSuffix()
		copyMaximum += len(suffix)
		if appendSeedCopy(
			session.contract,
			session.copy,
			suffix,
		) != nil {
			zero(suffix)
			return task11synthetic.SeedProof{},
				errors.New("task11 listener seed unavailable")
		}
		zero(suffix)
	}
	source, err := readSeedFile(
		session.contract.sourcePath,
		session.contract.sourceUID,
		session.contract.sourceGID,
		session.contract.sourceMode,
		sourceMaximum,
	)
	if err != nil {
		return task11synthetic.SeedProof{},
			errors.New("task11 listener seed unavailable")
	}
	copySnapshot, err := readSeedFile(
		session.contract.copyPath,
		session.contract.copyUID,
		session.contract.copyGID,
		session.contract.copyMode,
		copyMaximum,
	)
	if err != nil {
		zero(source.document)
		return task11synthetic.SeedProof{},
			errors.New("task11 listener seed unavailable")
	}
	defer zero(source.document)
	defer zero(copySnapshot.document)
	if !source.identity.sameObject(session.source) ||
		!copySnapshot.identity.sameObject(session.copy) ||
		task11synthetic.SeedSourceDigest(source.document) !=
			task11synthetic.SeedSourceSHA256 ||
		!bytes.Equal(source.document, task11synthetic.SeedSourceBytes()) ||
		session.contract.requireSourceWriteDeny &&
			!seedSourceWriteDenied(session.contract.sourcePath) {
		return task11synthetic.SeedProof{},
			errors.New("task11 listener seed unavailable")
	}
	mutationAbsent := session.scenario == task11synthetic.ScenarioSeedSecond
	if mutationAbsent {
		suffix := task11synthetic.SeedMutationSuffix()
		defer zero(suffix)
		if !bytes.Equal(
			copySnapshot.document,
			task11synthetic.SeedSourceBytes(),
		) ||
			bytes.Contains(source.document, suffix) ||
			bytes.Contains(copySnapshot.document, suffix) {
			return task11synthetic.SeedProof{},
				errors.New("task11 listener seed unavailable")
		}
	} else {
		want := append(
			task11synthetic.SeedSourceBytes(),
			task11synthetic.SeedMutationSuffix()...,
		)
		defer zero(want)
		if !bytes.Equal(copySnapshot.document, want) ||
			task11synthetic.SeedCopyDigest(copySnapshot.document) !=
				task11synthetic.SeedMutationSHA256 {
			return task11synthetic.SeedProof{},
				errors.New("task11 listener seed unavailable")
		}
	}
	proof := task11synthetic.SeedProof{
		SeedID:           task11synthetic.SeedID,
		SourceDigest:     task11synthetic.SeedSourceSHA256,
		CopyDigest:       task11synthetic.SeedSourceSHA256,
		MutationDigest:   task11synthetic.SeedMutationSHA256,
		SourcePostDigest: task11synthetic.SeedSourceSHA256,
		MutationAbsent:   mutationAbsent,
		SourceImmutable:  true,
	}
	return proof, nil
}

func readSeedFile(
	path string,
	expectedUID uint32,
	expectedGID uint32,
	expectedMode uint32,
	maximum int,
) (seedFileSnapshot, error) {
	if !canonicalAbsolutePath(path) ||
		maximum <= 0 ||
		expectedMode > 0o777 {
		return seedFileSnapshot{}, errors.New("task11 listener seed unavailable")
	}
	parentFD, _, err := openExactDirectory(filepath.Dir(path))
	if err != nil {
		return seedFileSnapshot{}, errors.New("task11 listener seed unavailable")
	}
	defer closeFD(parentFD)
	name := filepath.Base(path)
	beforePath, err := identityAt(parentFD, name)
	if err != nil ||
		!seedIdentityMatches(
			beforePath,
			expectedUID,
			expectedGID,
			expectedMode,
		) {
		return seedFileSnapshot{}, errors.New("task11 listener seed unavailable")
	}
	fd, err := unix.Openat(
		parentFD,
		name,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return seedFileSnapshot{}, errors.New("task11 listener seed unavailable")
	}
	file := os.NewFile(uintptr(fd), "task11-seed")
	if file == nil {
		closeFD(fd)
		return seedFileSnapshot{}, errors.New("task11 listener seed unavailable")
	}
	beforeFD, identityErr := identityFromFD(fd)
	document, readErr := readAllFile(file, int64(maximum))
	afterFD, afterErr := identityFromFD(fd)
	closeErr := file.Close()
	afterPath, pathErr := identityAt(parentFD, name)
	if identityErr != nil ||
		readErr != nil ||
		afterErr != nil ||
		closeErr != nil ||
		pathErr != nil ||
		len(document) == 0 ||
		len(document) > maximum ||
		!beforePath.equal(beforeFD) ||
		!beforeFD.equal(afterFD) ||
		!afterFD.equal(afterPath) ||
		!seedIdentityMatches(
			afterFD,
			expectedUID,
			expectedGID,
			expectedMode,
		) ||
		afterFD.size != int64(len(document)) {
		zero(document)
		return seedFileSnapshot{}, errors.New("task11 listener seed unavailable")
	}
	return seedFileSnapshot{identity: afterFD, document: document}, nil
}

func appendSeedCopy(
	contract seedFileContract,
	want listenerFileIdentity,
	suffix []byte,
) error {
	parentFD, _, err := openExactDirectory(filepath.Dir(contract.copyPath))
	if err != nil {
		return errors.New("task11 listener seed unavailable")
	}
	defer closeFD(parentFD)
	name := filepath.Base(contract.copyPath)
	current, err := identityAt(parentFD, name)
	if err != nil ||
		!current.equal(want) ||
		!seedIdentityMatches(
			current,
			contract.copyUID,
			contract.copyGID,
			contract.copyMode,
		) {
		return errors.New("task11 listener seed unavailable")
	}
	fd, err := unix.Openat(
		parentFD,
		name,
		unix.O_WRONLY|unix.O_APPEND|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return errors.New("task11 listener seed unavailable")
	}
	defer closeFD(fd)
	opened, err := identityFromFD(fd)
	if err != nil || !opened.equal(want) ||
		writeExactFD(fd, suffix) != nil ||
		unix.Fsync(fd) != nil {
		return errors.New("task11 listener seed unavailable")
	}
	after, err := identityFromFD(fd)
	pathAfter, pathErr := identityAt(parentFD, name)
	if err != nil ||
		pathErr != nil ||
		!after.sameObject(want) ||
		!after.equal(pathAfter) ||
		after.size != want.size+int64(len(suffix)) ||
		syncDirectoryFD(parentFD) != nil {
		return errors.New("task11 listener seed unavailable")
	}
	return nil
}

func seedSourceWriteDenied(path string) bool {
	if !canonicalAbsolutePath(path) {
		return false
	}
	parentFD, _, err := openExactDirectory(filepath.Dir(path))
	if err != nil {
		return false
	}
	defer closeFD(parentFD)
	fd, err := unix.Openat(
		parentFD,
		filepath.Base(path),
		unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err == nil {
		closeFD(fd)
		return false
	}
	return errors.Is(err, unix.EACCES) || errors.Is(err, unix.EROFS)
}

func seedIdentityMatches(
	identity listenerFileIdentity,
	uid uint32,
	gid uint32,
	mode uint32,
) bool {
	return identity.isRegular(mode, uid) && identity.gid == gid
}

func validSeedContract(contract seedFileContract) bool {
	return canonicalAbsolutePath(contract.sourcePath) &&
		canonicalAbsolutePath(contract.copyPath) &&
		contract.sourcePath != contract.copyPath &&
		validLeaf(filepath.Base(contract.sourcePath)) &&
		validLeaf(filepath.Base(contract.copyPath)) &&
		contract.sourceMode <= 0o777 &&
		contract.copyMode <= 0o777
}
