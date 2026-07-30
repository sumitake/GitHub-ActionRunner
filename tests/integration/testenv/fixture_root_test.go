package testenv

import "testing"

func TestFixtureEmptyDigestBindsParentRootOwnerAndMode(t *testing.T) {
	t.Parallel()

	valid := fixtureRootObservation{
		SchemaVersion:  1,
		ParentDevice:   7,
		ParentInode:    11,
		ParentOwnerUID: 1000,
		ParentMode:     0o700,
		RootDevice:     7,
		RootInode:      13,
		OwnerUID:       1000,
		Mode:           0o700,
	}
	first, err := computeFixtureEmptyDigest(valid)
	if err != nil || !isLowerHex(first, 64) {
		t.Fatalf("computeFixtureEmptyDigest = %q/%v", first, err)
	}
	mutations := []func(*fixtureRootObservation){
		func(value *fixtureRootObservation) {
			value.ParentDevice++
			value.RootDevice++
		},
		func(value *fixtureRootObservation) { value.ParentInode++ },
		func(value *fixtureRootObservation) { value.ParentMode = 0o500 },
		func(value *fixtureRootObservation) { value.RootInode++ },
		func(value *fixtureRootObservation) {
			value.OwnerUID++
			value.ParentOwnerUID++
		},
	}
	for index, mutate := range mutations {
		candidate := valid
		mutate(&candidate)
		digest, err := computeFixtureEmptyDigest(candidate)
		if err != nil {
			t.Fatalf("mutation %d returned error: %v", index, err)
		}
		if digest == first {
			t.Fatalf("mutation %d did not change digest", index)
		}
	}
	for name, candidate := range map[string]fixtureRootObservation{
		"zero schema": func() fixtureRootObservation { value := valid; value.SchemaVersion = 0; return value }(),
		"cross device": func() fixtureRootObservation {
			value := valid
			value.RootDevice++
			return value
		}(),
		"writable parent": func() fixtureRootObservation {
			value := valid
			value.ParentMode = 0o770
			return value
		}(),
		"loose mode": func() fixtureRootObservation { value := valid; value.Mode = 0o755; return value }(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := computeFixtureEmptyDigest(candidate); err == nil {
				t.Fatal("accepted invalid fixture-root observation")
			}
		})
	}
}
