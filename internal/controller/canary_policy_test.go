package controller

import (
	"context"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
)

func TestCanaryPolicyPreviewMatchesTheActualOperatorTransition(t *testing.T) {
	f := newRuntimeServiceFixture(t, nil, nil, nil)
	if err := f.service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	original := cloneAcquisitionPolicy(f.service.enabledTemplate)
	preview, err := CanaryPolicy(f.service.enabledTemplate, "portable-ghar")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := AcquisitionPolicyDigest(preview)
	if err != nil {
		t.Fatal(err)
	}
	status, err := f.service.SetAcquisition(context.Background(), AcquisitionChange{Set: AcquisitionCanaryOnly, Expected: AcquisitionDisabled, EligibleScaleSet: "portable-ghar"})
	if err != nil {
		t.Fatal(err)
	}
	if status.Digest != hex.EncodeToString(digest[:]) || preview.Mode != AcquisitionCanaryOnly || preview.MaxCapacity != 1 || !reflect.DeepEqual(preview.EligibleScaleSets, []string{"portable-ghar"}) {
		t.Fatal("preview differs from actual canary policy")
	}
	preview.RepositoryPolicies[0].Alias = "changed"
	if !reflect.DeepEqual(original, f.service.enabledTemplate) {
		t.Fatal("preview mutated template")
	}
	for _, name := range []string{"", "bad\nname"} {
		if _, err := CanaryPolicy(original, name); !errors.Is(err, ErrAdminConflict) {
			t.Fatal("invalid canary label accepted")
		}
	}
}
