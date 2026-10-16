package testenv

import (
	"reflect"
	"testing"

	"github.com/sumitake/portable-ghar/internal/canary"
)

func TestCanaryToolInventoryMatchesCurrentProxyMatrix(t *testing.T) {
	if !reflect.DeepEqual(canary.RequiredTools(), requiredWorkflowToolProbeIDs[:]) {
		t.Fatal("canary and target proxy-sensitive tool inventories differ")
	}
}
