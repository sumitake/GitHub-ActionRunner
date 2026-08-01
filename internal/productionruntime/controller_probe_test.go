package productionruntime

import (
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/controller"
)

func TestParseControllerPolicyAcceptsOnlyCanonicalClosedStatus(t *testing.T) {
	digest := strings.Repeat("a", 64)
	tests := []struct {
		name     string
		document string
		want     bool
	}{
		{
			name: "disabled",
			document: `{"mode":"disabled","epoch":7,"digest":"` +
				digest + `","capacity":0}` + "\n",
			want: true,
		},
		{
			name: "enabled",
			document: `{"mode":"enabled","epoch":8,"digest":"` +
				digest + `","capacity":4}` + "\n",
			want: true,
		},
		{
			name: "disabled nonzero capacity",
			document: `{"mode":"disabled","epoch":7,"digest":"` +
				digest + `","capacity":1}` + "\n",
		},
		{
			name: "unknown field",
			document: `{"mode":"disabled","epoch":7,"digest":"` +
				digest + `","capacity":0,"extra":true}` + "\n",
		},
		{
			name: "missing newline",
			document: `{"mode":"disabled","epoch":7,"digest":"` +
				digest + `","capacity":0}`,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			var status controller.PolicyStatus
			if got := parseControllerPolicy(
				[]byte(test.document),
				&status,
			); got != test.want {
				t.Fatalf("parseControllerPolicy() = %t, want %t", got, test.want)
			}
		})
	}
}
