//go:build linux

package fleetfence

import (
	"fmt"
	"testing"
)

func TestParseLinuxIdentityDocuments(t *testing.T) {
	t.Parallel()

	bootID := "01234567" + "-89ab-cdef-0123-" + "456789abcdef"
	boot := []byte(bootID + "\n")
	if value, err := parseLinuxBootID(boot); err != nil ||
		value != bootID {
		t.Fatalf("parseLinuxBootID = %q, %v", value, err)
	}
	fields := make([]any, 20)
	for index := range fields {
		fields[index] = 1
	}
	fields[0] = "S"
	fields[19] = 987654
	document := []byte(fmt.Sprintf(
		"1234 (command with ) parenthesis) %v %v %v %v %v %v %v %v %v %v %v %v %v %v %v %v %v %v %v %v\n",
		fields...,
	))
	if value, err := parseLinuxProcessStart(document, 1234); err != nil ||
		value != "987654" {
		t.Fatalf("parseLinuxProcessStart = %q, %v", value, err)
	}
}
