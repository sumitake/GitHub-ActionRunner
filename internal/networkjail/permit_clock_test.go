package networkjail

import "testing"

func TestParseBootIDIsCanonical(t *testing.T) {
	const canonical = "00112233-4455-6677-8899-aabbccddeeff"
	boot, err := ParseBootID(canonical)
	if err != nil {
		t.Fatalf("ParseBootID: %v", err)
	}
	if got := boot.String(); got != canonical {
		t.Fatalf("BootID.String = %q, want %q", got, canonical)
	}
	for _, invalid := range []string{
		"",
		"00112233445566778899aabbccddeeff",
		"00112233-4455-6677-8899-AABBCCDDEEFF",
		"00000000-0000-0000-0000-000000000000",
		canonical + "\n",
	} {
		if _, err := ParseBootID(invalid); err == nil {
			t.Fatalf("ParseBootID(%q) = nil error", invalid)
		}
	}
}
