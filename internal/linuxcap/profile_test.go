package linuxcap

import (
	"strings"
	"testing"
)

func TestParseStatusRequiresCanonicalCompleteCapabilityProfile(t *testing.T) {
	document := []byte(
		"Name:\tportable-ghar\n" +
			"CapInh:\t0000000000000000\n" +
			"CapPrm:\t0000000000001000\n" +
			"CapEff:\t0000000000001000\n" +
			"CapBnd:\t0000000000001000\n" +
			"CapAmb:\t0000000000000000\n" +
			"Seccomp:\t2\n",
	)
	got, err := ParseStatus(document)
	if err != nil {
		t.Fatalf("ParseStatus: %v", err)
	}
	want := Wire{
		Effective:   "0000000000001000",
		Permitted:   "0000000000001000",
		Inheritable: "0000000000000000",
		Bounding:    "0000000000001000",
		Ambient:     "0000000000000000",
	}
	if got != want {
		t.Fatalf("ParseStatus=%+v want=%+v", got, want)
	}
}

func TestParseStatusRejectsMalformedOrAmbiguousCapabilityProfile(t *testing.T) {
	valid := "CapInh:\t0000000000000000\n" +
		"CapPrm:\t0000000000001000\n" +
		"CapEff:\t0000000000001000\n" +
		"CapBnd:\t0000000000001000\n" +
		"CapAmb:\t0000000000000000\n"
	tests := map[string]string{
		"missing": strings.Replace(
			valid,
			"CapAmb:\t0000000000000000\n",
			"",
			1,
		),
		"duplicate": valid + "CapEff:\t0000000000001000\n",
		"unknown":   valid + "CapFoo:\t0000000000000000\n",
		"upper": strings.Replace(
			valid,
			"0000000000001000",
			"000000000000A000",
			1,
		),
		"short": strings.Replace(
			valid,
			"0000000000001000",
			"1000",
			1,
		),
		"wide": strings.Replace(
			valid,
			"0000000000001000",
			"00000000000001000",
			1,
		),
		"nonhex": strings.Replace(
			valid,
			"0000000000001000",
			"000000000000x000",
			1,
		),
		"wrong separator": strings.Replace(
			valid,
			"CapEff:\t",
			"CapEff: ",
			1,
		),
		"outside kernel domain": strings.Replace(
			valid,
			"0000000000001000",
			"8000000000001000",
			1,
		),
		"no final newline": strings.TrimSuffix(valid, "\n"),
	}
	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseStatus([]byte(document)); err == nil {
				t.Fatal("ParseStatus accepted invalid capability profile")
			}
		})
	}
}

func TestCapabilityProfilesAcceptOnlyEmptyOrNetAdminOnly(t *testing.T) {
	empty := Wire{
		Effective:   "0000000000000000",
		Permitted:   "0000000000000000",
		Inheritable: "0000000000000000",
		Bounding:    "0000000000000000",
		Ambient:     "0000000000000000",
	}
	netAdmin := empty
	netAdmin.Effective = "0000000000001000"
	netAdmin.Permitted = "0000000000001000"
	netAdmin.Bounding = "0000000000001000"

	if err := ValidateEmpty(empty); err != nil {
		t.Fatalf("ValidateEmpty: %v", err)
	}
	if err := ValidateNetAdmin(netAdmin); err != nil {
		t.Fatalf("ValidateNetAdmin: %v", err)
	}
	for name, wire := range map[string]Wire{
		"empty rejects net admin": netAdmin,
		"net admin rejects empty": empty,
		"effective extra": func() Wire {
			value := netAdmin
			value.Effective = "0000000000001001"
			return value
		}(),
		"permitted extra": func() Wire {
			value := netAdmin
			value.Permitted = "0000000000001001"
			return value
		}(),
		"bounding extra": func() Wire {
			value := netAdmin
			value.Bounding = "0000000000001001"
			return value
		}(),
		"inheritable nonzero": func() Wire {
			value := netAdmin
			value.Inheritable = "0000000000001000"
			return value
		}(),
		"ambient nonzero": func() Wire {
			value := netAdmin
			value.Ambient = "0000000000001000"
			return value
		}(),
		"noncanonical": func() Wire {
			value := netAdmin
			value.Effective = "1000"
			return value
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			if name == "empty rejects net admin" {
				if err := ValidateEmpty(wire); err == nil {
					t.Fatal("ValidateEmpty accepted NET_ADMIN")
				}
				return
			}
			if err := ValidateNetAdmin(wire); err == nil {
				t.Fatal("ValidateNetAdmin accepted invalid profile")
			}
		})
	}
}
