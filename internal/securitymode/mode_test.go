package securitymode

import "testing"

func TestProductionDefaultsRejectInsecureTransports(t *testing.T) {
	for _, mode := range []string{"", "production", " Production "} {
		if err := ValidateTransport(mode, true); err == nil {
			t.Fatalf("%q allowed insecure transport", mode)
		}
		if err := ValidateTransport(mode, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := ValidateTransport("permissive", true); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTransport("prodution", false); err == nil {
		t.Fatal("invalid mode accepted")
	}
}
