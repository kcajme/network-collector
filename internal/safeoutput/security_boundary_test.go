package safeoutput

import (
	"bytes"
	"strings"
	"testing"
)

func TestVendorCredentialForms(t *testing.T) {
	for _, input := range []string{
		"enable secret 4 SYNTHETIC_CREDENTIAL", "enable secret 6 SYNTHETIC_CREDENTIAL", "enable secret 8 SYNTHETIC_CREDENTIAL",
		"tacacs-server key 7 SYNTHETIC_CREDENTIAL", "radius-server key 7 SYNTHETIC_CREDENTIAL", " key 7 SYNTHETIC_CREDENTIAL",
		"snmp-server user probe group v3 auth sha SYNTHETIC_CREDENTIAL priv aes 128 SYNTHETIC_CREDENTIAL",
		"crypto isakmp key SYNTHETIC_CREDENTIAL address 192.0.2.1", "pre-shared-key local 6 SYNTHETIC_CREDENTIAL",
		"ntp authentication-key 1 md5 SYNTHETIC_CREDENTIAL"} {
		if got := Sanitize(input); strings.Contains(got, "SYNTHETIC_CREDENTIAL") {
			t.Errorf("credential retained: %q", got)
		}
	}
	if got := Sanitize("interface Ethernet1\ndescription uplink\n"); got != "interface Ethernet1\ndescription uplink\n" {
		t.Fatal(got)
	}
}
func TestTranscriptNeverWritesChannelContents(t *testing.T) {
	var output bytes.Buffer
	w := NewTranscriptWriter(&output)
	for _, part := range []string{"pass", "word: SYNTHETIC_", "CREDENTIAL\n", "\x1b[2J"} {
		if n, err := w.Write([]byte(part)); err != nil || n != len(part) {
			t.Fatalf("write %d %v", n, err)
		}
	}
	if strings.Contains(output.String(), "CREDENTIAL") || strings.Contains(output.String(), "\x1b") || !strings.Contains(output.String(), "channel data omitted") {
		t.Fatal(output.String())
	}
}
