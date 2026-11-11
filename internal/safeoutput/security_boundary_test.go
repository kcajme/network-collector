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

// Each form below previously redacted a qualifier word (or nothing) and left
// the secret itself in the output.
func TestQualifiedAndVendorSpecificCredentialForms(t *testing.T) {
	for _, input := range []string{
		`pre-shared-key ascii-text "$9$SYNTHETIC_CREDENTIAL"; ## SECRET-DATA`,
		`pre-shared-key hexadecimal SYNTHETIC_CREDENTIAL;`,
		"username admin password encrypted SYNTHETIC_CREDENTIAL",
		"secret 10 $6$SYNTHETIC_CREDENTIAL",
		"username admin role network-admin secret sha512 $6$SYNTHETIC_CREDENTIAL",
		"ip ospf message-digest-key 1 md5 7 SYNTHETIC_CREDENTIAL",
		"ip ospf message-digest-key 1 md5 SYNTHETIC_CREDENTIAL",
		`privacy-key "$9$SYNTHETIC_CREDENTIAL";`,
		`authentication-password "SYNTHETIC_CREDENTIAL";`,
		"key config-key password-encrypt SYNTHETIC_CREDENTIAL",
		"<pre-shared-key><ascii-text>$9$SYNTHETIC_CREDENTIAL</ascii-text></pre-shared-key>",
		"<privacy-key>$9$SYNTHETIC_CREDENTIAL</privacy-key>",
		"<encrypted-password>$6$SYNTHETIC_CREDENTIAL</encrypted-password>",
	} {
		if got := Sanitize(input); strings.Contains(got, "SYNTHETIC_CREDENTIAL") {
			t.Errorf("credential retained: %q", got)
		}
	}
}

func TestBareKeyLeavesHarmlessCommandsReadable(t *testing.T) {
	for _, input := range []string{
		"key chain OSPF-KEYS",
		"crypto key generate rsa modulus 2048",
		"crypto key zeroize rsa",
		"crypto key pubkey-chain rsa",
	} {
		if got := Sanitize(input); got != input {
			t.Errorf("harmless line changed: %q -> %q", input, got)
		}
	}
	// A key-chain ID must not pull the next line's content into the match.
	if got := Sanitize("key 1\n key-string 7 SYNTHETIC_CREDENTIAL\n"); !strings.Contains(got, "key-string 7 [REDACTED]") {
		t.Errorf("key-string not redacted on its own line: %q", got)
	}
}

// Second review round. The key-chain line regressed in 2.0.3/2.0.4: the
// bare-key rule redacted the word "secret" and hid the value from the
// secret rule.
func TestFollowUpCredentialForms(t *testing.T) {
	for _, input := range []string{
		`set security authentication-key-chains key-chain kc key 0 secret "$9$SYNTHETIC_CREDENTIAL"`,
		`key 0 secret "$9$SYNTHETIC_CREDENTIAL"`,
		"isis password hmac-md5 encrypted SYNTHETIC_CREDENTIAL",
		"lsp-password hmac-md5 encrypted SYNTHETIC_CREDENTIAL",
		"wpa-psk ascii 0 SYNTHETIC_CREDENTIAL",
		`wpa-psk "SYNTHETIC_CREDENTIAL"`,
		"snmp-server host 192.0.2.5 traps version 2c SYNTHETIC_CREDENTIAL",
		"snmp-server host 192.0.2.5 vrf MGMT informs version 2c SYNTHETIC_CREDENTIAL udp-port 162",
		"snmp-server host 192.0.2.5 SYNTHETIC_CREDENTIAL",
		"cak 0 SYNTHETIC_CREDENTIAL",
		`set security macsec connectivity-association ca pre-shared-key cak "$9$SYNTHETIC_CREDENTIAL"`,
		"<cak>$9$SYNTHETIC_CREDENTIAL</cak>",
	} {
		if got := Sanitize(input); strings.Contains(got, "SYNTHETIC_CREDENTIAL") {
			t.Errorf("credential retained: %q", got)
		}
	}
}

func TestSyntaxWordsAfterKeywordsStayReadable(t *testing.T) {
	for _, input := range []string{
		"mka pre-shared-key key-chain MKA-KEYS",
		"set security macsec connectivity-association ca pre-shared-key ckn 0123ABCD",
	} {
		if got := Sanitize(input); got != input {
			t.Errorf("harmless line changed: %q -> %q", input, got)
		}
	}
	// A keyword at the end of a line must not redact the next line.
	if got := Sanitize("snmp community\ninterface Ethernet1\n"); got != "snmp community\ninterface Ethernet1\n" {
		t.Errorf("redaction crossed a line boundary: %q", got)
	}
}
