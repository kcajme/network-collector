package sshprofile

import (
	"errors"
	"strings"
	"testing"
)

func withProbe(t *testing.T, results map[string][]string) {
	t.Helper()
	previous := Probe
	Probe = func(query string) []string { return results[query] }
	t.Cleanup(func() { Probe = previous })
}

func argValue(args []string, option string) (string, bool) {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-o" && strings.HasPrefix(args[i+1], option+"=") {
			return strings.TrimPrefix(args[i+1], option+"="), true
		}
	}
	return "", false
}

// An unknown algorithm name makes ssh refuse to start, so a client that
// cannot be probed (or is old) must get only the baseline names.
func TestArgsUseOnlyBaselineWhenClientCannotBeProbed(t *testing.T) {
	withProbe(t, nil)
	for _, profile := range []string{"modern", "legacy"} {
		args := Args(profile)
		kex, _ := argValue(args, "KexAlgorithms")
		if strings.Contains(kex, "mlkem") || strings.Contains(kex, "sntrup") {
			t.Fatalf("%s offered unprobed PQ kex: %s", profile, kex)
		}
		if _, ok := argValue(args, "HostKeyAlgorithms"); ok {
			t.Fatalf("%s set HostKeyAlgorithms without confirming ssh-rsa support", profile)
		}
	}
}

func TestModernPrefersSupportedPostQuantumHybrids(t *testing.T) {
	withProbe(t, map[string][]string{"kex": {"curve25519-sha256", "sntrup761x25519-sha512@openssh.com", "mlkem768x25519-sha256"}, "key": {"ssh-rsa"}})
	args := Args("modern")
	kex, _ := argValue(args, "KexAlgorithms")
	if !strings.HasPrefix(kex, "mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256") {
		t.Fatalf("PQ hybrids not preferred in supported order: %s", kex)
	}
	if strings.Contains(kex, "sntrup761x25519-sha512,") {
		t.Fatalf("offered a PQ name the client did not report: %s", kex)
	}
	if _, ok := argValue(args, "HostKeyAlgorithms"); ok || strings.Contains(kex, "sha1") {
		t.Fatalf("modern enabled legacy algorithms: %v", args)
	}
}

func TestLegacyReenablesSHA1RSAHostKeys(t *testing.T) {
	withProbe(t, map[string][]string{"key": {"ssh-ed25519", "ssh-rsa"}})
	for _, profile := range []string{"legacy", "compatibility"} {
		args := Args(profile)
		if value, ok := argValue(args, "HostKeyAlgorithms"); !ok || value != "+ssh-rsa" {
			t.Fatalf("%s: HostKeyAlgorithms = %q, want +ssh-rsa", profile, value)
		}
		kex, _ := argValue(args, "KexAlgorithms")
		ciphers, _ := argValue(args, "Ciphers")
		if !strings.Contains(kex, "diffie-hellman-group14-sha1") || !strings.Contains(ciphers, "aes128-cbc") {
			t.Fatalf("%s missing legacy algorithms: %v", profile, args)
		}
	}
}

func TestValidateHost(t *testing.T) {
	for _, host := range []string{"192.0.2.1", "2001:db8::1", "router-1.example.net", "edge_01"} {
		if err := ValidateHost(host); err != nil {
			t.Errorf("%q rejected: %v", host, err)
		}
	}
	for _, host := range []string{"", "-oProxyCommand=bad", "user@router", "router;id", "router\n-o", strings.Repeat("a", 254)} {
		if ValidateHost(host) == nil {
			t.Errorf("%q accepted", host)
		}
	}
}

func TestIsNegotiationErrorIncludesHostKeyType(t *testing.T) {
	if !IsNegotiationError(errors.New("Unable to negotiate with 192.0.2.1 port 22: no matching host key type found. Their offer: ssh-rsa")) {
		t.Fatal("host key type mismatch should trigger the auto legacy retry")
	}
	if IsNegotiationError(errors.New("permission denied")) {
		t.Fatal("auth failure treated as negotiation error")
	}
}
