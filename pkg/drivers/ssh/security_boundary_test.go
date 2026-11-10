package ssh

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPlatformAndHostRejectedBeforeTransport(t *testing.T) {
	for _, name := range []string{"./custom.yaml", "https://example.invalid/platform", "missing", "cisco_iosxe.yaml"} {
		c := NewClient()
		called := false
		c.connectProfile = func(_, _, _, _, _, _ string) error { called = true; return nil }
		if err := c.Connect("192.0.2.1", "synthetic", "synthetic", name); err == nil || called {
			t.Fatalf("platform %q reached transport", name)
		}
	}
	for _, host := range []string{"-oProxyCommand=bad", "router\n-o", "user@router", "router;command"} {
		c := NewClient()
		called := false
		c.connectProfile = func(_, _, _, _, _, _ string) error { called = true; return nil }
		if err := c.Connect(host, "synthetic", "synthetic", "cisco_iosxe"); err == nil || called {
			t.Fatalf("host %q reached transport", host)
		}
	}
	c := NewClient()
	c.connectProfile = func(_, _, _, name, _, _ string) error {
		if name != "cisco_iosxe" {
			t.Fatalf("alias resolved to %q", name)
		}
		return nil
	}
	if err := c.Connect("192.0.2.1", "synthetic", "synthetic", "cisco_ios"); err != nil {
		t.Fatal(err)
	}
}

// Capture the actual subprocess argv, including scrapligo's final transformations.
func TestSystemSSHArgvEnforcesAlgorithmAndPinnedPolicy(t *testing.T) {
	dir := t.TempDir()
	capture := filepath.Join(dir, "argv")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$SSH_TEST_CAPTURE\"\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	known := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(known, nil, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("SSH_TEST_CAPTURE", capture)
	for _, profile := range []string{"modern", "legacy", "compatibility"} {
		t.Run(profile, func(t *testing.T) {
			_ = os.Remove(capture)
			c := NewClient(WithSecurityProfile(profile), WithHostKeyPolicy("pinned", known), WithConnectionTimeout(time.Second), WithOperationTimeout(time.Second))
			if err := c.Connect("192.0.2.1", "synthetic", "synthetic", "cisco_iosxe"); err == nil {
				t.Fatal("fake ssh unexpectedly connected")
			}
			content, err := os.ReadFile(capture)
			if err != nil {
				t.Fatal(err)
			}
			argv := string(content)
			for _, required := range []string{"StrictHostKeyChecking=yes", "GlobalKnownHostsFile=/dev/null", "UserKnownHostsFile=" + known} {
				if !strings.Contains(argv, required+"\n") {
					t.Errorf("missing %q in argv %q", required, argv)
				}
			}
			// -F /dev/null is what stops any ssh_config from adding a
			// KnownHostsCommand or other verification source.
			if !strings.Contains(argv, "-F\n/dev/null\n") {
				t.Errorf("missing -F /dev/null in argv %q", argv)
			}
			if strings.Contains(argv, "KnownHostsCommand") {
				t.Errorf("KnownHostsCommand breaks OpenSSH < 8.5: %q", argv)
			}
			for _, arg := range algorithmArgs(profile) {
				if arg != "-o" && !strings.Contains(argv, arg+"\n") {
					t.Errorf("missing algorithm constraint %q", arg)
				}
			}
			if profile == "modern" && (strings.Contains(argv, "group1-sha1") || strings.Contains(argv, "aes128-cbc")) {
				t.Fatal("modern enables legacy algorithms")
			}
		})
	}
}
