package hostkey

import (
	"github.com/scrapli/scrapligo/driver/options"
	"github.com/scrapli/scrapligo/transport"
	"os"
	"path/filepath"
	"testing"

	"github.com/scrapli/scrapligo/util"
)

func TestPolicyDefaultsAndValidation(t *testing.T) {
	defaultPolicy, err := New("", "")
	if err != nil || defaultPolicy.Name() != "known_hosts" {
		t.Fatalf("unexpected default policy=%v error=%v", defaultPolicy, err)
	}
	if _, err := New("pinned", ""); err == nil {
		t.Fatal("pinned policy accepted without a pinned known_hosts file")
	}
	for _, name := range []string{"known_hosts", "pinned", "insecure"} {
		file := ""
		if name == "pinned" {
			file = "device.known_hosts"
		}
		selected, err := New(name, file)
		if err != nil {
			t.Fatalf("valid policy %q rejected: %v", name, err)
		}
		if _, err := selected.Apply([]util.Option{}); err != nil {
			t.Fatalf("policy %q could not be applied: %v", name, err)
		}
	}
	if _, err := New("accept-new", ""); err == nil {
		t.Fatal("unknown policy accepted")
	}
}

func TestVerifiedPolicyReenablesStrictKeyAtTransportBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"known_hosts", "pinned"} {
		policy, err := New(mode, path)
		if err != nil {
			t.Fatal(err)
		}
		opts, err := policy.Apply([]util.Option{options.WithAuthNoStrictKey()})
		if err != nil {
			t.Fatal(err)
		}
		args, err := transport.NewSSHArgs(opts...)
		if err != nil {
			t.Fatal(err)
		}
		if !args.StrictKey || args.KnownHostsFile != path {
			t.Fatalf("policy not enforced: %+v", args)
		}
	}
}
