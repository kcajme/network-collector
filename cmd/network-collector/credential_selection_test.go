package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/gwoodwa1/network-collector/pkg/credentials"
)

func TestCredentialSelectionPromptsOnlyWhenAppropriate(t *testing.T) {
	for _, tc := range []struct {
		name, provider, user, password string
		force, terminal                bool
		want                           string
	}{
		{name: "terminal with no credentials", terminal: true, want: "interactive"},
		{name: "missing password", terminal: true, user: "alice", want: "interactive"},
		{name: "missing username", terminal: true, password: "secret", want: "interactive"},
		{name: "blank credentials", terminal: true, user: " ", password: "\t", want: "interactive"},
		{name: "environment complete", terminal: true, user: "alice", password: "secret", want: ""},
		{name: "explicit env missing", provider: "env", terminal: true, want: "interactive"},
		{name: "environment alias", provider: " ENVIRONMENT ", terminal: true, want: "interactive"},
		{name: "file provider", provider: "file", terminal: true, want: "file"},
		{name: "vault provider", provider: "vault", terminal: true, want: "vault"},
		{name: "onepassword provider", provider: "1password", terminal: true, want: "1password"},
		{name: "cyberark provider", provider: "cyberark", terminal: true, want: "cyberark"},
		{name: "unknown provider retains error", provider: "unknown", terminal: true, want: "unknown"},
		{name: "explicit interactive", provider: "interactive", want: "interactive"},
		{name: "automation missing credentials", want: ""},
		{name: "automation partial credentials", user: "alice", want: ""},
		{name: "forced credentials override environment", force: true, user: "alice", password: "secret", want: "interactive"},
		{name: "forced credentials override provider", force: true, provider: "file", want: "interactive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := selectCredentialProvider(tc.provider, tc.force, tc.terminal, tc.user, tc.password); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestAutomaticallySelectedPromptResolvesOnceWithoutLeakingPassword(t *testing.T) {
	t.Setenv("NET_USER", "")
	t.Setenv("NET_PASSWORD", "")
	providerType := selectCredentialProvider("", false, true, "", "")
	var output bytes.Buffer
	provider, err := credentials.NewProvider(credentials.ProviderConfig{Type: providerType}, strings.NewReader("alice\nsmoke-password\n"), &output)
	if err != nil {
		t.Fatal(err)
	}
	got, err := provider.Resolve(context.Background(), credentials.Target{Hostname: "selected inventory"})
	if err != nil || got.Username != "alice" || got.Password != "smoke-password" {
		t.Fatal("automatic prompt failed to resolve credentials")
	}
	if strings.Count(output.String(), "Username:") != 1 || strings.Contains(output.String(), "smoke-password") {
		t.Fatal("prompt repeated or leaked password")
	}
}
