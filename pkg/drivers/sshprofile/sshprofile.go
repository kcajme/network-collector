// Package sshprofile holds the SSH algorithm and target-host policy shared by
// every driver that runs the system OpenSSH client (CLI over SSH and
// NETCONF over SSH), so a security profile means the same thing whichever
// protocol carries the session.
package sshprofile

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Normalize validates a security profile name. Empty means "modern".
func Normalize(profile string) (string, error) {
	profile = strings.ToLower(strings.TrimSpace(profile))
	if profile == "" {
		return "modern", nil
	}
	switch profile {
	case "compatibility", "auto", "modern", "legacy":
		return profile, nil
	}
	return "", fmt.Errorf("unsupported SSH security profile %q", profile)
}

// IsNegotiationError reports whether err looks like an SSH algorithm
// negotiation failure, which is the only failure "auto" retries as legacy.
func IsNegotiationError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	markers := []string{"no common algorithm", "no common algo", "no matching key exchange", "no matching cipher", "no matching host key type", "unable to negotiate", "no common key exchange", "no common cipher"}
	for _, marker := range markers {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

var hostPattern = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$`)

// ValidateHost accepts only an IP address or a plain hostname, so a target
// can never be parsed by ssh as an option, a user@host form, or a command.
func ValidateHost(host string) error {
	host = strings.TrimSpace(host)
	if net.ParseIP(host) != nil {
		return nil
	}
	if len(host) == 0 || len(host) > 253 || host[0] == '-' || !hostPattern.MatchString(host) {
		return fmt.Errorf("invalid SSH host: expected an IP address or hostname")
	}
	return nil
}

// Baseline lists use only names OpenSSH has recognised since 7.4, so they
// are accepted by every supported client (RHEL 8 ships 8.0, Ubuntu 20.04
// ships 8.2). ssh exits with "Bad SSH2 ..." on any name it does not know,
// which is why newer algorithms are added only after probing the client.
const (
	baseKex     = "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512"
	baseCiphers = "chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr"
	baseMACs    = "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512"

	legacyKex     = "diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1"
	legacyCiphers = "aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc"
	legacyMACs    = "hmac-sha1"
)

// Post-quantum hybrid key exchanges, in the order current OpenSSH prefers
// them. Each is offered first when the local client supports it.
var pqKex = []string{"mlkem768x25519-sha256", "sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com"}

// Probe lists what the local ssh client supports for a `ssh -Q` query
// ("kex", "key"). It returns nil when the client cannot be queried.
// Replaceable in tests.
var Probe = probeSystemSSH

var (
	probeMu    sync.Mutex
	probeCache = map[string][]string{}
)

func probeSystemSSH(query string) []string {
	// The argv is fixed: only these read-only capability queries ever run.
	if query != "kex" && query != "key" {
		return nil
	}
	path, err := exec.LookPath("ssh")
	if err != nil {
		return nil
	}
	key := path + "\x00" + query
	probeMu.Lock()
	defer probeMu.Unlock()
	if cached, ok := probeCache[key]; ok {
		return cached
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, path, "-Q", query)
	cmd.Stdout = &out
	var names []string
	if cmd.Run() == nil {
		names = strings.Fields(out.String())
	}
	probeCache[key] = names
	return names
}

func supported(query string) map[string]bool {
	set := map[string]bool{}
	for _, name := range Probe(query) {
		set[name] = true
	}
	return set
}

// Args returns the ssh -o arguments that pin the algorithms for profile.
// "auto" is resolved by the caller into "modern" then "legacy"; any other
// non-legacy value gets the modern set.
func Args(profile string) []string {
	kexSupport := supported("kex")
	var kex []string
	for _, name := range pqKex {
		if kexSupport[name] {
			kex = append(kex, name)
		}
	}
	kex = append(kex, baseKex)
	ciphers, macs := baseCiphers, baseMACs
	var hostKeyArgs []string
	if profile == "legacy" || profile == "compatibility" {
		kex = append(kex, legacyKex)
		ciphers += "," + legacyCiphers
		macs += "," + legacyMACs
		// OpenSSH 8.8+ no longer offers SHA-1 RSA host-key signatures, which
		// many older devices still require. "+" keeps the client defaults
		// and only appends ssh-rsa, when the client still knows it.
		if supported("key")["ssh-rsa"] {
			hostKeyArgs = []string{"-o", "HostKeyAlgorithms=+ssh-rsa"}
		}
	}
	args := []string{"-o", "KexAlgorithms=" + strings.Join(kex, ","), "-o", "Ciphers=" + ciphers, "-o", "MACs=" + macs}
	return append(args, hostKeyArgs...)
}
