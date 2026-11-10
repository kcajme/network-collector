package hostkey

import (
	"fmt"
	"strings"

	"github.com/scrapli/scrapligo/driver/options"
	"github.com/scrapli/scrapligo/transport"
	"github.com/scrapli/scrapligo/util"
)

// Policy applies a reviewed SSH host-key verification policy to Scrapli
// transport options.
type Policy interface {
	Apply([]util.Option) ([]util.Option, error)
	Name() string
}

type policy struct {
	name           string
	knownHostsFile string
}

// New returns a strict host-key policy. Empty names default to known_hosts.
// The pinned policy uses an explicitly supplied one-entry OpenSSH
// known_hosts file, giving it the same mature verification path as the
// general known_hosts policy.
func New(name, knownHostsFile string) (Policy, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		name = "known_hosts"
	}
	knownHostsFile = strings.TrimSpace(knownHostsFile)
	switch name {
	case "known_hosts":
	case "pinned":
		if knownHostsFile == "" {
			return nil, fmt.Errorf("pinned host-key policy requires known_hosts_file containing the pinned host key")
		}
	case "insecure":
	default:
		return nil, fmt.Errorf("unsupported host-key policy %q", name)
	}
	return policy{name: name, knownHostsFile: knownHostsFile}, nil
}

func (value policy) Name() string {
	return value.name
}

func (value policy) Apply(existing []util.Option) ([]util.Option, error) {
	result := append([]util.Option(nil), existing...)
	switch value.name {
	case "insecure":
		return append(result, options.WithAuthNoStrictKey()), nil
	case "known_hosts", "pinned":
		result = append(result, func(o interface{}) error {
			args, ok := o.(*transport.SSHArgs)
			if !ok {
				return util.ErrIgnoredOption
			}
			args.StrictKey = true
			return nil
		})
		if value.name == "pinned" {
			// Only the pinned file may vouch for the host. scrapligo already
			// passes -F /dev/null, so no config can add a KnownHostsCommand;
			// passing KnownHostsCommand=none here would also make OpenSSH
			// older than 8.5 (RHEL 8, Ubuntu 20.04) reject the command line.
			result = append(result, options.WithSystemTransportOpenArgs([]string{"-o", "GlobalKnownHostsFile=/dev/null"}))
		}

		if value.knownHostsFile != "" {
			return append(result, options.WithSSHKnownHostsFile(value.knownHostsFile)), nil
		}
		return append(result, options.WithSSHKnownHostsFileSystem()), nil
	default:
		return nil, fmt.Errorf("unsupported host-key policy %q", value.name)
	}
}
