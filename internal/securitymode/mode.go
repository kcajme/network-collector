// Package securitymode enforces the common production transport policy.
package securitymode

import (
	"fmt"
	"strings"
)

func ValidateTransport(mode string, insecure bool) error {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "production":
		if insecure {
			return fmt.Errorf("production security requires verified TLS; insecure transport requires explicit security_mode: permissive")
		}
	case "permissive":
	default:
		return fmt.Errorf("security_mode must be production or permissive")
	}
	return nil
}
