package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// validateRegisterInteger deliberately permits only ordinary SSH capture steps.
// Bounds are explicit and cannot be supplied by runtime device data.
func validateRegisterInteger(step StepConfig) (*regexp.Regexp, error) {
	c := step.RegisterInteger
	if c == nil {
		return nil, nil
	}
	if strings.TrimSpace(step.Register) == "" || strings.TrimSpace(step.Command) == "" ||
		step.NETCONF != nil || step.Ensure != nil || step.Facts != nil || step.GNMISubscribe != nil ||
		step.Approval != nil || step.Repeat != nil || step.Foreach != nil || step.Block != nil ||
		step.Parallel != nil || strings.TrimSpace(step.Use) != "" || step.Retry != nil || step.SSHProbe != nil {
		return nil, fmt.Errorf("register_integer requires register and an SSH cmd without retry or control fields")
	}
	if c.Min == nil || c.Max == nil || *c.Min < 0 || *c.Max < *c.Min || *c.Max > 2147483647 {
		return nil, fmt.Errorf("register_integer requires explicit bounds 0 <= min <= max <= 2147483647")
	}
	re, err := regexp.Compile(c.Pattern)
	if err != nil || re.NumSubexp() != 1 {
		return nil, fmt.Errorf("register_integer.pattern must be a valid regex with exactly one capture group")
	}
	return re, nil
}

func captureRegisteredInteger(step StepConfig, output string) (string, error) {
	re, err := validateRegisterInteger(step)
	if err != nil {
		return "", err
	}
	if re == nil {
		return "", fmt.Errorf("register_integer is required")
	}
	matches := re.FindAllStringSubmatch(output, 2)
	if len(matches) != 1 {
		return "", fmt.Errorf("register_integer requires exactly one matching value")
	}
	raw := matches[0][1]
	if len(raw) == 0 || len(raw) > 10 {
		return "", fmt.Errorf("register_integer requires 1–10 ASCII decimal digits")
	}
	for _, ch := range raw {
		if ch < '0' || ch > '9' {
			return "", fmt.Errorf("register_integer rejects non-decimal data")
		}
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < *step.RegisterInteger.Min || value > *step.RegisterInteger.Max {
		return "", fmt.Errorf("register_integer value is outside configured bounds")
	}
	return strconv.FormatInt(value, 10), nil
}
