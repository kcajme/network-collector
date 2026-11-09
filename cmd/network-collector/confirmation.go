package main

import (
	"fmt"
	"regexp"
	"strings"
)

func validateConfirmation(step StepConfig) error {
	c := step.Confirmation
	if c == nil {
		return nil
	}
	if strings.TrimSpace(step.Command) == "" || step.NETCONF != nil || step.Ensure != nil || step.Facts != nil || step.GNMISubscribe != nil || step.Approval != nil || step.Repeat != nil || step.Foreach != nil || step.Block != nil || step.Parallel != nil || step.Use != "" || step.Retry != nil || step.SSHProbe != nil || step.RegisterInteger != nil {
		return fmt.Errorf("confirmation requires an SSH cmd without retry, other transports, or control fields")
	}
	if strings.TrimSpace(c.Prompt) == "" || strings.Contains(c.Prompt, "{{") {
		return fmt.Errorf("confirmation.prompt requires a static nonempty regex")
	}
	if compiled, err := regexp.Compile(c.Prompt); err != nil || compiled.MatchString("") {
		return fmt.Errorf("confirmation.prompt must be valid and must not match empty output")
	}
	switch c.Response {
	case "yes", "no", "y", "n":
	default:
		return fmt.Errorf("confirmation.response must be yes, no, y, or n")
	}
	return nil
}

type sshConfirmationExecutor interface {
	ExecuteWithConfirmation(string, string, string, bool) (string, error)
}

func executeSSHConfirmation(executor sshEnsureCommandExecutor, step StepConfig, command string) (string, error) {
	interactive, ok := executor.(sshConfirmationExecutor)
	if !ok {
		return "", fmt.Errorf("SSH executor does not support confirmation prompts")
	}
	return interactive.ExecuteWithConfirmation(command, step.Confirmation.Prompt, step.Confirmation.Response, shouldReturnToPrompt(step.ReturnToPrompt))
}
