package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

type fakeConfirmationExecutor struct {
	sequenceSSHEnsureExecutor
	calls int
	wait  bool
	err   error
}

func (e *fakeConfirmationExecutor) ExecuteWithConfirmation(command, prompt, response string, wait bool) (string, error) {
	e.calls++
	e.wait = wait
	e.commands = append(e.commands, command)
	return "This install operation will reload the system, continue?\n[confirmation response: yes]", e.err
}

func TestConfirmationWorkflowReachesProbeWithoutNormalPrompt(t *testing.T) {
	ctx, failed := interactionContext(t, map[string]string{"install_id": "58"})
	var log bytes.Buffer
	ctx.sessionLog = &log
	ctx.sessionOutput = true
	executor := &fakeConfirmationExecutor{}
	ctx.sshCommand = executor
	noPrompt := false
	step := StepConfig{Name: "activate", Command: "install activate id {{install_id}} sync", ReturnToPrompt: &noPrompt, Confirmation: &ConfirmationConfig{Prompt: `continue\?`, Response: "yes"}}
	if err := preflightDeviceVariables(DeviceConfig{Steps: []StepConfig{step}}, nil, ctx.variables); err != nil {
		t.Fatal(err)
	}
	if executeSteps(ctx, nil, []StepConfig{step, {Name: "after", Message: "Reached reboot wait"}}) || *failed || executor.calls != 1 || executor.wait {
		t.Fatal("activation did not finish promptly after confirmation")
	}
	if !strings.Contains(log.String(), "Reached reboot wait") || executor.commands[0] != "install activate id 58 sync" {
		t.Fatal(log.String())
	}
	executor.err = errors.New("question did not match")
	*failed = false
	log.Reset()
	if !executeSteps(ctx, nil, []StepConfig{step, {Message: "must-not-run"}}) || !*failed || strings.Contains(log.String(), "must-not-run") {
		t.Fatal("confirmation error was treated as an expected reboot")
	}
}

func TestConfirmationConfigRejectsRetriesAndExecutableResponses(t *testing.T) {
	for _, step := range []StepConfig{
		{Command: "activate", Retry: &RetryConfig{MaxAttempts: 2}, Confirmation: &ConfirmationConfig{Prompt: `continue\?`, Response: "yes"}},
		{Command: "activate", Confirmation: &ConfirmationConfig{Prompt: "[", Response: "yes"}},
		{Command: "activate", Confirmation: &ConfirmationConfig{Prompt: `continue\?`, Response: "yes\nreload"}},
		{Command: "activate", Confirmation: &ConfirmationConfig{Prompt: `{{device_output}}`, Response: "yes"}},
	} {
		if err := preflightDeviceVariables(DeviceConfig{Steps: []StepConfig{step}}, nil, nil); err == nil {
			t.Fatal("invalid confirmation config accepted")
		}
	}
}
