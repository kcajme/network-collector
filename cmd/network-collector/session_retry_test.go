package main

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

func TestCheckpointRetriesFailedStepWithoutReplayingSuccess(t *testing.T) {
	capture := integerCaptureStep()
	steps := []StepConfig{capture, {Name: "activate", Command: "install activate id {{install_id}} sync"}, {Name: "verify", Command: "show install request"}}
	ctx, failed := interactionContext(t, map[string]string{})
	checkpoint := &hostCheckpoint{}
	ctx.checkpoint = checkpoint
	executor := &sequenceSSHEnsureExecutor{outputs: []string{"Install operation 42\n", ""}, errors: []error{nil, errors.New("connection lost")}}
	ctx.sshCommand = executor
	if !executeSteps(ctx, nil, steps) || !*failed || len(executor.commands) != 2 {
		t.Fatal("failure did not stop the host")
	}
	if len(checkpoint.remaining) != 2 || checkpoint.remaining[0].Name != "activate" || checkpoint.before["install_id"] != "42" {
		t.Fatalf("wrong checkpoint: %+v", checkpoint)
	}
	// Simulate a user changing remote state and explicitly confirming another attempt.
	retried, retryFailed := interactionContext(t, cloneVariables(checkpoint.before))
	retried.checkpoint = checkpoint
	success := &sequenceSSHEnsureExecutor{outputs: []string{"activated", "verified"}}
	retried.sshCommand = success
	if executeSteps(retried, nil, checkpoint.remaining) || *retryFailed {
		t.Fatal("retry failed")
	}
	if len(success.commands) != 2 || success.commands[0] != "install activate id 42 sync" || success.commands[1] != "show install request" {
		t.Fatalf("replayed or skipped the wrong steps: %v", success.commands)
	}
	if checkpoint.remaining != nil {
		t.Fatal("successful retry retained failed checkpoint")
	}
}

func TestCheckpointStopsAtValidationFailureAndPreservesInput(t *testing.T) {
	steps := []StepConfig{{Name: "check", Command: "show state", Register: "state", Validation: &ValidationConfig{Extractor: "regex", Pattern: `state: (\w+)`, Condition: "eq", Expected: "ready", ExpectedType: "string"}}, {Command: "must-not-run"}}
	ctx, failed := interactionContext(t, map[string]string{"state": "previous"})
	ctx.checkpoint = &hostCheckpoint{}
	executor := &sequenceSSHEnsureExecutor{outputs: []string{"state: broken"}}
	ctx.sshCommand = executor
	if !executeSteps(ctx, nil, steps) || !*failed || len(executor.commands) != 1 {
		t.Fatal("validation failure continued host")
	}
	if ctx.checkpoint.before["state"] != "previous" {
		t.Fatal("checkpoint captured partially failed outputs")
	}
}

func TestSessionRemainsOpenAndSuccessfulRetryUpdatesResult(t *testing.T) {
	device := DeviceConfig{Hostname: "host", IP: "1"}
	key := variableScopeKey(device.Hostname, device.IP)
	display := newProgressDisplay(io.Discard, []DeviceConfig{device})
	checkpoint := &hostCheckpoint{remaining: []StepConfig{{Name: "failed", Command: "retry"}}, before: map[string]string{"id": "42"}}
	results := []deviceRunResult{{index: 0, hostname: "host", ip: "1", failed: true}}
	done := make(chan []deviceRunResult, 1)
	retried := make(chan struct{}, 1)
	go func() {
		done <- waitForSessionActions(context.Background(), display, []DeviceConfig{device}, map[string]*hostCheckpoint{key: checkpoint}, results, false, func(index int, device DeviceConfig, vars map[string]string) deviceRunResult {
			if len(device.Steps) != 1 || vars["id"] != "42" {
				panic("bad retry input")
			}
			checkpoint.remaining = nil
			retried <- struct{}{}
			return deviceRunResult{index: index, hostname: device.Hostname, ip: device.IP}
		})
	}()
	// Even with no work executing, the session must not finish until explicitly quit.
	select {
	case <-done:
		t.Fatal("session exited without user action")
	case <-time.After(20 * time.Millisecond):
	}
	display.requests <- sessionRequest{host: key}
	select {
	case <-retried:
	case <-time.After(time.Second):
		t.Fatal("retry was not dispatched")
	}
	select {
	case <-done:
		t.Fatal("successful retry exited the app")
	case <-time.After(20 * time.Millisecond):
	}
	display.requests <- sessionRequest{quit: true}
	select {
	case got := <-done:
		if len(got) != 1 || got[0].failed {
			t.Fatal("retry result remained failed")
		}
	case <-time.After(time.Second):
		t.Fatal("idle quit did not exit")
	}
}

func TestNestedRetryBoundaryIsExplicit(t *testing.T) {
	if retryBoundary(StepConfig{Command: "show version"}) != "" {
		t.Fatal("plain step cannot retry")
	}
	if retryBoundary(StepConfig{Repeat: &RepeatConfig{}}) == "" || retryBoundary(StepConfig{Use: "workflow"}) == "" {
		t.Fatal("nested failure could replay enclosing operations")
	}
}

// Checkpoint execution runs one top-level step at a time. It must retain the
// same journal identities as ordinary execution, including after a retry.
func TestCheckpointPreservesJournalIdentitiesAcrossRetry(t *testing.T) {
	steps := []StepConfig{{Name: "same", Command: "first"}, {Name: "same", Command: "second"}, {Command: "third"}}
	expectedCtx, _ := interactionContext(t, map[string]string{})
	expectedCtx.executionPath = "device:0"
	expectedCtx.sshCommand = &sequenceSSHEnsureExecutor{outputs: []string{"ok", "ok", "ok"}}
	expectedDir := t.TempDir()
	expectedCtx.journal, _ = newRunJournal(expectedDir)
	executeSteps(expectedCtx, nil, steps)
	expected, err := completedJournalEntries(expectedDir)
	if err != nil || len(expected) != 3 {
		t.Fatalf("baseline identities: %v %v", expected, err)
	}

	ctx, failed := interactionContext(t, map[string]string{})
	ctx.executionPath = "device:0"
	ctx.checkpoint = &hostCheckpoint{}
	ctx.sshCommand = &sequenceSSHEnsureExecutor{outputs: []string{"ok", ""}, errors: []error{nil, errors.New("disconnected")}}
	dir := t.TempDir()
	ctx.journal, _ = newRunJournal(dir)
	if !executeSteps(ctx, nil, steps) || !*failed {
		t.Fatal("expected failed second step")
	}
	if ctx.checkpoint.startIndex != 1 {
		t.Fatalf("checkpoint index: %d", ctx.checkpoint.startIndex)
	}
	retryCtx, retryFailed := interactionContext(t, cloneVariables(ctx.checkpoint.before))
	retryCtx.executionPath = "device:0"
	retryCtx.checkpoint = ctx.checkpoint
	retryCtx.journal = ctx.journal
	retryCtx.sshCommand = &sequenceSSHEnsureExecutor{outputs: []string{"ok", "ok"}}
	if executeSteps(retryCtx, nil, ctx.checkpoint.remaining) || *retryFailed {
		t.Fatal("retry failed")
	}
	actual, err := completedJournalEntries(dir)
	if err != nil || len(actual) != 3 {
		t.Fatalf("checkpoint identities: %v %v", actual, err)
	}
	for key, digest := range expected {
		if actual[key] != digest {
			t.Fatalf("checkpoint changed journal identity %s", key)
		}
	}
}
