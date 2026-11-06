package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sshdriver "github.com/gwoodwa1/network-collector/pkg/drivers/ssh"
)

func TestSessionTranscriptDefaultsToResponsesAndHonorsOptOut(t *testing.T) {
	for _, tc := range []struct {
		yaml string
		want bool
	}{{"name_playbook: test\n", true}, {"output:\n  session_transcript: false\n", false}} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(tc.yaml), 0600); err != nil {
			t.Fatal(err)
		}
		config, _, err := loadConfig(path)
		if err != nil {
			t.Fatal(err)
		}
		if config.Output.SessionTranscript != tc.want || config.Output.ConsoleOutput {
			t.Fatalf("wrong transcript/console defaults: %+v", config.Output)
		}
	}
}

func TestHostTranscriptCapturesResponsesAndSeparatesSteps(t *testing.T) {
	ctx, failed := interactionContext(t, map[string]string{})
	var log bytes.Buffer
	ctx.sessionLog = &log
	ctx.sessionOutput = true
	ctx.sshCommand = &sequenceSSHEnsureExecutor{outputs: []string{"Alarm summary\nNo active alarms\n", "interface up\npassword=supersecret\n\x1b[31m"}}
	executeSteps(ctx, nil, []StepConfig{{Name: "alarms", Category: "Prechecks", Command: "show alarms"}, {Name: "interfaces", Command: "show interfaces"}})
	text := log.String()
	for _, want := range []string{"STEP: alarms", "STAGE: Prechecks", "STEP: interfaces", "Alarm summary\nNo active alarms", "interface up", "[REDACTED]", "attempt 1 at", "\n\n" + strings.Repeat("=", 72)} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q: %s", want, text)
		}
	}
	if strings.Count(text, "STAGE: Prechecks") != 1 {
		t.Fatal("stage label leaked into the next unrelated step")
	}
	if *failed || strings.Contains(text, "output omitted") || strings.Contains(text, "supersecret") || strings.ContainsRune(text, '\x1b') {
		t.Fatalf("invalid transcript: %s", text)
	}
}

func TestHostTranscriptRetainsPartialErrorAndReloadOutput(t *testing.T) {
	for _, reload := range []bool{false, true} {
		ctx, _ := interactionContext(t, map[string]string{})
		var log bytes.Buffer
		ctx.sessionLog = &log
		ctx.sessionOutput = true
		ctx.sshCommand = &sequenceSSHEnsureExecutor{outputs: []string{"Host reply before disconnect\n"}, errors: []error{errors.New("connection closed")}}
		step := StepConfig{Name: "disconnect", Command: "reload"}
		if reload {
			noPrompt := false
			step.ReturnToPrompt = &noPrompt
		}
		var client *sshdriver.Client
		executeSteps(ctx, &client, []StepConfig{step})
		if !strings.Contains(log.String(), "Host reply before disconnect") {
			t.Fatal("partial host response lost")
		}
	}
}
