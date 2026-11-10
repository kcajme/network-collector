package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func securityConfigFile(t *testing.T, text string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestWorkbookOnlyAcceptsBoundEnvironment(t *testing.T) {
	t.Setenv("SECURITY_MODE", "permissive")
	t.Setenv("INVENTORY_FILE", "untrusted.yaml")
	t.Setenv("PARSERS_FILE", "untrusted.yaml")
	t.Setenv("FAIL_ON_FAIL", "true")
	p := securityConfigFile(t, "security_mode: production\ninventory_file: inventory.yaml\nparsers_file: parsers.yaml\nfail_on_fail: false\n")
	c, fail, err := loadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.SecurityMode != "production" || c.InventoryFile != "inventory.yaml" || c.ParsersFile != "parsers.yaml" || !fail {
		t.Fatalf("unexpected settings: %+v fail=%v", c, fail)
	}
}
func TestWorkbookRejectsSafetyTypos(t *testing.T) {
	for _, text := range []string{"execution:\n  canary_cout: 1\n", "ssh:\n  - steps:\n      - cmd: show version\n        aproval: {}\n", "ssh:\n  - steps:\n      - cmd: show version\n        wen: false\n"} {
		if _, _, err := loadConfig(securityConfigFile(t, text)); err == nil {
			t.Fatalf("accepted %q", text)
		}
	}
	p := securityConfigFile(t, "vars:\n  arbitrary: valid\nssh:\n  - steps:\n      - cmd: show version\n        approval:\n          message: Continue?\n")
	if _, _, err := loadConfig(p); err != nil {
		t.Fatal(err)
	}
}
func TestInventoryAndParsersRejectUnknownFields(t *testing.T) {
	p := securityConfigFile(t, "hosts:\n  - name: router\n    ssh_securty: {}\n")
	if _, err := loadInventory(p, ""); err == nil {
		t.Fatal("inventory accepted typo")
	}
	p = securityConfigFile(t, "parsers:\n  probe:\n    unknow_field: true\n")
	if _, err := loadParsers(p, ""); err == nil {
		t.Fatal("parsers accepted typo")
	}
}
func TestApprovalSanitizesPromptAndBothLogPaths(t *testing.T) {
	for _, automatic := range []bool{false, true} {
		ctx, _ := interactionContext(t, map[string]string{"device_text": "\x1b[2J secret SYNTHETIC_CREDENTIAL"})
		var prompt, log bytes.Buffer
		ctx.sessionLog = &log
		ctx.approvalWriter = &prompt
		ctx.approvalInput = newApprovalInput(strings.NewReader("yes\n"))
		ctx.approveAll = automatic
		ctx.hostname = "router\x1b[2J"
		if _, err := requestApproval(ctx, ApprovalConfig{Message: "{{device_text}}"}, "gate\x1b[2J"); err != nil {
			t.Fatal(err)
		}
		for _, text := range []string{prompt.String(), log.String()} {
			if strings.Contains(text, "\x1b") || strings.Contains(text, "SYNTHETIC_CREDENTIAL") {
				t.Fatalf("unsafe output %q", text)
			}
		}
	}
}

type securityCommandRecorder struct{ commands []string }

func (r *securityCommandRecorder) Execute(command string) (string, error) {
	r.commands = append(r.commands, command)
	return "ok", nil
}
func TestResumeIdentifiesDuplicateUnnamedAndLoopInstances(t *testing.T) {
	tests := map[string][]StepConfig{
		"duplicates": {{Name: "same", Command: "show version"}, {Name: "same", Command: "show version"}},
		"unnamed":    {{Command: "show version"}, {Command: "show version"}},
		"foreach":    {{Foreach: &ForeachConfig{Items: []interface{}{"one", "one"}, Steps: []StepConfig{{Command: "show version"}}}}},
	}
	for name, steps := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			ctx, _ := interactionContext(t, map[string]string{})
			recorder := &securityCommandRecorder{}
			ctx.sshCommand = recorder
			journal, err := newRunJournal(dir)
			if err != nil {
				t.Fatal(err)
			}
			ctx.journal = journal
			executeSteps(ctx, nil, steps)
			if len(recorder.commands) != 2 {
				t.Fatalf("initial commands %v", recorder.commands)
			}
			completed, err := completedJournalEntries(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(completed) != 2 {
				t.Fatalf("colliding identities: %v", completed)
			}
			// Simulate only one completed instance, with the other never executed.
			for key := range completed {
				delete(completed, key)
				break
			}
			ctx.resumeCompleted = completed
			recorder.commands = nil
			executeSteps(ctx, nil, steps)
			if len(recorder.commands) != 1 {
				t.Fatalf("resume executed %d commands, want 1", len(recorder.commands))
			}
		})
	}
}
func TestResumeRejectsChangedDependencies(t *testing.T) {
	for _, kind := range []string{"import", "vars", "payload"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			root := filepath.Join(dir, "config.yaml")
			child := filepath.Join(dir, "child.yaml")
			text := "imports: child.yaml\n"
			content := "vars:\n  value: before\n"
			if kind == "vars" {
				text = "vars_files: child.yaml\n"
			}
			if kind == "payload" {
				text = "ssh:\n  - steps:\n      - netconf:\n          operation: rpc\n          payload_file: child.yaml\n"
				content = "<before/>"
			}
			if err := os.WriteFile(root, []byte(text), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(child, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			c, _, err := loadConfig(root)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = writeRunManifest(dir, "test", root, c, c.SSH); err != nil {
				t.Fatal(err)
			}
			if _, err = verifyResumeManifest(dir, root, c, c.SSH); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(child, []byte(strings.ReplaceAll(content, "before", "after")), 0600); err != nil {
				t.Fatal(err)
			}
			c, _, err = loadConfig(root)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = verifyResumeManifest(dir, root, c, c.SSH); err == nil {
				t.Fatal("changed dependency accepted")
			}
		})
	}
}
func TestSyslogRequiresAdminDestinationAndProductionTLS(t *testing.T) {
	t.Setenv("NETWORK_COLLECTOR_SYSLOG_ALLOWED_ADDRESSES", "collector.example:6514")
	for _, c := range []EventSinkConfig{{Type: "syslog", Network: "udp", Address: "collector.example:6514"}, {Type: "syslog", Network: "tls", Address: "other.example:6514"}} {
		if sink, err := newNetworkEventSink(c, "production"); err == nil {
			sink.Close()
			t.Fatal("unsafe sink accepted")
		}
	}
	sink, err := newNetworkEventSink(EventSinkConfig{Type: "syslog", Address: "collector.example:6514", TimeoutSeconds: 1}, "production")
	if err != nil {
		t.Fatal(err)
	}
	if err = sink.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestRepeatJournalUsesDistinctIterations(t *testing.T) {
	ctx, _ := interactionContext(t, map[string]string{})
	ctx.sshCommand = &securityCommandRecorder{}
	dir := t.TempDir()
	j, err := newRunJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx.journal = j
	executeRepeat(ctx, nil, RepeatConfig{Count: 2, IntervalSeconds: 1, Steps: []StepConfig{{Command: "show version"}}}, "repeat", 1, func(time.Duration) {})
	entries, err := completedJournalEntries(dir)
	if err != nil || len(entries) != 2 {
		t.Fatalf("entries=%v error=%v", entries, err)
	}
}

func TestResumeRejectsOldAndDynamicPayloadManifests(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, runManifestFilename)
	if err := os.WriteFile(path, []byte(`{"format_version":1,"run_id":"old","config_digest":"x","plan_digest":"y"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRunManifest(dir); err == nil {
		t.Fatal("old manifest accepted")
	}
	root := securityConfigFile(t, "ssh:\n  - steps:\n      - netconf:\n          operation: rpc\n          payload_file: '{{runtime_path}}'\n")
	c, _, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writeRunManifest(dir, "new", root, c, c.SSH); err != nil {
		t.Fatal(err)
	}
	if _, err = verifyResumeManifest(dir, root, c, c.SSH); err == nil {
		t.Fatal("dynamic payload resume accepted")
	}
}

func TestResumeChangedRuntimeBindingsNeitherReplaysNorSkips(t *testing.T) {
	ctx, _ := interactionContext(t, map[string]string{"target": "one"})
	recorder := &securityCommandRecorder{}
	ctx.sshCommand = recorder
	dir := t.TempDir()
	j, err := newRunJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx.journal = j
	steps := []StepConfig{{Command: "show {{target}}"}}
	executeSteps(ctx, nil, steps)
	completed, err := completedJournalEntries(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx.resumeCompleted = completed
	ctx.variables["target"] = "two"
	recorder.commands = nil
	if stopped := executeSteps(ctx, nil, steps); !stopped || !*ctx.runFailed || len(recorder.commands) != 0 {
		t.Fatalf("unsafe changed binding: stopped=%v failed=%v commands=%v", stopped, *ctx.runFailed, recorder.commands)
	}
}

func TestResumeDoesNotSilentlySkipDependentActions(t *testing.T) {
	ctx, _ := interactionContext(t, map[string]string{})
	recorder := &securityCommandRecorder{}
	ctx.sshCommand = recorder
	step := StepConfig{Name: "parent", Command: "show version", OnPass: &ValidationActionConfig{Action: "steps", Steps: []StepConfig{{Command: "show clock"}}}}
	ctx.executionPath = "/step:0"
	key := journalEntryKey(runJournalEntry{Hostname: ctx.hostname, IP: ctx.ip, Step: step.Name, ExecutionID: executionID(ctx)})
	ctx.resumeCompleted = map[string]string{key: executionBinding(ctx)}
	ctx.executionPath = ""
	if stopped := executeSteps(ctx, nil, []StepConfig{step}); !stopped || !*ctx.runFailed || len(recorder.commands) != 0 {
		t.Fatal("dependent actions were silently skipped or mutation replayed")
	}
}

func TestResumeBindingPreservesExactRuntimeBytes(t *testing.T) {
	ctx, _ := interactionContext(t, map[string]string{"value": string([]byte{0xff})})
	first := executionBinding(ctx)
	ctx.variables["value"] = string([]byte{0xfe})
	if first == executionBinding(ctx) {
		t.Fatal("distinct device bytes collapsed into one binding")
	}
}
