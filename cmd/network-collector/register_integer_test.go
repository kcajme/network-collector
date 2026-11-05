package main

import (
	"errors"
	"strings"
	"testing"
)

func integerCaptureStep() StepConfig {
	min, max := int64(1), int64(2147483647)
	return StepConfig{Name: "capture", Command: "show install request", Register: "install_id",
		RegisterInteger: &RegisterIntegerConfig{Pattern: `(?m)^Install operation ([^\r\n]+)$`, Min: &min, Max: &max}}
}

func TestBoundedIntegerCaptureAtCommandBoundary(t *testing.T) {
	for _, tc := range []struct{ name, output, want string }{
		{"valid", "Install operation 42\n", "42"},
		{"canonical", "Install operation 00042\n", "42"},
		{"upper bound", "Install operation 2147483647\n", "2147483647"},
		{"zero", "Install operation 0\n", ""},
		{"above bound", "Install operation 2147483648\n", ""},
		{"overflow", "Install operation 9999999999999999999999999\n", ""},
		{"negative", "Install operation -42\n", ""},
		{"sign", "Install operation +42\n", ""},
		{"unicode", "Install operation ４２\n", ""},
		{"whitespace", "Install operation 42 \n", ""},
		{"injection", "Install operation 42; reload\n", ""},
		{"template", "Install operation {{payload}}\n", ""},
		{"missing", "No install operation\n", ""},
		{"ambiguous", "Install operation 42\nInstall operation 43\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			step := integerCaptureStep()
			steps := []StepConfig{step, {Name: "activate", Command: "install activate id {{install_id}} sync"}}
			vars := map[string]string{"install_id": "99"}
			if err := preflightDeviceVariables(DeviceConfig{Hostname: "router", Steps: steps}, nil, vars); err != nil {
				t.Fatal(err)
			}
			ctx, failed := interactionContext(t, vars)
			executor := &sequenceSSHEnsureExecutor{outputs: []string{tc.output, "activated"}}
			ctx.sshCommand = executor
			stopped := executeSteps(ctx, nil, steps)
			if tc.want == "" {
				if !stopped || !*failed || len(executor.commands) != 1 {
					t.Fatalf("unsafe output reached next step: stopped=%v failed=%v commands=%v", stopped, *failed, executor.commands)
				}
				if _, exists := vars["install_id"]; exists {
					t.Fatal("invalid capture retained stale variable")
				}
			} else {
				if stopped || *failed || len(executor.commands) != 2 || executor.commands[1] != "install activate id "+tc.want+" sync" {
					t.Fatalf("capture flow failed: stopped=%v failed=%v commands=%v", stopped, *failed, executor.commands)
				}
			}
		})
	}
}

func TestIntegerCaptureFailureStopsAfterTransportOrParserError(t *testing.T) {
	for _, parser := range []bool{false, true} {
		step := integerCaptureStep()
		executor := &sequenceSSHEnsureExecutor{outputs: []string{"Install operation 42\n"}}
		if parser {
			step.Parser = "nonexistent"
		} else {
			executor.errors = []error{errors.New("connection lost")}
		}
		ctx, failed := interactionContext(t, map[string]string{"install_id": "99"})
		ctx.sshCommand = executor
		if !executeSteps(ctx, nil, []StepConfig{step, {Command: "install activate id {{install_id}} sync"}}) || !*failed || len(executor.commands) != 1 {
			t.Fatal("failed capture continued execution")
		}
		if _, exists := ctx.variables["install_id"]; exists {
			t.Fatal("failed capture retained stale value")
		}
	}
}

func TestIntegerCaptureDoesNotPublishRawValidationExtract(t *testing.T) {
	step := integerCaptureStep()
	step.Validation = &ValidationConfig{Extractor: "regex", Pattern: `Danger: (.+)`, Condition: "contains", Expected: "reload", ExpectedType: "string"}
	executor := &sequenceSSHEnsureExecutor{outputs: []string{"Install operation 42\nDanger: reload; delete all\n", "ok"}}
	ctx, failed := interactionContext(t, map[string]string{})
	ctx.sshCommand = executor
	executeSteps(ctx, nil, []StepConfig{step, {Command: "install activate id {{install_id}} sync"}})
	if *failed || len(executor.commands) != 2 || executor.commands[1] != "install activate id 42 sync" {
		t.Fatalf("raw validation output replaced integer: %v", executor.commands)
	}
}

func TestInvalidIntegerCaptureConfigurationRejectedBeforeExecution(t *testing.T) {
	for _, change := range []func(*StepConfig){
		func(s *StepConfig) { s.Register = "" }, func(s *StepConfig) { s.Command = "" },
		func(s *StepConfig) { s.RegisterInteger.Min = nil }, func(s *StepConfig) { s.RegisterInteger.Max = nil },
		func(s *StepConfig) { v := int64(-1); s.RegisterInteger.Min = &v },
		func(s *StepConfig) { v := int64(2147483648); s.RegisterInteger.Max = &v },
		func(s *StepConfig) { v := int64(0); s.RegisterInteger.Max = &v },
		func(s *StepConfig) { s.RegisterInteger.Pattern = "[" }, func(s *StepConfig) { s.RegisterInteger.Pattern = "digits" },
		func(s *StepConfig) { s.RegisterInteger.Pattern = "(a)(b)" },
		func(s *StepConfig) { s.Retry = &RetryConfig{UntilPass: true} },
		func(s *StepConfig) { s.Use = "workflow" }, func(s *StepConfig) { s.NETCONF = &NETCONFStepConfig{} },
	} {
		step := integerCaptureStep()
		change(&step)
		if err := preflightDeviceVariables(DeviceConfig{Steps: []StepConfig{step}}, nil, nil); err == nil {
			t.Fatalf("invalid config passed preflight: %+v", step)
		}
		ctx, failed := interactionContext(t, map[string]string{})
		executor := &sequenceSSHEnsureExecutor{}
		ctx.sshCommand = executor
		if !executeSteps(ctx, nil, []StepConfig{step}) || !*failed || len(executor.commands) != 0 {
			t.Fatal("invalid config executed")
		}
	}
}

func TestIntegerCaptureDoesNotRelaxOtherDeviceOutputRules(t *testing.T) {
	step := integerCaptureStep()
	for _, sink := range []StepConfig{
		{Command: "display", NETCONF: &NETCONFStepConfig{Payload: "{{install_id}}"}},
		{Command: "{{install_id}}", Register: "install_id"},
	} {
		steps := []StepConfig{step, sink}
		if sink.Register != "" {
			steps = append(steps, StepConfig{Command: "install activate id {{install_id}} sync"})
		}
		err := preflightDeviceVariables(DeviceConfig{Steps: steps}, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "tainted") {
			t.Fatalf("taint boundary relaxed: %v", err)
		}
	}
}
