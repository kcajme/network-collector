package main

import (
	"errors"
	"testing"
)

func retryRecoverySteps() []StepConfig {
	return []StepConfig{
		{Name: "show-install-request", Command: "show install request", Retry: &RetryConfig{UntilPass: true, IntervalSeconds: 1, MaxAttempts: 2}, Validation: &ValidationConfig{Extractor: "regex", Pattern: "No install operation in progress", Condition: "contains", Expected: "No install operation in progress", ExpectedType: "string"}},
		{Name: "next", Command: "show version"},
	}
}

func TestRetryRecoveryClearsOnlyEarlierAttemptsOfSameStep(t *testing.T) {
	for _, checkpointed := range []bool{false, true} {
		ctx, failed := interactionContext(t, map[string]string{})
		if checkpointed {
			ctx.checkpoint = &hostCheckpoint{}
		}
		executor := &sequenceSSHEnsureExecutor{outputs: []string{"cleanup still running", "No install operation in progress", "version"}}
		ctx.sshCommand = executor
		if executeSteps(ctx, nil, retryRecoverySteps()) || *failed || len(executor.commands) != 3 {
			t.Fatalf("recovered retry stopped remaining steps: checkpoint=%v commands=%v", checkpointed, executor.commands)
		}
		results := *ctx.aggregated
		if len(results) != 2 || results[0].Result.Status != "fail" || !results[0].Recovered || !results[1].Result.Pass {
			t.Fatalf("retry history not recovered: %+v", results)
		}
	}
}

func TestRetryRecoveryDoesNotStopCanaryOrTriggerFailureThreshold(t *testing.T) {
	for _, policy := range []ExecutionConfig{{MaxParallel: 1, CanaryCount: 1, FailureThreshold: 0}, {MaxParallel: 1, FailureThreshold: 1}} {
		devices := []DeviceConfig{{Hostname: "one", IP: "1"}, {Hostname: "two", IP: "2"}}
		results, stopped := runScheduledDevices(devices, policy, func(index int, device DeviceConfig) deviceRunResult {
			ctx, failed := interactionContext(t, map[string]string{})
			ctx.checkpoint = &hostCheckpoint{}
			output := []string{"No install operation in progress", "version"}
			if index == 0 {
				output = append([]string{"cleanup still running"}, output...)
			}
			executor := &sequenceSSHEnsureExecutor{outputs: output}
			ctx.sshCommand = executor
			executeSteps(ctx, nil, retryRecoverySteps())
			for _, v := range *ctx.aggregated {
				if !v.Recovered && (v.Result.Status == "fail" || v.Result.Status == "error") {
					*failed = true
				}
			}
			return deviceRunResult{index: index, hostname: device.Hostname, failed: *failed}
		})
		if stopped || len(results) != 2 || results[0].failed || results[1].failed {
			t.Fatalf("successful retry stopped rollout: %+v results=%+v stopped=%v", policy, results, stopped)
		}
	}
}

func TestExhaustedRetriesAndLaterCommandErrorsRemainFailures(t *testing.T) {
	for _, recoverThenError := range []bool{false, true} {
		ctx, failed := interactionContext(t, map[string]string{})
		ctx.checkpoint = &hostCheckpoint{}
		executor := &sequenceSSHEnsureExecutor{outputs: []string{"busy", "busy"}}
		if recoverThenError {
			executor.outputs = []string{"busy", "No install operation in progress", "partial"}
			executor.errors = []error{nil, nil, errors.New("transport failed")}
		}
		ctx.sshCommand = executor
		if !executeSteps(ctx, nil, retryRecoverySteps()) || !*failed {
			t.Fatal("real failure incorrectly recovered")
		}
		if !recoverThenError && (len(executor.commands) != 2 || (*ctx.aggregated)[0].Recovered || (*ctx.aggregated)[1].Recovered) {
			t.Fatal("exhausted retry failure hidden")
		}
	}
}
