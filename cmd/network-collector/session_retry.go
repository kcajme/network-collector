package main

import (
	"context"
	"fmt"

	"github.com/gwoodwa1/network-collector/pkg/drivers/ssh"
)

func waitForSessionActions(run context.Context, display *progressDisplay, devices []DeviceConfig, checkpoints map[string]*hostCheckpoint, results []deviceRunResult, recurring bool, retry func(int, DeviceConfig, map[string]string) deviceRunResult) []deviceRunResult {
	counts := map[string]int{}
	for _, device := range devices {
		counts[variableScopeKey(device.Hostname, device.IP)]++
	}
	for run.Err() == nil {
		descriptions := map[string]string{}
		enabled := map[string]bool{}
		for index, device := range devices {
			key := variableScopeKey(device.Hostname, device.IP)
			descriptions[key] = "Only failed hosts can be retried."
			for _, result := range results {
				if result.index == index && result.failed {
					checkpoint := checkpoints[key]
					descriptions[key] = checkpointDescription(checkpoint)
					enabled[key] = checkpoint != nil && len(checkpoint.remaining) > 0 && checkpoint.blocked == ""
				}
			}
			if counts[key] > 1 {
				enabled[key] = false
				descriptions[key] = "Retry is unavailable for duplicate host targets."
			}
			if recurring {
				enabled[key] = false
				descriptions[key] = "Retrying recurring jobs is not supported; select a single occurrence."
			}
		}
		display.readyForRetries(descriptions, enabled)
		select {
		case <-run.Done():
			return results
		case request := <-display.requests:
			if request.quit {
				return results
			}
			if !enabled[request.host] {
				continue
			}
			for index, device := range devices {
				if variableScopeKey(device.Hostname, device.IP) != request.host {
					continue
				}
				checkpoint := checkpoints[request.host]
				device.Steps = append([]StepConfig(nil), checkpoint.remaining...)
				next := retry(index, device, cloneVariables(checkpoint.before))
				for i, previous := range results {
					if previous.index == index {
						if !next.failed {
							for j := range previous.aggregated {
								if previous.aggregated[j].Result.Status == "fail" || previous.aggregated[j].Result.Status == "error" {
									previous.aggregated[j].Recovered = true
								}
							}
						}
						next.aggregated = append(previous.aggregated, next.aggregated...)
						next.artifacts = append(previous.artifacts, next.artifacts...)
						next.duration += previous.duration
						results[i] = next
						break
					}
				}
				break
			}
		}
	}
	return results
}

// These checkpoints intentionally live only in memory. Restoring one never
// re-executes successful steps to reconstruct variables from device output.
type hostCheckpoint struct {
	remaining []StepConfig
	before    map[string]string
	attempt   int
	blocked   string
}

func retryBoundary(step StepConfig) string {
	if step.Block != nil || step.Foreach != nil || step.Repeat != nil || step.Parallel != nil || step.Use != "" || step.GNMISubscribe != nil || step.OnPass != nil || step.OnFail != nil {
		return "Exact retry inside control workflows or validation actions is not supported."
	}
	return ""
}

func executeCheckpointedSteps(ctx *stepExecutionContext, client **ssh.Client, steps []StepConfig) bool {
	checkpoint := ctx.checkpoint
	ctx.checkpoint = nil
	defer func() { ctx.checkpoint = checkpoint }()
	for index, step := range steps {
		checkpoint.remaining = steps[index:]
		checkpoint.before = cloneVariables(ctx.variables)
		checkpoint.blocked = retryBoundary(step)
		count := len(*ctx.aggregated)
		stopped := executeStepsAtDepth(ctx, client, []StepConfig{step}, 0)
		failed := *ctx.runFailed
		for _, v := range (*ctx.aggregated)[count:] {
			if !v.Recovered && (v.Result.Status == "fail" || v.Result.Status == "error") {
				failed = true
			}
		}
		if failed {
			*ctx.runFailed = true
			return true
		}
		if stopped {
			checkpoint.remaining = nil
			return true
		}
	}
	checkpoint.remaining = nil
	return false
}

type sessionRequest struct {
	host string
	quit bool
}

func checkpointDescription(checkpoint *hostCheckpoint) string {
	if checkpoint == nil || len(checkpoint.remaining) == 0 {
		return "No failed-step checkpoint is available."
	}
	if checkpoint.blocked != "" {
		return checkpoint.blocked
	}
	name := checkpoint.remaining[0].Name
	if name == "" {
		name = "unnamed step"
	}
	return fmt.Sprintf("Retry %s? This may resend a command already executed on the device. Verify remote state first. [y/N]", progressText(name, 30))
}
