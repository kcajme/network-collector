package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/gwoodwa1/network-collector/pkg/drivers/ssh"
)

// A readiness attempt includes both the TCP check and establishing a usable SSH
// session. An open port alone does not mean a rebooting device is ready.
func retrySSHReadiness(runContext context.Context, probe resolvedSSHProbe, attempt func(int) (retryable bool, err error)) error {
	var lastErr error
	for n := 1; n <= probe.Attempts; n++ {
		if err := runContext.Err(); err != nil {
			return err
		}
		retryable, err := attempt(n)
		if err == nil {
			return nil
		}
		if !retryable {
			return err
		}
		lastErr = err
		if n < probe.Attempts {
			if err := waitRunContext(runContext, probe.Interval); err != nil {
				return err
			}
		}
	}
	return fmt.Errorf("SSH readiness failed after %d attempts: %w", probe.Attempts, lastErr)
}

func reconnectAfterSSHProbe(ctx *stepExecutionContext, client **ssh.Client, stepName string, probe resolvedSSHProbe) error {
	postWaitDone := false
	return retrySSHReadiness(stepRunContext(ctx), probe, func(attempt int) (bool, error) {
		writeSessionf(ctx.sessionLog, "\n[step:%s] SSH readiness attempt %d/%d\n", stepName, attempt, probe.Attempts)
		// Use one TCP check per readiness attempt, so connection and login failures
		// consume the same configured budget rather than nested retry budgets.
		cfg := &SSHProbeConfig{Port: probe.Port, MaxAttempts: 1}
		cfg.TimeoutSeconds = int(probe.Timeout.Seconds())
		if err := waitForSSHPortContext(stepRunContext(ctx), ctx.ip, cfg); err != nil {
			writeSessionf(ctx.sessionLog, "[step:%s] TCP probe failed on attempt %d: %v\n", stepName, attempt, err)
			return true, err
		}
		if !postWaitDone && probe.PostWait > 0 {
			writeSessionf(ctx.sessionLog, "[step:%s] TCP probe succeeded; waiting %s before SSH login\n", stepName, probe.PostWait)
			if err := waitRunContext(stepRunContext(ctx), probe.PostWait); err != nil {
				return false, err
			}
			postWaitDone = true
		}
		username, password := ctx.username, ctx.password
		if ctx.reauthenticate != nil {
			var err error
			username, password, err = ctx.reauthenticate()
			if err != nil {
				return false, fmt.Errorf("RSA re-authentication failed: %w", err)
			}
		}
		if err := stepRunContext(ctx).Err(); err != nil {
			return false, err
		}
		candidate := ssh.NewClient(ctx.opts...)
		if err := candidate.Connect(ctx.ip, username, password, ctx.deviceType); err != nil {
			_ = candidate.Close()
			slog.Warn("SSH login not ready", "hostname", ctx.hostname, "step", stepName, "attempt", attempt, "max_attempts", probe.Attempts, "error", err)
			writeSessionf(ctx.sessionLog, "[step:%s] SSH login failed on attempt %d/%d: %v\n", stepName, attempt, probe.Attempts, err)
			return true, err
		}
		*client = candidate
		return false, nil
	})
}
