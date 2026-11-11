package main

import (
	"fmt"
	"time"
)

func reconnectNETCONF(ctx *stepExecutionContext, cfg NETCONFStepConfig) error {
	executor, ok := ctx.netconf.(*lazyNETCONFExecutor)
	if !ok {
		return fmt.Errorf("NETCONF executor does not support reconnection")
	}
	probe := resolvedSSHProbe{Attempts: cfg.MaxAttempts, Interval: time.Duration(cfg.IntervalSeconds) * time.Second}
	return retrySSHReadiness(stepRunContext(ctx), probe, func(attempt int) (bool, error) {
		username, password := ctx.username, ctx.password
		if ctx.reauthenticate != nil {
			var err error
			username, password, err = ctx.reauthenticate()
			if err != nil {
				return false, err
			}
		}
		executor.Reset(username, password)
		writeSessionf(ctx.sessionLog, "[netconf] connection attempt %d/%d\n", attempt, cfg.MaxAttempts)
		if err := executor.connect(); err != nil {
			writeSessionf(ctx.sessionLog, "[netconf] connection attempt failed: %v\n", err)
			return true, err
		}
		return false, nil
	})
}
