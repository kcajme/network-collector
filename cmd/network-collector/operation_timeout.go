package main

import (
	"fmt"
	"math"
	"time"

	"github.com/gwoodwa1/network-collector/pkg/drivers/ssh"
)

type operationTimeoutController interface {
	OperationTimeout() time.Duration
	SetOperationTimeout(time.Duration)
}

func validateOperationTimeout(seconds int) error {
	if seconds < 0 || int64(seconds) > math.MaxInt64/int64(time.Second) {
		return fmt.Errorf("operation_timeout must be non-negative seconds within the supported duration range; 0 inherits the default")
	}
	return nil
}

func withPlaybookTimeout(device DeviceConfig, config Config) DeviceConfig {
	if device.OperationTimeout == 0 {
		device.OperationTimeout = config.OperationTimeout
	}
	return device
}

// A workflow session executes sequentially; parallel branches own independent
// clients. Restore the current client as well as the policy because a step may
// replace a stale session or establish a lazy NETCONF connection.
func scopeOperationTimeout(ctx *stepExecutionContext, client **ssh.Client, timeout time.Duration) func() {
	previousOpts, previousPolicy := ctx.opts, ctx.netconfPolicy
	sshTimeout := ssh.NewClient(previousOpts...).OperationTimeout()
	if client != nil && *client != nil {
		sshTimeout = (*client).OperationTimeout()
		(*client).SetOperationTimeout(timeout)
	}
	ctx.opts = append(append([]ssh.Option(nil), previousOpts...), ssh.WithOperationTimeout(timeout))
	ctx.netconfPolicy.timeout = timeout
	var restoreInjectedSSH func()
	if controller, ok := ctx.sshCommand.(operationTimeoutController); ok {
		before := controller.OperationTimeout()
		controller.SetOperationTimeout(timeout)
		restoreInjectedSSH = func() { controller.SetOperationTimeout(before) }
	}
	var restoreNETCONF func()
	if executor, ok := ctx.netconf.(*lazyNETCONFExecutor); ok {
		previous := executor.policy.timeout
		effective := previous
		if executor.client != nil {
			effective = executor.client.OperationTimeout()
		}
		if effective <= 0 {
			effective = 60 * time.Second
		}
		executor.policy.timeout = timeout
		if executor.client != nil {
			executor.client.SetOperationTimeout(timeout)
		}
		restoreNETCONF = func() {
			executor.policy.timeout = previous
			if executor.client != nil {
				executor.client.SetOperationTimeout(effective)
			}
		}
	} else if controller, ok := ctx.netconf.(operationTimeoutController); ok {
		before := controller.OperationTimeout()
		controller.SetOperationTimeout(timeout)
		restoreNETCONF = func() { controller.SetOperationTimeout(before) }
	}
	return func() {
		if client != nil && *client != nil {
			(*client).SetOperationTimeout(sshTimeout)
		}
		if restoreInjectedSSH != nil {
			restoreInjectedSSH()
		}
		if restoreNETCONF != nil {
			restoreNETCONF()
		}
		ctx.opts, ctx.netconfPolicy = previousOpts, previousPolicy
	}
}
