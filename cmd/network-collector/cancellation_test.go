package main

import (
	"context"
	"io"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestQuitMenuRequiresConfirmation(t *testing.T) {
	d := newProgressDisplay(io.Discard, nil)
	cancelled := 0
	d.requestStop = func() { cancelled++ }
	d.handleCommand("q")
	if !d.confirmStop || cancelled != 0 {
		t.Fatal("quit did not request confirmation")
	}
	d.handleCommand("n")
	if d.confirmStop || cancelled != 0 {
		t.Fatal("declining quit stopped operation")
	}
	d.handleCommand("h")
	if !d.help {
		t.Fatal("help unavailable")
	}
	d.handleCommand("quit")
	d.handleCommand("yes")
	d.handleCommand("q")
	if cancelled != 1 || !d.stopping {
		t.Fatal("confirmed quit failed or was repeated")
	}
}

func TestRunCancellationIsBounded(t *testing.T) {
	for _, second := range []bool{false, true} {
		signals := make(chan os.Signal, 2)
		exits := make(chan int, 1)
		ctx, finish := watchRunCancellation(signals, io.Discard, 30*time.Millisecond, func(code int) { exits <- code })
		signals <- syscall.SIGTERM
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
			t.Fatal("quit did not cancel run")
		}
		if second {
			signals <- syscall.SIGTERM
		}
		select {
		case code := <-exits:
			if code != 130 {
				t.Fatal(code)
			}
		case <-time.After(time.Second):
			t.Fatal("blocked run never exited")
		}
		finish()
	}
}

func TestCancelledStepWaitDoesNotExecuteFollowingCommand(t *testing.T) {
	ctx, failed := interactionContext(t, map[string]string{})
	run, cancel := context.WithCancel(context.Background())
	ctx.runContext = run
	executor := &sequenceSSHEnsureExecutor{}
	ctx.sshCommand = executor
	done := make(chan bool, 1)
	go func() {
		done <- executeSteps(ctx, nil, []StepConfig{{Name: "wait", WaitSeconds: 600}, {Command: "must-not-run"}})
	}()
	cancel()
	select {
	case stopped := <-done:
		if !stopped || len(executor.commands) != 0 {
			t.Fatal("cancelled workflow continued")
		}
	case <-time.After(time.Second):
		t.Fatal("wait ignored quit")
	}
	_ = failed
}

func TestContextWaitAndProbeCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if waitRunContext(ctx, time.Hour) != context.Canceled {
		t.Fatal("wait did not cancel")
	}
	started := time.Now()
	err := waitForSSHPortContext(ctx, "192.0.2.1", &SSHProbeConfig{IntervalSeconds: 60, TimeoutSeconds: 60, MaxAttempts: 5})
	if err == nil || time.Since(started) > time.Second {
		t.Fatal("probe did not cancel promptly")
	}
}
