package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSSHReadinessRetriesUntilLoginSucceeds(t *testing.T) {
	// Model the observed reboot: port closed, then TCP ready but login times
	// out, then a usable session. No command/activation is retried here.
	errs := []error{errors.New("connection refused"), errors.New("timed out connecting to host"), nil}
	attempts := 0
	err := retrySSHReadiness(context.Background(), resolvedSSHProbe{Attempts: 4, Interval: time.Nanosecond}, func(n int) (bool, error) {
		attempts++
		return true, errs[n-1]
	})
	if err != nil || attempts != 3 {
		t.Fatalf("recovered login should succeed after three attempts: attempts=%d err=%v", attempts, err)
	}
}

func TestSSHReadinessExhaustsSharedBudget(t *testing.T) {
	last := errors.New("SSH authentication timeout")
	attempts := 0
	err := retrySSHReadiness(context.Background(), resolvedSSHProbe{Attempts: 3, Interval: time.Nanosecond}, func(n int) (bool, error) {
		attempts++
		return true, last
	})
	if attempts != 3 || !errors.Is(err, last) || !strings.Contains(err.Error(), "after 3 attempts") {
		t.Fatalf("attempts=%d err=%v", attempts, err)
	}
}

func TestSSHReadinessStopsWhenUserCancels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	attempts := 0
	err := retrySSHReadiness(ctx, resolvedSSHProbe{Attempts: 40, Interval: time.Hour}, func(int) (bool, error) {
		attempts++
		cancel()
		return true, errors.New("not ready")
	})
	if !errors.Is(err, context.Canceled) || attempts != 1 {
		t.Fatalf("attempts=%d err=%v", attempts, err)
	}
}

func TestSSHReadinessDoesNotRepeatCredentialPromptFailure(t *testing.T) {
	failure := errors.New("credential entry cancelled")
	attempts := 0
	err := retrySSHReadiness(context.Background(), resolvedSSHProbe{Attempts: 40}, func(int) (bool, error) {
		attempts++
		return false, failure
	})
	if !errors.Is(err, failure) || attempts != 1 {
		t.Fatalf("attempts=%d err=%v", attempts, err)
	}
}
