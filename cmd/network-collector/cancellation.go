package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"
)

func stepRunContext(ctx *stepExecutionContext) context.Context {
	if ctx.runContext != nil {
		return ctx.runContext
	}
	return context.Background()
}

func waitRunContext(ctx context.Context, d time.Duration) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func newRunCancellation(input *os.File, output io.Writer, menu bool) (context.Context, func(), func()) {
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	// Save the terminal before any hidden password entry, so forced exits restore echo.
	// #nosec G115 -- x/term requires an OS descriptor as int.
	state, _ := term.GetState(int(input.Fd()))
	restore := func() {
		if state != nil {
			_ = term.Restore(int(input.Fd()), state)
		}
	}
	ctx, finish := watchRunCancellation(signals, output, 5*time.Second, func(code int) { restore(); os.Exit(code) })
	return ctx, func() {
			select {
			case signals <- syscall.SIGTERM:
			default:
			}
		}, func() {
			signal.Stop(signals)
			if menu {
				signal.Reset(os.Interrupt)
			}
			finish()
			restore()
		}
}

// A second signal, or a blocked transport exceeding the grace period, terminates
// the process. This bounds shutdown even for libraries without context support.
func watchRunCancellation(signals <-chan os.Signal, output io.Writer, grace time.Duration, forceExit func(int)) (context.Context, func()) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var once sync.Once
	go func() {
		select {
		case <-done:
			return
		case <-signals:
			cancel()
		}
		fmt.Fprintln(output, "\nStopping operation; waiting up to five seconds for shutdown.")
		timer := time.NewTimer(grace)
		defer timer.Stop()
		select {
		case <-done:
			return
		case <-signals:
			forceExit(130)
		case <-timer.C:
			forceExit(130)
		}
	}()
	return ctx, func() { once.Do(func() { close(done); cancel() }) }
}
