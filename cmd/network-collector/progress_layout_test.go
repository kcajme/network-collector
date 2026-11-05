package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func layoutFixture() *progressDisplay {
	devices := make([]DeviceConfig, 100)
	for i := range devices {
		devices[i] = DeviceConfig{Hostname: fmt.Sprintf("long-device-name-%03d", i+1), IP: fmt.Sprint(i)}
	}
	d := newProgressDisplay(io.Discard, devices)
	d.input = os.Stdin
	d.idle = true
	for _, host := range d.hosts {
		host.step = strings.Repeat("step-", 30)
		host.category = strings.Repeat("category-", 15)
	}
	return d
}

func assertFrameFits(t *testing.T, frame string, width, height int) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(frame, "\n"), "\n")
	if len(lines) > max(1, height-2) {
		t.Fatalf("%dx%d frame has %d lines: %s", width, height, len(lines), frame)
	}
	for _, line := range lines {
		if len(line) > max(0, width-1) {
			t.Fatalf("%dx%d frame overflow: %d cells: %q", width, height, len(line), line)
		}
	}
	if strings.Contains(frame, "\x1b") {
		t.Fatal("data injected terminal control sequences")
	}
}

func TestProgressFramesFitTerminalIncludingPrompts(t *testing.T) {
	for _, size := range [][2]int{{1, 1}, {10, 3}, {24, 6}, {40, 10}, {60, 12}, {80, 24}, {120, 40}, {200, 60}} {
		for _, mode := range []string{"normal", "help", "notice", "quit", "retry", "stopping", "closed"} {
			t.Run(fmt.Sprintf("%dx%d/%s", size[0], size[1], mode), func(t *testing.T) {
				d := layoutFixture()
				switch mode {
				case "help":
					d.help = true
				case "notice":
					d.notice = strings.Repeat("A long notice with control data\x1b[2J\n", 20)
				case "quit":
					d.confirmStop = true
				case "retry":
					d.pendingRetry = d.order[0]
				case "stopping":
					d.stopping = true
				case "closed":
					d.closed = true
				}
				assertFrameFits(t, d.renderSize(time.Now(), size[0], size[1]), size[0], size[1])
			})
		}
	}
}

func TestProgressPaginationAccessesEveryHostAndKeepsGlobalTotals(t *testing.T) {
	d := layoutFixture()
	d.size = func() (int, int) { return 80, 12 }
	seen := map[string]bool{}
	for page := 0; page < 100; page++ {
		frame := d.render(time.Now())
		if !strings.Contains(frame, "Total: 100") || !strings.Contains(frame, "Remaining: 100") {
			t.Fatalf("totals reflect only visible hosts: %s", frame)
		}
		for _, line := range strings.Split(frame, "\n") {
			fields := strings.Fields(strings.Trim(line, "| "))
			if len(fields) > 2 && strings.HasPrefix(fields[1], "long-device") {
				seen[fields[0]] = true
			}
		}
		last := d.page
		d.handleCommand("n")
		if d.page == last {
			break
		}
	}
	if len(seen) != 100 {
		t.Fatalf("only %d of 100 hosts accessible", len(seen))
	}
	d.handleCommand("first")
	if d.page != 0 {
		t.Fatal("first page unavailable")
	}
	d.handleCommand("g 100")
	frame := d.render(time.Now())
	if !strings.Contains(frame, "100 ") {
		t.Fatalf("jump to host failed: %s", frame)
	}
	d.handleCommand("p")
	if d.page == 0 {
		t.Fatal("previous page did not change view")
	}
}

func TestProgressResizesAndClampsPageWithoutLosingPrompts(t *testing.T) {
	d := layoutFixture()
	width, height := 80, 12
	d.size = func() (int, int) { return width, height }
	d.handleCommand("last")
	for _, size := range [][2]int{{120, 40}, {40, 10}, {80, 24}, {10, 3}, {160, 50}} {
		width, height = size[0], size[1]
		frame := d.render(time.Now())
		assertFrameFits(t, frame, width, height)
		if d.page < 0 {
			t.Fatal("negative page after resize")
		}
	}
	d.confirmStop = true
	width, height = 40, 10
	frame := d.render(time.Now())
	if !strings.Contains(frame, "y=yes") || !strings.Contains(frame, "n=stay") {
		t.Fatalf("confirmation lost on small terminal: %s", frame)
	}
	if progressText("value", 0) != "" {
		t.Fatal("zero width text is not empty")
	}
	d.confirmStop = false
	small := d.renderSize(time.Now(), 20, 5)
	if !strings.Contains(small, "Enlarge") || !strings.Contains(small, "[Q] Quit") {
		t.Fatalf("compact instructions unavailable: %s", small)
	}
}

func TestRetryCannotBeConfirmedWhenWarningDoesNotFit(t *testing.T) {
	d := layoutFixture()
	width, height := 20, 4
	d.size = func() (int, int) { return width, height }
	d.pendingRetry = d.order[0]
	d.handleCommand("y")
	if d.pendingRetry == "" || len(d.requests) != 0 {
		t.Fatal("accepted retry while confirmation was hidden")
	}
	width, height = 80, 24
	d.handleCommand("y")
	if d.pendingRetry != "" || len(d.requests) != 1 {
		t.Fatal("retry unavailable after enlarging terminal")
	}
}
