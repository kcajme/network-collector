package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type progressHost struct {
	ended                       time.Time
	name, state, category, step string
	since                       time.Time
	completed                   int
}

// progressDisplay consumes the same lifecycle events as disk/report sinks.
// It never receives command output, credentials or validation payloads.
type progressDisplay struct {
	page              int
	pageSize          int
	focusHost         string
	size              func() (int, int)
	idle              bool
	retryDescriptions map[string]string
	retryEnabled      map[string]bool
	pendingRetry      string
	notice            string
	requests          chan sessionRequest
	input             *os.File
	requestStop       func()
	confirmStop       bool
	help              bool
	stopping          bool
	commandBuffer     []byte
	mu                sync.Mutex
	writer            io.Writer
	hosts             map[string]*progressHost
	order             []string
	sequence          int
	paused            int
	closed            bool
	done              chan struct{}
	stopped           chan struct{}
}

func newProgressDisplay(writer io.Writer, devices []DeviceConfig) *progressDisplay {
	d := &progressDisplay{requests: make(chan sessionRequest, 1), writer: writer, hosts: map[string]*progressHost{}, done: make(chan struct{}), stopped: make(chan struct{})}
	for _, device := range devices {
		key := variableScopeKey(device.Hostname, device.IP)
		if _, ok := d.hosts[key]; ok {
			continue
		}
		name := strings.TrimSpace(device.Hostname)
		if name == "" {
			name = device.IP
		}
		d.hosts[key] = &progressHost{name: name, state: "QUEUED", category: "-", step: "-"}
		d.order = append(d.order, key)
	}
	return d
}

func (d *progressDisplay) start() {
	d.mu.Lock()
	d.draw(time.Now())
	d.mu.Unlock()
	go func() {
		defer close(d.stopped)
		keyboard := time.NewTicker(50 * time.Millisecond)
		defer keyboard.Stop()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-d.done:
				return
			case <-keyboard.C:
				d.readCommands()
			case now := <-ticker.C:
				d.mu.Lock()
				if d.paused == 0 {
					d.draw(now)
				}
				d.mu.Unlock()
			}
		}
	}()
}

func (d *progressDisplay) Handle(_ context.Context, e lifecycleEvent) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	h := d.hosts[variableScopeKey(e.Hostname, e.IP)]
	now := e.Timestamp
	if now.IsZero() {
		now = time.Now()
	}
	if h != nil {
		switch e.Type {
		case "device.started":
			h.state = "ACTIVE"
			h.category = "Connecting"
			h.step = "-"
			h.since = now
			h.completed = 0
			h.ended = time.Time{}
		case "step.started":
			category, _ := e.Data["category"].(string)
			if category == "" {
				category = "Uncategorised"
			}
			if category != h.category || (category == "Uncategorised" && e.Step != h.step) {
				h.since = now
			}
			h.category = category
			h.step = e.Step
		case "device.completed":
			h.state = "DONE"
			if e.Failed != nil && *e.Failed {
				h.state = "FAILED"
			}
			if e.Data["interrupted"] == true {
				h.state = "CANCELLED"
			}
			d.sequence++
			h.completed = d.sequence
			h.ended = now
		}
	}
	if e.Type == "run.completed" {
		for _, host := range d.hosts {
			if host.state == "QUEUED" || host.state == "ACTIVE" {
				host.state = "NOT RUN"
				if e.Data["interrupted"] == true {
					host.state = "CANCELLED"
				}
				d.sequence++
				host.completed = d.sequence
				host.ended = now
			}
		}
	}
	return nil
}

func progressText(value string, width int) string {
	if width <= 0 {
		return ""
	}
	var b strings.Builder
	for _, r := range value {
		if r >= 32 && r <= 126 {
			b.WriteRune(r)
		} else {
			b.WriteByte('?')
		}
	}
	s := b.String()
	if len(s) > width {
		s = s[:width-1] + "~"
	}
	return fmt.Sprintf("%-*s", width, s)
}

func (d *progressDisplay) render(now time.Time) string {
	width, height := d.dimensions()
	return d.renderSize(now, width, height)
}

func (d *progressDisplay) draw(now time.Time) { fmt.Fprint(d.writer, "\x1b[H\x1b[2J", d.render(now)) }

// Keep prompts readable while other hosts and timers continue in the background.
func (d *progressDisplay) pause() func() {
	if d == nil {
		return func() {}
	}
	d.mu.Lock()
	d.paused++
	d.mu.Unlock()
	return func() { d.mu.Lock(); d.paused--; d.mu.Unlock() }
}

func (d *progressDisplay) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	close(d.done)
	d.mu.Unlock()
	<-d.stopped
	d.mu.Lock()
	defer d.mu.Unlock()
	d.draw(time.Now())
	return nil
}

// Read only available terminal bytes, and never compete with a suspended prompt.
// Canonical terminal mode retains normal editing, echo and Ctrl+C handling.
func (d *progressDisplay) readCommands() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.paused > 0 || d.input == nil {
		return
	}
	// #nosec G115 -- operating-system descriptor used by poll.
	fds := []unix.PollFd{{Fd: int32(d.input.Fd()), Events: unix.POLLIN}}
	for count := 0; count < 128; count++ {
		n, err := unix.Poll(fds, 0)
		if err != nil || n == 0 || fds[0].Revents&unix.POLLIN == 0 {
			return
		}
		var b [1]byte
		if n, err := d.input.Read(b[:]); err != nil || n == 0 {
			return
		}
		if b[0] == '\n' {
			d.handleCommand(strings.TrimSpace(string(d.commandBuffer)))
			d.commandBuffer = nil
			if d.paused > 0 {
				return
			}
		} else if len(d.commandBuffer) < 64 {
			d.commandBuffer = append(d.commandBuffer, b[0])
		}
	}
}

// Called with the display lock held.
func (d *progressDisplay) handleCommand(command string) {
	if d.stopping {
		return
	}
	command = strings.ToLower(command)
	if d.pendingRetry != "" {
		if command == "y" || command == "yes" {
			width, height := d.dimensions()
			if width < 26 || len(d.menuLines(max(0, width-1))) > max(1, height-2) {
				d.notice = "Enlarge terminal to confirm retry."
				d.draw(time.Now())
				return
			}
		}
		host := d.pendingRetry
		d.pendingRetry = ""
		if command == "y" || command == "yes" {
			d.idle = false
			d.notice = ""
			d.requests <- sessionRequest{host: host}
		}
		d.draw(time.Now())
		return
	}
	if d.confirmStop {
		d.confirmStop = false
		if command == "y" || command == "yes" {
			d.stopping = true
			if d.idle {
				d.requests <- sessionRequest{quit: true}
			} else if d.requestStop != nil {
				d.requestStop()
			}
		}
	} else {
		switch command {
		case "q", "quit", "stop":
			d.confirmStop = true
		case "n", "next":
			d.page++
		case "p", "prev", "previous":
			d.page--
		case "first":
			d.page = 0
		case "last":
			d.page = len(d.order)
		case "h", "help", "?":
			d.help = !d.help
		default:
			fields := strings.Fields(command)
			if len(fields) == 2 && (fields[0] == "g" || fields[0] == "goto") {
				id, err := strconv.Atoi(fields[1])
				if err == nil && id >= 1 && id <= len(d.order) {
					d.focusHost = d.order[id-1]
				} else {
					d.notice = "Choose a host ID shown in the table."
				}
			} else if len(fields) == 2 && (fields[0] == "r" || fields[0] == "retry") {
				id, err := strconv.Atoi(fields[1])
				if !d.idle {
					d.notice = "Wait until current jobs finish before retrying a host."
				} else if err != nil || id < 1 || id > len(d.order) {
					d.notice = "Choose a host ID shown in the table."
				} else {
					key := d.order[id-1]
					if d.retryEnabled[key] {
						d.pendingRetry = key
						d.focusHost = key
						d.notice = ""
					} else {
						d.notice = d.retryDescriptions[key]
						if d.notice == "" {
							d.notice = "Only failed hosts with checkpoints can be retried."
						}
					}
				}
			}
		}
	}
	d.draw(time.Now())
}

func (d *progressDisplay) readyForRetries(descriptions map[string]string, enabled map[string]bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.idle = true
	d.retryDescriptions = descriptions
	d.retryEnabled = enabled
	for _, h := range d.hosts {
		if h.state == "QUEUED" {
			h.state = "NOT RUN"
			d.sequence++
			h.completed = d.sequence
			h.ended = time.Now()
		}
	}
	d.draw(time.Now())
}
