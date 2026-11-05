package main

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
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
	mu       sync.Mutex
	writer   io.Writer
	hosts    map[string]*progressHost
	order    []string
	sequence int
	paused   int
	closed   bool
	done     chan struct{}
	stopped  chan struct{}
}

func newProgressDisplay(writer io.Writer, devices []DeviceConfig) *progressDisplay {
	d := &progressDisplay{writer: writer, hosts: map[string]*progressHost{}, done: make(chan struct{}), stopped: make(chan struct{})}
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
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-d.done:
				return
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
	rows := append([]string(nil), d.order...)
	// Finished hosts first, oldest completion at the top; new completions append.
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := d.hosts[rows[i]], d.hosts[rows[j]]
		if (a.completed > 0) != (b.completed > 0) {
			return a.completed > 0
		}
		if a.completed > 0 {
			return a.completed < b.completed
		}
		return false
	})
	var out strings.Builder
	fmt.Fprintln(&out, "NETWORK COLLECTOR - operation progress")
	fmt.Fprintln(&out, "HOST               STATE     CATEGORY       STEP                 STAGE TIME")
	fmt.Fprintln(&out, strings.Repeat("-", 78))
	counts := map[string]int{}
	for _, key := range rows {
		h := d.hosts[key]
		counts[h.state]++
		elapsed := "-"
		if !h.since.IsZero() {
			elapsed = now.Sub(h.since).Truncate(time.Second).String()
			if h.completed > 0 {
				elapsed = h.ended.Sub(h.since).Truncate(time.Second).String()
			}
		}
		fmt.Fprintf(&out, "%s %s %s %s %s\n", progressText(h.name, 18), progressText(h.state, 9), progressText(h.category, 14), progressText(h.step, 20), elapsed)
	}
	fmt.Fprintln(&out, strings.Repeat("-", 78))
	fmt.Fprintf(&out, "Total: %d | Active: %d | Queued: %d | Remaining: %d\n", len(rows), counts["ACTIVE"], counts["QUEUED"], counts["ACTIVE"]+counts["QUEUED"])
	fmt.Fprintf(&out, "Done: %d | Failed: %d | Not run: %d | Cancelled: %d\n", counts["DONE"], counts["FAILED"], counts["NOT RUN"], counts["CANCELLED"])
	return out.String()
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
