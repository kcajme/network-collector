package main

import (
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestProgressOrderingTimersAndTotals(t *testing.T) {
	devices := []DeviceConfig{{Hostname: "a", IP: "1"}, {Hostname: "b", IP: "2"}, {Hostname: "c", IP: "3"}}
	d := newProgressDisplay(io.Discard, devices)
	now := time.Unix(100, 0)
	emit := func(kind, host, ip, step, category string, at time.Time) {
		t.Helper()
		if err := d.Handle(context.Background(), lifecycleEvent{Type: kind, Hostname: host, IP: ip, Step: step, Timestamp: at, Data: map[string]interface{}{"category": category}}); err != nil {
			t.Fatal(err)
		}
	}
	emit("device.started", "a", "1", "", "", now)
	emit("step.started", "a", "1", "check", "precheck", now)
	emit("step.started", "a", "1", "second-check", "precheck", now.Add(5*time.Second))
	if !strings.Contains(d.render(now.Add(10*time.Second)), "10s") {
		t.Fatal("category timer reset for a step in the same category")
	}
	emit("device.started", "b", "2", "", "", now)
	emit("device.completed", "b", "2", "", "", now.Add(11*time.Second))
	emit("device.completed", "a", "1", "", "", now.Add(12*time.Second))
	rows := d.render(now.Add(time.Hour))
	positions := map[string]int{}
	for index, line := range strings.Split(rows, "\n") {
		fields := strings.Fields(strings.Trim(line, "| "))
		if len(fields) >= 3 && (fields[1] == "a" || fields[1] == "b" || fields[1] == "c") {
			positions[fields[1]] = index
		}
	}
	if len(positions) != 3 || positions["b"] >= positions["a"] || positions["a"] >= positions["c"] {
		t.Fatalf("completion order wrong:\n%s", rows)
	}
	for _, want := range []string{"Started: 2/3", "Complete: 2", "Failed: 0", "12s"} {
		if !strings.Contains(rows, want) {
			t.Fatalf("missing %q in %s", want, rows)
		}
	}
	d.Handle(context.Background(), lifecycleEvent{Type: "run.completed", Timestamp: now.Add(13 * time.Second)})
	rows = d.render(now.Add(time.Hour))
	if d.hosts[variableScopeKey("c", "3")].state != "NOT RUN" || !strings.Contains(rows, "Started: 2/3") {
		t.Fatal(rows)
	}
	// A recurring occurrence reuses its host row and starts fresh timers.
	emit("device.started", "a", "1", "", "", now.Add(time.Hour))
	if d.hosts[variableScopeKey("a", "1")].state != "ACTIVE" || !strings.Contains(d.render(now.Add(time.Hour)), "Started: 2/3") {
		t.Fatal("recurring host did not reset")
	}
}

func TestProgressCategoryChangeAndTerminalSafety(t *testing.T) {
	d := newProgressDisplay(io.Discard, []DeviceConfig{{Hostname: "evil\x1b[2J\nrouter", IP: "1"}})
	now := time.Unix(100, 0)
	for i, cat := range []string{"precheck", "install"} {
		d.Handle(context.Background(), lifecycleEvent{Type: "step.started", Hostname: "evil\x1b[2J\nrouter", IP: "1", Step: "step", Timestamp: now.Add(time.Duration(i) * time.Minute), Data: map[string]interface{}{"category": cat}})
	}
	text := d.render(now.Add(70 * time.Second))
	if strings.Contains(text, "\x1b") || !strings.Contains(text, "10s") {
		t.Fatal(text)
	}
	failed := true
	d.Handle(context.Background(), lifecycleEvent{Type: "device.completed", Hostname: "evil\x1b[2J\nrouter", IP: "1", Failed: &failed, Timestamp: now.Add(70 * time.Second)})
	if !strings.Contains(d.render(now.Add(time.Hour)), "Failed: 1") {
		t.Fatal("failed host not counted")
	}
}

func TestProgressConcurrentUpdatesAndPause(t *testing.T) {
	d := newProgressDisplay(io.Discard, []DeviceConfig{{Hostname: "a", IP: "1"}})
	d.start()
	resume := d.pause()
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				d.Handle(context.Background(), lifecycleEvent{Type: "step.started", Hostname: "a", IP: "1", Step: "check"})
			}
		}()
	}
	wg.Wait()
	resume()
	d.Close()
	d.Close()
}

type categoryCollector struct{ events []lifecycleEvent }

func (c *categoryCollector) Handle(_ context.Context, e lifecycleEvent) error {
	c.events = append(c.events, e)
	return nil
}
func (c *categoryCollector) Close() error { return nil }

func TestCategoryIsMetadataAndNestedStepsInherit(t *testing.T) {
	ctx, failed := interactionContext(t, map[string]string{})
	collector := &categoryCollector{}
	ctx.events = &eventDispatcher{sinks: []eventSink{collector}}
	steps := []StepConfig{{Name: "outer", Category: "precheck", Block: &BlockConfig{Steps: []StepConfig{
		{Name: "child", Command: "show version"}, {Name: "override", Command: "show install", Category: "install"},
	}}}, {Name: "after", Command: "show version"}}
	if err := preflightDeviceVariables(DeviceConfig{Steps: steps}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if executeSteps(ctx, nil, steps) || *failed {
		t.Fatal("metadata affected execution")
	}
	categories := map[string]string{}
	for _, e := range collector.events {
		if e.Type == "step.started" {
			categories[e.Step], _ = e.Data["category"].(string)
		}
	}
	if categories["child"] != "precheck" || categories["override"] != "install" || categories["after"] != "" {
		t.Fatalf("wrong categories: %v", categories)
	}
}

func TestCompactCountsTrackUniqueHostsThatBecameActive(t *testing.T) {
	d := newProgressDisplay(io.Discard, []DeviceConfig{{Hostname: "a", IP: "1"}, {Hostname: "b", IP: "2"}, {Hostname: "c", IP: "3"}})
	emit := func(kind, host, ip string, failed *bool) {
		t.Helper()
		d.Handle(context.Background(), lifecycleEvent{Type: kind, Hostname: host, IP: ip, Failed: failed})
	}
	check := func(want string) {
		t.Helper()
		frame := d.render(time.Now())
		if !strings.Contains(frame, want) {
			t.Fatalf("missing %q: %s", want, frame)
		}
	}
	check("Started: 0/3 | Complete: 0 | Failed: 0")
	emit("device.started", "a", "1", nil)
	emit("device.started", "b", "2", nil)
	failed := true
	emit("device.completed", "a", "1", nil)
	emit("device.completed", "b", "2", &failed)
	check("Started: 2/3 | Complete: 1 | Failed: 1")
	emit("device.started", "b", "2", nil)
	check("Started: 2/3 | Complete: 1 | Failed: 0")
	emit("device.completed", "b", "2", nil)
	check("Started: 2/3 | Complete: 2 | Failed: 0")
	// The third host has never reached ACTIVE, so it remains outside the numerator.
	emit("run.completed", "", "", nil)
	check("Started: 2/3 | Complete: 2 | Failed: 0")
}
