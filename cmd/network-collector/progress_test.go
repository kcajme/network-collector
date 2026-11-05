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
	if strings.Index(rows, "b                  DONE") > strings.Index(rows, "a                  DONE") || strings.Index(rows, "a                  DONE") > strings.Index(rows, "c                  QUEUED") {
		t.Fatalf("completion order wrong:\n%s", rows)
	}
	for _, want := range []string{"Total: 3", "Remaining: 1", "Done: 2", "12s"} {
		if !strings.Contains(rows, want) {
			t.Fatalf("missing %q in %s", want, rows)
		}
	}
	d.Handle(context.Background(), lifecycleEvent{Type: "run.completed", Timestamp: now.Add(13 * time.Second)})
	rows = d.render(now.Add(time.Hour))
	if !strings.Contains(rows, "Not run: 1") || !strings.Contains(rows, "Remaining: 0") {
		t.Fatal(rows)
	}
	// A recurring occurrence reuses its host row and starts fresh timers.
	emit("device.started", "a", "1", "", "", now.Add(time.Hour))
	if !strings.Contains(d.render(now.Add(time.Hour)), "Active: 1") {
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
