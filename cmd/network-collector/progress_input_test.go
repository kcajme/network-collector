package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"
)

func TestMenuDraftSurvivesRepeatedRefreshes(t *testing.T) {
	var out bytes.Buffer
	d := newProgressDisplay(&out, nil)
	d.input = os.Stdin
	d.size = func() (int, int) { return 80, 24 }
	d.acceptCommandByte('Q')
	for i := 0; i < 4; i++ {
		d.draw(time.Unix(int64(100+i), 0))
	}
	if string(d.commandBuffer) != "Q" || strings.Count(out.String(), "Command> Q") != 4 {
		t.Fatal("redraw erased the pending command")
	}
	if d.confirmStop {
		t.Fatal("command executed before Enter")
	}
	d.acceptCommandByte('\r')
	if !d.confirmStop || len(d.commandBuffer) != 0 {
		t.Fatal("Enter did not submit the pending command")
	}
	d.acceptCommandByte('N')
	d.draw(time.Now())
	d.acceptCommandByte('\n')
	if d.confirmStop || d.stopping {
		t.Fatal("declining confirmation failed")
	}
}

func TestMenuLineEditingAndControlCharacters(t *testing.T) {
	d := newProgressDisplay(&bytes.Buffer{}, nil)
	for _, b := range []byte("r 12\x1b[D\x7f0") {
		d.acceptCommandByte(b)
	}
	if string(d.commandBuffer) != "r 02" || d.commandCursor != 3 {
		t.Fatalf("editing failed: %q at %d", d.commandBuffer, d.commandCursor)
	}
	d.acceptCommandByte(1)
	d.acceptCommandByte(5)
	if d.commandCursor != len(d.commandBuffer) {
		t.Fatal("end navigation failed")
	}
	d.acceptCommandByte(3)
	if string(d.commandBuffer) != "r 02" || d.stopping {
		t.Fatal("Ctrl+C changed or quit the menu")
	}
	d.acceptCommandByte(21)
	if len(d.commandBuffer) != 0 || d.commandCursor != 0 {
		t.Fatal("Ctrl+U failed to clear line")
	}
	for i := 0; i < 100; i++ {
		d.acceptCommandByte('x')
	}
	if len(d.commandBuffer) != 64 {
		t.Fatal("command length limit lost")
	}
	for width := 1; width <= 100; width++ {
		line, cursor := d.commandLine(width)
		if len(line) > width || cursor < 0 || cursor >= width {
			t.Fatalf("input line overflow at width %d: %q cursor %d", width, line, cursor)
		}
	}
}

func TestProgressUsesBoundedAsciiFrame(t *testing.T) {
	d := layoutFixture()
	frame := d.renderSize(time.Now(), 80, 24)
	lines := strings.Split(strings.TrimSuffix(frame, "\n"), "\n")
	if !strings.HasPrefix(lines[0], "+---") || !strings.HasPrefix(lines[len(lines)-1], "+---") {
		t.Fatal("ASCII frame missing")
	}
	if !strings.Contains(frame, "[Q]") || !strings.Contains(frame, "[N/P]") {
		t.Fatal("shortcut legend missing")
	}
	assertFrameFits(t, frame, 80, 24)
	for _, r := range frame {
		if r > 127 {
			t.Fatal("frame contains non-ASCII decoration")
		}
	}
}
