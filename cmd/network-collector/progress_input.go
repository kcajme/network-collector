package main

import (
	"log/slog"
	"strings"

	"golang.org/x/term"
)

// Terminal state is also saved by the process cancellation controller, so a
// bounded forced shutdown can restore echo even during a blocked transport.
func (d *progressDisplay) enableInput() {
	if d.input == nil || d.rawInput {
		return
	}
	// #nosec G115 -- x/term requires an OS descriptor as int.
	state, err := term.MakeRaw(int(d.input.Fd()))
	if err != nil {
		slog.Warn("cannot activate terminal menu input", "error", err)
		return
	}
	if d.inputState == nil {
		d.inputState = state
	}
	d.rawInput = true
}

func (d *progressDisplay) restoreInput() {
	if !d.rawInput || d.input == nil || d.inputState == nil {
		return
	}
	// #nosec G115 -- operating-system descriptor used by x/term.
	_ = term.Restore(int(d.input.Fd()), d.inputState)
	d.rawInput = false
}

// Returns true when the editable command line changed. Time and redraws never
// clear it. Commands execute only on Enter, preserving the existing menu model.
func (d *progressDisplay) acceptCommandByte(value byte) bool {
	// Nano-style controls execute without submitting or losing the draft line.
	switch value {
	case 22:
		d.escapeInput = nil
		d.page++
		return true // Ctrl+V.
	case 25:
		d.escapeInput = nil
		d.page--
		return true // Ctrl+Y.
	case 7:
		d.escapeInput = nil
		d.help = !d.help
		return true // Ctrl+G.
	case 24:
		d.escapeInput = nil
		d.pendingRetry = ""
		d.confirmStop = true
		d.commandBuffer = nil
		d.commandCursor = 0
		return true // Ctrl+X.
	case 18, 23:
		d.escapeInput = nil
		if d.confirmStop || d.pendingRetry != "" || d.stopping {
			return false
		}
		if value == 18 && !d.idle {
			d.notice = "Retry is available after current jobs finish."
			return true
		}
		d.commandBuffer = []byte("r ")
		if value == 23 {
			d.commandBuffer = []byte("g ")
		}
		d.commandCursor = len(d.commandBuffer)
		d.notice = "Enter a host ID, then press Enter."
		return true
	}

	if len(d.escapeInput) > 0 {
		d.escapeInput = append(d.escapeInput, value)
		if len(d.escapeInput) == 2 && (value == '[' || value == 'O') {
			return false
		}
		if len(d.escapeInput) > 8 {
			d.escapeInput = nil
			return false
		}
		if value >= 0x40 && value <= 0x7e {
			sequence := string(d.escapeInput)
			d.escapeInput = nil
			switch sequence {
			case "\x1b[D":
				d.commandCursor = max(0, d.commandCursor-1)
			case "\x1b[C":
				d.commandCursor = min(len(d.commandBuffer), d.commandCursor+1)
			case "\x1b[H", "\x1bOH", "\x1b[1~":
				d.commandCursor = 0
			case "\x1b[F", "\x1bOF", "\x1b[4~":
				d.commandCursor = len(d.commandBuffer)
			case "\x1b[3~":
				if d.commandCursor < len(d.commandBuffer) {
					d.commandBuffer = append(d.commandBuffer[:d.commandCursor], d.commandBuffer[d.commandCursor+1:]...)
				}
			}
			return true
		}
		return false
	}
	switch value {
	case 27:
		d.escapeInput = []byte{value}
		return false
	case '\r', '\n':
		command := strings.TrimSpace(string(d.commandBuffer))
		d.commandBuffer = nil
		d.commandCursor = 0
		if command != "" {
			d.handleCommand(command)
		}
		return true
	case 3:
		return false // Ctrl+C intentionally does not quit the menu.
	case 21:
		d.commandBuffer = nil
		d.commandCursor = 0
		return true // Ctrl+U.
	case 1:
		d.commandCursor = 0
		return true
	case 5:
		d.commandCursor = len(d.commandBuffer)
		return true
	case 8, 127:
		if d.commandCursor > 0 {
			d.commandBuffer = append(d.commandBuffer[:d.commandCursor-1], d.commandBuffer[d.commandCursor:]...)
			d.commandCursor--
		}
		return true
	default:
		if value >= 32 && value <= 126 && len(d.commandBuffer) < 64 {
			d.commandBuffer = append(d.commandBuffer, 0)
			copy(d.commandBuffer[d.commandCursor+1:], d.commandBuffer[d.commandCursor:])
			d.commandBuffer[d.commandCursor] = value
			d.commandCursor++
			return true
		}
	}
	return false
}

func (d *progressDisplay) commandLine(width int) (string, int) {
	if width < 1 {
		return "", 0
	}
	prefix := "Command> "
	if width < 20 {
		prefix = "> "
	}
	if width <= len(prefix) {
		return progressLine(prefix, width), max(0, width-1)
	}
	available := width - len(prefix)
	start := max(0, d.commandCursor-available+1)
	end := min(len(d.commandBuffer), start+available)
	return prefix + string(d.commandBuffer[start:end]), len(prefix) + d.commandCursor - start
}
