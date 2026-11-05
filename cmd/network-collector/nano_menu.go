package main

import (
	"regexp"
	"strings"
)

// Each column is a pair, matching Nano's Help/Exit arrangement on two rows.
func nanoMenuLines(width int) []string {
	if width < 1 {
		return nil
	}
	pairs := [][2]string{
		{"^G Help", "^X Exit"},
		{"^R Retry Host", "^W Find Host"},
		{"^Y Prev Page", "^V Next Page"},
	}
	columns := 1
	if width >= 39 {
		columns = 3
	} else if width >= 26 {
		columns = 2
	}
	cellWidth := width / columns
	var lines []string
	for first := 0; first < len(pairs); first += columns {
		for row := 0; row < 2; row++ {
			var line strings.Builder
			for column := first; column < min(first+columns, len(pairs)); column++ {
				line.WriteString(progressText(pairs[column][row], cellWidth))
			}
			lines = append(lines, strings.TrimRight(line.String(), " "))
		}
	}
	return lines
}

var nanoCaretKey = regexp.MustCompile(`\^[A-Z]`)

// Keep the layout representation plain ASCII for width calculations; terminal
// reverse-video styling is applied only when drawing the shortcut strip.
func styleNanoMenu(frame string) string {
	lines := strings.Split(frame, "\n")
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimLeft(line, "| "), "^") {
			lines[i] = nanoCaretKey.ReplaceAllStringFunc(line, func(key string) string { return "\x1b[7m" + key + "\x1b[0m" })
		}
	}
	return strings.Join(lines, "\n")
}
