package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"golang.org/x/term"
)

func (d *progressDisplay) dimensions() (int, int) {
	if d.size != nil {
		return d.size()
	}
	if file, ok := d.writer.(*os.File); ok {
		// #nosec G115 -- x/term requires an OS descriptor as int.
		if width, height, err := term.GetSize(int(file.Fd())); err == nil && width > 0 && height > 0 {
			return width, height
		}
	}
	return 80, 24
}

func (d *progressDisplay) sortedHosts() []string {
	rows := append([]string(nil), d.order...)
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
	return rows
}

// All display text is ASCII, so byte length equals terminal cell width.
func progressLine(text string, width int) string {
	return strings.TrimRight(progressText(text, width), " ")
}

func wrapProgress(text string, width int) []string {
	if width < 1 {
		return nil
	}
	text = strings.TrimSpace(progressLine(text, len(text)))
	var lines []string
	for len(text) > width {
		split := strings.LastIndex(text[:width+1], " ")
		if split < 1 {
			split = width
		}
		lines = append(lines, text[:split])
		text = strings.TrimSpace(text[split:])
	}
	if text != "" {
		lines = append(lines, text)
	}
	return lines
}

func (d *progressDisplay) menuLines(width int) []string {
	if d.closed {
		return nil
	}
	message := ""
	switch {
	case d.pendingRetry != "":
		id := 0
		for i, key := range d.order {
			if key == d.pendingRetry {
				id = i + 1
				break
			}
		}
		message = fmt.Sprintf("Retry ID %d may resend a command. Verify remote state. Confirm y/N", id)
	case d.stopping:
		message = "Stopping operation..."
	case d.confirmStop:
		if d.idle {
			message = "Exit application? y=yes / n=stay"
		} else {
			message = "Stop operation? y=yes / n=continue"
		}
	case d.input != nil:
		if d.idle {
			if width >= 65 {
				message = "Jobs finished. r ID retry | q exit | h help | n/p pages"
			} else {
				message = "r ID retry | q exit | n/p pages | h help"
			}
		} else {
			message = "q stop | h help | n/p pages"
		}
	}
	return wrapProgress(message, width)
}

// Leave the last column unused to prevent auto-wrap, and two rows for command input and its Enter key.
// Footer space is reserved before calculating the number of visible hosts.
func (d *progressDisplay) renderSize(now time.Time, terminalWidth, terminalHeight int) string {
	width := max(0, terminalWidth-1)
	height := max(1, terminalHeight-2)
	if width == 0 {
		return ""
	}
	rows := d.sortedHosts()
	counts := map[string]int{}
	ids := map[string]int{}
	for i, key := range d.order {
		counts[d.hosts[key].state]++
		ids[key] = i + 1
	}
	menu := d.menuLines(width)
	var summary []string
	if width >= 65 {
		summary = []string{
			fmt.Sprintf("Total: %d | Active: %d | Queued: %d | Remaining: %d", len(rows), counts["ACTIVE"], counts["QUEUED"], counts["ACTIVE"]+counts["QUEUED"]),
			fmt.Sprintf("Done: %d | Failed: %d | Not run: %d | Cancelled: %d", counts["DONE"], counts["FAILED"], counts["NOT RUN"], counts["CANCELLED"]),
		}
	} else {
		summary = []string{
			fmt.Sprintf("Total %d Active %d Queued %d Left %d", len(rows), counts["ACTIVE"], counts["QUEUED"], counts["ACTIVE"]+counts["QUEUED"]),
			fmt.Sprintf("Done %d Fail %d NotRun %d Cancel %d", counts["DONE"], counts["FAILED"], counts["NOT RUN"], counts["CANCELLED"]),
		}
	}
	footer := []string{}
	for _, line := range summary {
		footer = append(footer, wrapProgress(line, width)...)
	}
	if d.notice != "" {
		footer = append(footer, wrapProgress(d.notice, width)...)
	}
	if d.help {
		help := "n/p next/previous page | first/last | g ID find host. Commands need Enter. Quit does not undo device changes."
		if width < 65 {
			help = "n/p pages | first/last | g ID jump"
		}
		footer = append(footer, wrapProgress(help, width)...)
	}
	footer = append(footer, menu...)
	// Two header rows, viewport indicator, and at least one host need four rows.
	capacity := height - 2 - 1 - len(footer)
	if capacity < 1 || width < 25 {
		d.pageSize = 0
		d.page = max(0, d.page)
		if !d.closed && d.input != nil && d.pendingRetry == "" && !d.confirmStop && !d.stopping {
			menu = wrapProgress("q quit | h help", width)
		}
		compact := []string{"Enlarge terminal for host table.", fmt.Sprintf("Total %d Left %d Failed %d", len(rows), counts["ACTIVE"]+counts["QUEUED"], counts["FAILED"])}
		if d.pendingRetry != "" && (width < 25 || len(menu) > height) {
			menu = wrapProgress("Enlarge terminal to confirm retry. n cancels.", width)
		}
		if len(menu) >= height {
			compact = nil
			menu = menu[len(menu)-min(len(menu), height):]
		}
		compact = compact[:min(len(compact), max(0, height-len(menu)))]
		compact = append(compact, menu...)
		return finishProgress(compact, width, height, terminalHeight)
	}
	d.pageSize = capacity
	pages := max(1, (len(rows)+capacity-1)/capacity)
	if d.focusHost != "" {
		for i, key := range rows {
			if key == d.focusHost {
				d.page = i / capacity
				break
			}
		}
		d.focusHost = ""
	}
	d.page = max(0, min(d.page, pages-1))
	start := min(len(rows), d.page*capacity)
	end := min(len(rows), start+capacity)
	header := d.hostLine("ID", "HOST", "STATE", "CATEGORY", "STEP", "TIME", width)
	lines := []string{"NETWORK COLLECTOR - operation progress", header}
	for _, key := range rows[start:end] {
		h := d.hosts[key]
		elapsed := "-"
		if !h.since.IsZero() {
			endTime := now
			if h.completed > 0 {
				endTime = h.ended
			}
			elapsed = endTime.Sub(h.since).Truncate(time.Second).String()
		}
		lines = append(lines, d.hostLine(strconvID(ids[key]), h.name, h.state, h.category, h.step, elapsed, width))
	}
	first := start + 1
	if len(rows) == 0 {
		first = 0
	}
	lines = append(lines, fmt.Sprintf("Hosts %d-%d of %d | Page %d/%d | n/p pages", first, end, len(rows), d.page+1, pages))
	lines = append(lines, footer...)
	return finishProgress(lines, width, height, terminalHeight)
}

func strconvID(id int) string { return fmt.Sprintf("%d", id) }

func (d *progressDisplay) hostLine(id, host, state, category, step, elapsed string, width int) string {
	idWidth := max(2, len(strconvID(max(1, len(d.order)))))
	// Narrow views progressively remove optional columns while keeping IDs,
	// state and elapsed time. Full labels remain in the config and disk logs.
	switch {
	case width >= 75:
		remaining := width - idWidth - 9 - 10 - 5
		hostWidth := max(12, remaining*30/100)
		categoryWidth := max(10, remaining*25/100)
		stepWidth := remaining - hostWidth - categoryWidth
		return fmt.Sprintf("%s %s %s %s %s %s", progressText(id, idWidth), progressText(host, hostWidth), progressText(state, 9), progressText(category, categoryWidth), progressText(step, stepWidth), progressText(elapsed, 10))
	case width >= 50:
		remaining := width - idWidth - 9 - 8 - 4
		hostWidth := remaining * 45 / 100
		return fmt.Sprintf("%s %s %s %s %s", progressText(id, idWidth), progressText(host, hostWidth), progressText(state, 9), progressText(step, remaining-hostWidth), progressText(elapsed, 8))
	default:
		hostWidth := width - idWidth - 9 - 8 - 3
		return fmt.Sprintf("%s %s %s %s", progressText(id, idWidth), progressText(host, hostWidth), progressText(state, 9), progressText(elapsed, 8))
	}
}

func finishProgress(lines []string, width, height, terminalHeight int) string {
	for i := range lines {
		lines[i] = progressLine(lines[i], width)
	}
	if len(lines) > height {
		lines = lines[:height]
	}
	result := strings.Join(lines, "\n")
	if terminalHeight > 1 && len(lines) > 0 {
		result += "\n"
	}
	return result
}
