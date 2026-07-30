package cmd

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const progressWidth = 28

// progress renders a single-line progress bar on stderr as hosts are processed.
// It deliberately writes to stderr only, so it never corrupts the JSON results
// streamed to stdout, and it draws nothing unless stderr is a real terminal.
type progress struct {
	total   int
	done    int32
	enabled bool
	start   time.Time
	mu      sync.Mutex
}

func newProgress(total int, disabled bool) *progress {
	return &progress{
		total:   total,
		enabled: !disabled && total > 0 && isTerminal(os.Stderr),
		start:   time.Now(),
	}
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// inc marks one host as processed and redraws the bar. Safe on a nil receiver.
func (p *progress) inc() {
	if p == nil {
		return
	}
	n := atomic.AddInt32(&p.done, 1)
	if !p.enabled {
		return
	}
	p.render(int(n))
}

// processed returns how many hosts have completed. It is counted even when the
// bar itself is disabled, so the interrupt path can report what was skipped.
func (p *progress) processed() int32 {
	if p == nil {
		return 0
	}
	return atomic.LoadInt32(&p.done)
}

// line formats the static part of the bar (no rate/time), so it is pure and
// testable.
func (p *progress) line(done int) string {
	if done > p.total {
		done = p.total
	}
	frac := float64(done) / float64(p.total)
	filled := int(frac * float64(progressWidth))
	bar := strings.Repeat("=", filled)
	if filled < progressWidth {
		bar += ">" + strings.Repeat(" ", progressWidth-filled-1)
	}
	return fmt.Sprintf("[%s] %d/%d hosts %3.0f%%", bar, done, p.total, frac*100)
}

func (p *progress) render(done int) {
	var rate float64
	if el := time.Since(p.start).Seconds(); el > 0 {
		rate = float64(done) / el
	}
	// \r returns to the start of the line; trailing spaces clear any leftovers.
	p.mu.Lock()
	fmt.Fprintf(os.Stderr, "\r%s %.1f/s   ", p.line(done), rate)
	p.mu.Unlock()
}

// finish ends the bar line so later output starts on a fresh line.
func (p *progress) finish() {
	if p == nil || !p.enabled {
		return
	}
	fmt.Fprintln(os.Stderr)
}
