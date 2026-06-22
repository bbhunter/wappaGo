package cmd

import (
	"strings"
	"testing"
)

func TestProgressLine(t *testing.T) {
	p := &progress{total: 10}

	empty := p.line(0)
	if !strings.Contains(empty, "0/10 hosts") || !strings.Contains(empty, "0%") || !strings.Contains(empty, ">") {
		t.Errorf("empty bar = %q", empty)
	}
	half := p.line(5)
	if !strings.Contains(half, "5/10 hosts") || !strings.Contains(half, "50%") {
		t.Errorf("half bar = %q", half)
	}
	full := p.line(10)
	if !strings.Contains(full, "10/10 hosts") || !strings.Contains(full, "100%") || strings.Contains(full, ">") {
		t.Errorf("full bar should be complete with no cursor: %q", full)
	}
	if over := p.line(99); !strings.Contains(over, "10/10 hosts") {
		t.Errorf("done must cap at total: %q", over)
	}
}

func TestProgressDisabledNoPanic(t *testing.T) {
	var nilP *progress
	nilP.inc()
	nilP.finish() // must not panic on a nil receiver

	off := newProgress(0, false) // total 0 -> disabled
	if off.enabled {
		t.Errorf("progress with 0 total should be disabled")
	}
	off.inc()
	off.finish()
}
