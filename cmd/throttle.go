package cmd

import (
	"math/rand"
	"sync"
	"time"
)

// hostThrottle paces outbound HTTP requests per host so a scan stays under a
// target's rate-based WAF rules. Each host has its own schedule: a request is
// released no sooner than `interval` after the previously reserved one for that
// host, plus an optional random jitter so the cadence isn't metronomic.
//
// The slot reservation happens under a short lock; the actual wait runs outside
// it, so concurrent requests to different hosts never block one another and
// concurrent requests to the same host are fanned out into evenly spaced slots.
type hostThrottle struct {
	mu       sync.Mutex
	next     map[string]time.Time
	interval time.Duration
	jitter   time.Duration
}

// newHostThrottle returns nil (a no-op) when neither pacing nor jitter is
// requested, so the default configuration adds zero overhead.
func newHostThrottle(rps float64, jitterMs int) *hostThrottle {
	if rps <= 0 && jitterMs <= 0 {
		return nil
	}
	t := &hostThrottle{next: make(map[string]time.Time)}
	if rps > 0 {
		t.interval = time.Duration(float64(time.Second) / rps)
	}
	if jitterMs > 0 {
		t.jitter = time.Duration(jitterMs) * time.Millisecond
	}
	return t
}

// wait blocks until this request is allowed to go out to host. It is safe to
// call on a nil *hostThrottle (the disabled case).
func (t *hostThrottle) wait(host string) {
	if t == nil {
		return
	}
	now := time.Now()

	t.mu.Lock()
	start := now
	if earliest, ok := t.next[host]; ok && earliest.After(start) {
		start = earliest
	}
	t.next[host] = start.Add(t.interval)
	t.mu.Unlock()

	delay := time.Until(start)
	if t.jitter > 0 {
		delay += time.Duration(rand.Int63n(int64(t.jitter)))
	}
	if delay > 0 {
		time.Sleep(delay)
	}
}
