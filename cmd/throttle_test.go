package cmd

import (
	"testing"
	"time"
)

func TestHostThrottleDisabled(t *testing.T) {
	if newHostThrottle(0, 0) != nil {
		t.Fatalf("expected nil throttle when rps and jitter are 0")
	}
	var nilT *hostThrottle
	nilT.wait("example.com") // must not panic
}

func TestHostThrottlePacesPerHost(t *testing.T) {
	// rps=100 -> 10ms between requests to the same host.
	th := newHostThrottle(100, 0)

	start := time.Now()
	for i := 0; i < 5; i++ {
		th.wait("a.example")
	}
	elapsed := time.Since(start)
	// 4 gaps * 10ms = 40ms; allow scheduler slack but require real pacing.
	if elapsed < 30*time.Millisecond {
		t.Errorf("5 same-host requests took %v, expected pacing >= ~30ms", elapsed)
	}
}

func TestHostThrottleIndependentHosts(t *testing.T) {
	// Different hosts must not be serialised against each other.
	th := newHostThrottle(20, 0) // 50ms spacing per host
	start := time.Now()
	for i := 0; i < 5; i++ {
		th.wait("host-" + string(rune('a'+i)))
	}
	if elapsed := time.Since(start); elapsed > 30*time.Millisecond {
		t.Errorf("first request to 5 distinct hosts took %v, expected near-immediate", elapsed)
	}
}
