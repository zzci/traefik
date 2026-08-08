package main

import (
	"os"
	"testing"
	"time"
)

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

func testLimiter(attempts int, window time.Duration) (*rateLimiter, *time.Time) {
	now := time.Now()
	rl := newRateLimiter(attempts, window)
	rl.now = func() time.Time { return now }
	return rl, &now
}

func TestRateLimiterBlocksAfterLimit(t *testing.T) {
	rl, _ := testLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !rl.allow("k") {
			t.Fatalf("attempt %d should be allowed", i)
		}
		rl.fail("k")
	}
	if rl.allow("k") {
		t.Fatal("should be blocked after 3 failures")
	}
}

func TestRateLimiterWindowExpiry(t *testing.T) {
	rl, now := testLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		rl.fail("k")
	}
	if rl.allow("k") {
		t.Fatal("should be blocked")
	}
	*now = now.Add(61 * time.Second)
	if !rl.allow("k") {
		t.Fatal("should be allowed after window expiry")
	}
}

func TestRateLimiterReset(t *testing.T) {
	rl, _ := testLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		rl.fail("k")
	}
	rl.reset("k")
	if !rl.allow("k") {
		t.Fatal("should be allowed after reset")
	}
}

func TestRateLimiterIndependentKeys(t *testing.T) {
	rl, _ := testLimiter(1, time.Minute)
	rl.fail("a")
	if rl.allow("a") {
		t.Fatal("a should be blocked")
	}
	if !rl.allow("b") {
		t.Fatal("b should be unaffected")
	}
}

func TestRateLimiterFailStartsNewWindowAfterExpiry(t *testing.T) {
	rl, now := testLimiter(2, time.Minute)
	rl.fail("k")
	*now = now.Add(2 * time.Minute)
	rl.fail("k")
	if !rl.allow("k") {
		t.Fatal("old window failures should not count")
	}
}

func TestRateLimiterSweepDropsExpired(t *testing.T) {
	rl, now := testLimiter(3, time.Minute)
	rl.fail("old")
	*now = now.Add(2 * time.Minute)
	rl.fail("fresh")
	rl.mu.Lock()
	rl.sweepLocked(rl.now())
	rl.mu.Unlock()
	if _, ok := rl.entries["old"]; ok {
		t.Fatal("expired entry should be swept")
	}
	if _, ok := rl.entries["fresh"]; !ok {
		t.Fatal("fresh entry should survive sweep")
	}
}
