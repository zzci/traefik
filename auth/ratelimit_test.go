package main

import (
	"os"
	"testing"
	"time"
)

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

func testLimiter() (*rateLimiter, *time.Time) {
	now := time.Now()
	rl := newRateLimiter()
	rl.now = func() time.Time { return now }
	return rl, &now
}

func TestRateLimiterBlocksAfterLimit(t *testing.T) {
	rl, _ := testLimiter()
	for i := 0; i < 3; i++ {
		if !rl.allow("k", 3, time.Minute) {
			t.Fatalf("attempt %d should be allowed", i)
		}
		rl.fail("k", time.Minute)
	}
	if rl.allow("k", 3, time.Minute) {
		t.Fatal("should be blocked after 3 failures")
	}
}

func TestRateLimiterWindowExpiry(t *testing.T) {
	rl, now := testLimiter()
	for i := 0; i < 3; i++ {
		rl.fail("k", time.Minute)
	}
	if rl.allow("k", 3, time.Minute) {
		t.Fatal("should be blocked")
	}
	*now = now.Add(61 * time.Second)
	if !rl.allow("k", 3, time.Minute) {
		t.Fatal("should be allowed after window expiry")
	}
}

func TestRateLimiterReset(t *testing.T) {
	rl, _ := testLimiter()
	for i := 0; i < 3; i++ {
		rl.fail("k", time.Minute)
	}
	rl.reset("k")
	if !rl.allow("k", 3, time.Minute) {
		t.Fatal("should be allowed after reset")
	}
}

func TestRateLimiterIndependentKeys(t *testing.T) {
	rl, _ := testLimiter()
	rl.fail("a", time.Minute)
	if rl.allow("a", 1, time.Minute) {
		t.Fatal("a should be blocked")
	}
	if !rl.allow("b", 1, time.Minute) {
		t.Fatal("b should be unaffected")
	}
}

func TestRateLimiterFailStartsNewWindowAfterExpiry(t *testing.T) {
	rl, now := testLimiter()
	rl.fail("k", time.Minute)
	*now = now.Add(2 * time.Minute)
	rl.fail("k", time.Minute)
	if !rl.allow("k", 2, time.Minute) {
		t.Fatal("old window failures should not count")
	}
}

func TestRateLimiterLimitChangeAppliesImmediately(t *testing.T) {
	rl, _ := testLimiter()
	for i := 0; i < 3; i++ {
		rl.fail("k", time.Minute)
	}
	if rl.allow("k", 3, time.Minute) {
		t.Fatal("blocked at limit 3")
	}
	// hot-reloaded config raised the limit: same state, new verdict
	if !rl.allow("k", 5, time.Minute) {
		t.Fatal("allowed at limit 5 without reset")
	}
}

func TestRateLimiterSweepDropsExpired(t *testing.T) {
	rl, now := testLimiter()
	rl.fail("old", time.Minute)
	*now = now.Add(2 * time.Minute)
	rl.fail("fresh", time.Minute)
	rl.mu.Lock()
	rl.sweepLocked(rl.now(), time.Minute)
	rl.mu.Unlock()
	if _, ok := rl.entries["old"]; ok {
		t.Fatal("expired entry should be swept")
	}
	if _, ok := rl.entries["fresh"]; !ok {
		t.Fatal("fresh entry should survive sweep")
	}
}
