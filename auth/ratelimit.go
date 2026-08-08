package main

import (
	"sync"
	"time"
)

// rateLimiter is a fixed-window failure counter keyed by string
// (e.g. "ip:1.2.3.4", "user:admin"). Only failures count against the
// limit; a successful login resets its key.
type rateLimiter struct {
	mu       sync.Mutex
	attempts int
	window   time.Duration
	now      func() time.Time
	entries  map[string]*rlEntry
}

type rlEntry struct {
	count int
	start time.Time
}

const rlSweepThreshold = 4096

func newRateLimiter(attempts int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		attempts: attempts,
		window:   window,
		now:      time.Now,
		entries:  map[string]*rlEntry{},
	}
}

// allow reports whether key is currently under the failure limit.
func (r *rateLimiter) allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[key]
	if !ok {
		return true
	}
	if r.now().Sub(e.start) >= r.window {
		delete(r.entries, key)
		return true
	}
	return e.count < r.attempts
}

// fail records a failed attempt for key.
func (r *rateLimiter) fail(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	e, ok := r.entries[key]
	if !ok || now.Sub(e.start) >= r.window {
		if len(r.entries) >= rlSweepThreshold {
			r.sweepLocked(now)
		}
		r.entries[key] = &rlEntry{count: 1, start: now}
		return
	}
	e.count++
}

// reset clears the failure history for key (called on successful login).
func (r *rateLimiter) reset(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, key)
}

func (r *rateLimiter) sweepLocked(now time.Time) {
	for k, e := range r.entries {
		if now.Sub(e.start) >= r.window {
			delete(r.entries, k)
		}
	}
}
