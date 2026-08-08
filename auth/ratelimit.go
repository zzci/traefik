package main

import (
	"sync"
	"time"
)

// rateLimiter is a fixed-window failure counter keyed by string
// (e.g. "ip:1.2.3.4", "user:admin"). Only failures count against the
// limit; a successful login resets its key. Limits are passed per call so
// config hot-reloads take effect immediately.
type rateLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]*rlEntry
}

type rlEntry struct {
	count int
	start time.Time
}

const rlSweepThreshold = 4096

func newRateLimiter() *rateLimiter {
	return &rateLimiter{
		now:     time.Now,
		entries: map[string]*rlEntry{},
	}
}

// allow reports whether key is currently under the failure limit.
func (r *rateLimiter) allow(key string, attempts int, window time.Duration) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[key]
	if !ok {
		return true
	}
	if r.now().Sub(e.start) >= window {
		delete(r.entries, key)
		return true
	}
	return e.count < attempts
}

// fail records a failed attempt for key.
func (r *rateLimiter) fail(key string, window time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	e, ok := r.entries[key]
	if !ok || now.Sub(e.start) >= window {
		if len(r.entries) >= rlSweepThreshold {
			r.sweepLocked(now, window)
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

func (r *rateLimiter) sweepLocked(now time.Time, window time.Duration) {
	for k, e := range r.entries {
		if now.Sub(e.start) >= window {
			delete(r.entries, k)
		}
	}
}
