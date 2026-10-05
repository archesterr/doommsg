// Package ratelimit implements a keyed token-bucket limiter with idle
// eviction, used to throttle per-IP and per-user traffic.
package ratelimit

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type entry struct {
	lim  *rate.Limiter
	seen time.Time
}

type Limiter struct {
	mu      sync.Mutex
	r       rate.Limit
	burst   int
	entries map[string]*entry
	idle    time.Duration
}

// New returns a limiter allowing r events/second with the given burst per key.
func New(r rate.Limit, burst int) *Limiter {
	return &Limiter{r: r, burst: burst, entries: make(map[string]*entry), idle: 10 * time.Minute}
}

func (l *Limiter) Allow(key string) bool {
	now := time.Now()
	return l.get(key, now).AllowN(now, 1)
}

// Wait blocks until key may proceed, for callers that should be slowed
// down rather than refused. It fails only when ctx ends first.
func (l *Limiter) Wait(ctx context.Context, key string) error {
	return l.get(key, time.Now()).Wait(ctx)
}

func (l *Limiter) get(key string, now time.Time) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok {
		e = &entry{lim: rate.NewLimiter(l.r, l.burst)}
		l.entries[key] = e
	}
	e.seen = now
	return e.lim
}

// Sweep drops keys idle for longer than the idle window. Call periodically.
func (l *Limiter) Sweep() {
	cutoff := time.Now().Add(-l.idle)
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, e := range l.entries {
		if e.seen.Before(cutoff) {
			delete(l.entries, k)
		}
	}
}
