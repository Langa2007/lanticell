package state

import (
	"sync"
	"time"
)

// MemoryStore provides bounded in-memory sliding-window counters and route sequence history.
// Multi-node deployments can swap this interface for a Redis/Valkey-backed implementation.
type MemoryStore struct {
	mu        sync.Mutex
	windows   map[string][]time.Time
	sequences map[string][]string
	maxKeys   int
}

func NewMemoryStore(maxKeys int) *MemoryStore {
	if maxKeys <= 0 {
		maxKeys = 10000
	}
	return &MemoryStore{
		windows:   make(map[string][]time.Time),
		sequences: make(map[string][]string),
		maxKeys:   maxKeys,
	}
}

// IncrementAndCount records an event at now and returns the count within the sliding window.
func (s *MemoryStore) IncrementAndCount(key string, window time.Duration, now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.windows) >= s.maxKeys {
		s.evictOldestWindowLocked(now.Add(-window))
	}

	cutoff := now.Add(-window)
	events := s.windows[key]
	kept := events[:0]
	for _, ts := range events {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	kept = append(kept, now)
	s.windows[key] = kept
	return len(kept)
}

// RecordRoute appends a route to a bounded per-session ring history and returns the recent routes.
func (s *MemoryStore) RecordRoute(key, route string, maxLen int) []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if maxLen <= 0 {
		maxLen = 10
	}
	hist := append(s.sequences[key], route)
	if len(hist) > maxLen {
		hist = hist[len(hist)-maxLen:]
	}
	s.sequences[key] = hist
	out := make([]string, len(hist))
	copy(out, hist)
	return out
}

func (s *MemoryStore) evictOldestWindowLocked(cutoff time.Time) {
	for k, events := range s.windows {
		if len(events) == 0 || events[len(events)-1].Before(cutoff) {
			delete(s.windows, k)
		}
		if len(s.windows) < s.maxKeys {
			return
		}
	}
	// Fallback: trim one arbitrary entry to guarantee bounded memory
	for k := range s.windows {
		delete(s.windows, k)
		return
	}
}
