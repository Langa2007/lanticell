package reputation

import (
	"context"
	"sync"
	"time"

	detectorsdk "github.com/lanticell/detector-sdk"
)

type FeedEntry struct {
	Source     string
	Confidence float64
	ExpiresAt  time.Time
}

// Detector checks configurable threat-intel feeds (e.g. CrowdSec decisions).
// Weighted input only: capped at 0.50 so reputation alone never acts as a universal blocklist.
type Detector struct {
	mu      sync.RWMutex
	entries map[string]FeedEntry
}

func New() *Detector {
	return &Detector{entries: make(map[string]FeedEntry)}
}

func (d *Detector) Upsert(prefix string, entry FeedEntry) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.entries[prefix] = entry
}

func (d *Detector) Name() string { return "reputation_feed" }

func (d *Detector) Evaluate(_ context.Context, req detectorsdk.RequestFeatures) detectorsdk.Signal {
	d.mu.RLock()
	entry, ok := d.entries[req.ClientPrefix]
	d.mu.RUnlock()

	if !ok || req.Timestamp.After(entry.ExpiresAt) {
		return detectorsdk.Signal{Detector: d.Name(), Score: 0, Confidence: 0.9, ReasonCode: "no_active_reputation_hit"}
	}

	score := 0.50 * entry.Confidence
	if score > 0.50 {
		score = 0.50
	}
	return detectorsdk.Signal{
		Detector:   d.Name(),
		Score:      score,
		Confidence: entry.Confidence,
		ReasonCode: "threat_feed_match",
		Evidence:   map[string]string{"source": entry.Source},
		TTL:        time.Until(entry.ExpiresAt),
	}
}
