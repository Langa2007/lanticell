package rate

import (
	"context"
	"fmt"
	"time"

	"github.com/lanticell/bot-engine/state"
	detectorsdk "github.com/lanticell/detector-sdk"
)

// Detector measures per-route request velocity using sliding windows.
// CGNAT-safe: IP/prefix velocity alone caps at 0.65 so shared mobile IPs are rate-limited rather than hard-blocked.
type Detector struct {
	Store     *state.MemoryStore
	Window    time.Duration
	Threshold int
}

func New(st *state.MemoryStore, window time.Duration, threshold int) *Detector {
	if window <= 0 {
		window = 10 * time.Second
	}
	if threshold <= 0 {
		threshold = 30
	}
	return &Detector{Store: st, Window: window, Threshold: threshold}
}

func (d *Detector) Name() string { return "rate_burst" }

func (d *Detector) Evaluate(_ context.Context, req detectorsdk.RequestFeatures) detectorsdk.Signal {
	identity := req.ClientPrefix
	if req.SessionKey != "" {
		identity = req.SessionKey
	}
	key := fmt.Sprintf("rate:%s:%s:%s", req.SiteID, req.Route, identity)
	count := d.Store.IncrementAndCount(key, d.Window, req.Timestamp)

	if count <= d.Threshold {
		return detectorsdk.Signal{Detector: d.Name(), Score: 0, Confidence: 0.9, ReasonCode: "within_rate_limit", TTL: d.Window}
	}

	ratio := float64(count) / float64(d.Threshold)
	score := 0.35 + (ratio-1.0)*0.15
	// CGNAT guard: if no session key, cap velocity score so shared mobile IPv4s aren't hard-blocked solely on IP.
	if req.SessionKey == "" && score > 0.65 {
		score = 0.65
	} else if score > 0.90 {
		score = 0.90
	}

	return detectorsdk.Signal{
		Detector:   d.Name(),
		Score:      score,
		Confidence: 0.85,
		ReasonCode: "route_burst_exceeded",
		Evidence: map[string]string{
			"count":     fmt.Sprintf("%d", count),
			"threshold": fmt.Sprintf("%d", d.Threshold),
		},
		TTL: d.Window,
	}
}
