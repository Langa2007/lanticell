package scraping

import (
	"context"
	"fmt"
	"time"

	"github.com/lanticell/bot-engine/state"
	detectorsdk "github.com/lanticell/detector-sdk"
)

// Detector identifies high-volume pagination and systematic resource enumeration.
type Detector struct {
	Store     *state.MemoryStore
	Window    time.Duration
	Threshold int
}

func New(st *state.MemoryStore, window time.Duration, threshold int) *Detector {
	if window <= 0 {
		window = 1 * time.Minute
	}
	if threshold <= 0 {
		threshold = 40
	}
	return &Detector{Store: st, Window: window, Threshold: threshold}
}

func (d *Detector) Name() string { return "scraping_enumeration" }

func (d *Detector) Evaluate(_ context.Context, req detectorsdk.RequestFeatures) detectorsdk.Signal {
	if req.Method != "GET" {
		return detectorsdk.Signal{Detector: d.Name(), Score: 0, Confidence: 0.9, ReasonCode: "non_get_method"}
	}

	hasPagination := false
	for _, k := range req.QueryKeys {
		if k == "page" || k == "offset" || k == "cursor" || k == "id" {
			hasPagination = true
			break
		}
	}
	if !hasPagination && req.RouteType != "search" {
		return detectorsdk.Signal{Detector: d.Name(), Score: 0, Confidence: 0.8, ReasonCode: "no_pagination_signal"}
	}

	identity := req.ClientPrefix
	if req.SessionKey != "" {
		identity = req.SessionKey
	}
	count := d.Store.IncrementAndCount(fmt.Sprintf("scrape:%s:%s", req.SiteID, identity), d.Window, req.Timestamp)
	if count > d.Threshold {
		return detectorsdk.Signal{
			Detector:   d.Name(),
			Score:      0.75,
			Confidence: 0.82,
			ReasonCode: "high_volume_pagination_scraping",
			Evidence:   map[string]string{"pages_in_window": fmt.Sprintf("%d", count)},
			TTL:        5 * time.Minute,
		}
	}

	return detectorsdk.Signal{Detector: d.Name(), Score: 0, Confidence: 0.8, ReasonCode: "normal_browsing"}
}
