package sequence

import (
	"context"
	"strings"
	"time"

	"github.com/lanticell/bot-engine/state"
	detectorsdk "github.com/lanticell/detector-sdk"
)

// Detector flags unusual or impossible route transitions within a session.
type Detector struct {
	Store *state.MemoryStore
}

func New(st *state.MemoryStore) *Detector {
	return &Detector{Store: st}
}

func (d *Detector) Name() string { return "navigation_sequence" }

func (d *Detector) Evaluate(_ context.Context, req detectorsdk.RequestFeatures) detectorsdk.Signal {
	if req.RouteType == "api" || req.RouteType == "webhook" {
		return detectorsdk.Signal{Detector: d.Name(), Score: 0, Confidence: 0.9, ReasonCode: "api_route_skip"}
	}

	key := req.SiteID + ":" + req.ClientPrefix
	if req.SessionKey != "" {
		key = req.SiteID + ":" + req.SessionKey
	}
	hist := d.Store.RecordRoute(key, req.Route, 12)

	// Impossible direct jump to sensitive confirmation endpoints without prior browsing/session history
	if (strings.Contains(req.Route, "/checkout/confirm") || strings.Contains(req.Route, "/transfer/confirm")) && len(hist) <= 1 {
		return detectorsdk.Signal{
			Detector:   d.Name(),
			Score:      0.70,
			Confidence: 0.80,
			ReasonCode: "missing_prior_flow",
			Evidence:   map[string]string{"route": req.Route},
			TTL:        5 * time.Minute,
		}
	}

	// Repeated identical POST endpoint hammering
	if req.Method == "POST" && len(hist) >= 6 {
		same := 0
		for _, r := range hist[len(hist)-6:] {
			if r == req.Route {
				same++
			}
		}
		if same == 6 {
			return detectorsdk.Signal{
				Detector:   d.Name(),
				Score:      0.55,
				Confidence: 0.75,
				ReasonCode: "repetitive_post_sequence",
				Evidence:   map[string]string{"route": req.Route},
				TTL:        2 * time.Minute,
			}
		}
	}

	return detectorsdk.Signal{Detector: d.Name(), Score: 0, Confidence: 0.8, ReasonCode: "normal_sequence"}
}
