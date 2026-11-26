package clientconsistency

import (
	"context"
	"strings"
	"time"

	detectorsdk "github.com/lanticell/detector-sdk"
)

// Detector evaluates protocol and header consistency while tolerating African proxy-compressed mobile browsers.
type Detector struct{}

func New() *Detector { return &Detector{} }

func (d *Detector) Name() string { return "client_consistency" }

func (d *Detector) Evaluate(_ context.Context, req detectorsdk.RequestFeatures) detectorsdk.Signal {
	if req.RouteType == "api" || req.RouteType == "webhook" || !req.IsBrowserRoute {
		return detectorsdk.Signal{Detector: d.Name(), Score: 0, Confidence: 0.9, ReasonCode: "non_browser_route"}
	}

	ua := strings.ToLower(req.UserAgent)
	if ua == "" {
		return detectorsdk.Signal{
			Detector:   d.Name(),
			Score:      0.50,
			Confidence: 0.80,
			ReasonCode: "missing_user_agent",
			TTL:        5 * time.Minute,
		}
	}

	// Explicitly tolerate Opera Mini, UC Browser, and mobile carrier proxies
	if strings.Contains(ua, "opera mini") || strings.Contains(ua, "ucbrowser") || req.Headers["X-OperaMini-Features"] != "" {
		return detectorsdk.Signal{Detector: d.Name(), Score: 0, Confidence: 0.95, ReasonCode: "proxy_compressed_browser_allowed"}
	}

	// Scripted HTTP clients hitting browser routes
	scripted := []string{"python-requests", "aiohttp", "scrapy", "go-http-client", "curl/", "wget/", "headlesschrome"}
	for _, marker := range scripted {
		if strings.Contains(ua, marker) {
			return detectorsdk.Signal{
				Detector:   d.Name(),
				Score:      0.75,
				Confidence: 0.90,
				ReasonCode: "scripted_client_on_browser_route",
				Evidence:   map[string]string{"marker": marker},
				TTL:        10 * time.Minute,
			}
		}
	}

	// Browser UA claim missing basic Accept header
	if strings.Contains(ua, "mozilla/5.0") && req.Headers["Accept"] == "" && req.Headers["Accept-Language"] == "" {
		return detectorsdk.Signal{
			Detector:   d.Name(),
			Score:      0.45,
			Confidence: 0.70,
			ReasonCode: "inconsistent_browser_headers",
			TTL:        5 * time.Minute,
		}
	}

	return detectorsdk.Signal{Detector: d.Name(), Score: 0, Confidence: 0.85, ReasonCode: "consistent_client"}
}
