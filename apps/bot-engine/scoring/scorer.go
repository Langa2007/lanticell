package scoring

import (
	"context"
	"strings"

	detectorsdk "github.com/lanticell/detector-sdk"
)

type SiteBotPolicy struct {
	Mode            string   `json:"mode"` // off | observe | enforce
	AllowlistedBots []string `json:"allowlisted_bots,omitempty"`
}

type Decision struct {
	Action      string               `json:"action"` // allow | observe | rate_limit | challenge | block
	RiskScore   float64              `json:"risk_score"`
	ReasonCodes []string             `json:"reason_codes"`
	Signals     []detectorsdk.Signal `json:"signals"`
}

// Aggregator runs detectors, deduplicates correlated signals, and maps risk scores to explainable actions.
type Aggregator struct {
	Detectors []detectorsdk.Detector
	Weights   map[string]float64
}

func NewAggregator(detectors ...detectorsdk.Detector) *Aggregator {
	return &Aggregator{
		Detectors: detectors,
		Weights: map[string]float64{
			"rate_burst":           0.30,
			"navigation_sequence":  0.25,
			"client_consistency":   0.25,
			"account_abuse":        0.40,
			"scraping_enumeration": 0.30,
			"reputation_feed":      0.20,
		},
	}
}

func (a *Aggregator) Evaluate(ctx context.Context, req detectorsdk.RequestFeatures, policy SiteBotPolicy) Decision {
	if policy.Mode == "off" {
		return Decision{Action: "allow", RiskScore: 0, ReasonCodes: []string{"bot_engine_off"}}
	}

	// Safe-list verified crawlers / uptime monitors configured by the tenant
	uaLower := strings.ToLower(req.UserAgent)
	for _, bot := range policy.AllowlistedBots {
		if bot != "" && strings.Contains(uaLower, strings.ToLower(bot)) {
			return Decision{Action: "allow", RiskScore: 0, ReasonCodes: []string{"allowlisted_automation"}}
		}
	}

	// Fintech/mobile-money webhooks must never be JS-challenged or blocked by browser heuristics
	if req.RouteType == "webhook" {
		return Decision{Action: "allow", RiskScore: 0, ReasonCodes: []string{"webhook_route_exempt"}}
	}

	signals := make([]detectorsdk.Signal, 0, len(a.Detectors))
	reasons := make([]string, 0)
	var weightedSum float64

	for _, d := range a.Detectors {
		sig := d.Evaluate(ctx, req)
		signals = append(signals, sig)
		if sig.Score > 0 {
			w := a.Weights[sig.Detector]
			if w == 0 {
				w = 0.20
			}
			weightedSum += sig.Score * sig.Confidence * w * 2.0
			reasons = append(reasons, sig.ReasonCode)
		}
	}

	// Route sensitivity adjustment
	if req.RouteType == "login" || req.RouteType == "checkout" || req.RouteType == "auth_otp" {
		weightedSum *= 1.20
	}

	// Clearance cookie discount (one signal, not absolute proof)
	if req.HasClearance {
		weightedSum *= 0.50
	}

	if weightedSum > 1.0 {
		weightedSum = 1.0
	}
	if len(reasons) == 0 {
		reasons = []string{"clean"}
	}

	action := mapScoreToAction(weightedSum, req.IsBrowserRoute, policy.Mode)
	return Decision{
		Action:      action,
		RiskScore:   weightedSum,
		ReasonCodes: reasons,
		Signals:     signals,
	}
}

func mapScoreToAction(score float64, isBrowser bool, mode string) string {
	if score < 0.25 {
		return "allow"
	}
	if mode != "enforce" {
		return "observe"
	}
	switch {
	case score >= 0.80:
		return "block"
	case score >= 0.55:
		if isBrowser {
			return "challenge"
		}
		return "rate_limit"
	case score >= 0.35:
		return "rate_limit"
	default:
		return "observe"
	}
}
