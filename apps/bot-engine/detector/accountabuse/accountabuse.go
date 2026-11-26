package accountabuse

import (
	"context"
	"fmt"
	"time"

	"github.com/lanticell/bot-engine/state"
	detectorsdk "github.com/lanticell/detector-sdk"
)

// Detector detects credential stuffing, login failure bursts, and OTP/password-reset abuse
// without collecting passwords, OTPs, or secrets.
type Detector struct {
	Store            *state.MemoryStore
	Window           time.Duration
	FailureThreshold int
}

func New(st *state.MemoryStore, window time.Duration, failureThreshold int) *Detector {
	if window <= 0 {
		window = 1 * time.Minute
	}
	if failureThreshold <= 0 {
		failureThreshold = 8
	}
	return &Detector{Store: st, Window: window, FailureThreshold: failureThreshold}
}

func (d *Detector) Name() string { return "account_abuse" }

func (d *Detector) Evaluate(_ context.Context, req detectorsdk.RequestFeatures) detectorsdk.Signal {
	if req.RouteType != "login" && req.RouteType != "auth_otp" {
		return detectorsdk.Signal{Detector: d.Name(), Score: 0, Confidence: 0.9, ReasonCode: "non_auth_route"}
	}

	// Track authentication velocity and explicit failure hints (401/403)
	key := fmt.Sprintf("auth:%s:%s:%s", req.SiteID, req.Route, req.ClientPrefix)
	if req.StatusHint == 401 || req.StatusHint == 403 {
		failures := d.Store.IncrementAndCount(key+":fail", d.Window, req.Timestamp)
		if failures >= d.FailureThreshold {
			return detectorsdk.Signal{
				Detector:   d.Name(),
				Score:      0.85,
				Confidence: 0.92,
				ReasonCode: "credential_stuffing_burst",
				Evidence:   map[string]string{"failures": fmt.Sprintf("%d", failures)},
				TTL:        10 * time.Minute,
			}
		}
	}

	attempts := d.Store.IncrementAndCount(key+":attempt", d.Window, req.Timestamp)
	if attempts > d.FailureThreshold*2 {
		return detectorsdk.Signal{
			Detector:   d.Name(),
			Score:      0.70,
			Confidence: 0.85,
			ReasonCode: "auth_attempt_velocity",
			Evidence:   map[string]string{"attempts": fmt.Sprintf("%d", attempts)},
			TTL:        5 * time.Minute,
		}
	}

	return detectorsdk.Signal{Detector: d.Name(), Score: 0, Confidence: 0.8, ReasonCode: "normal_auth_rate"}
}
