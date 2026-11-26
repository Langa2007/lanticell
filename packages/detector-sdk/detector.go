package detectorsdk

import (
	"context"
	"time"
)

// RequestFeatures holds normalized, privacy-safe request attributes for bot evaluation.
// Passwords, OTPs, authorization headers, cookies, and raw bodies are intentionally excluded.
type RequestFeatures struct {
	TenantID        string            `json:"tenant_id"`
	SiteID          string            `json:"site_id"`
	CorrelationID   string            `json:"correlation_id"`
	Method          string            `json:"method"`
	Route           string            `json:"route"`
	RouteType       string            `json:"route_type"` // public | login | checkout | search | api | webhook
	QueryKeys       []string          `json:"query_keys,omitempty"`
	ClientPrefix    string            `json:"client_prefix"` // /24 IPv4 or /64 IPv6 pseudonymized prefix
	SessionKey      string            `json:"session_key,omitempty"`
	UserAgent       string            `json:"user_agent"`
	Headers         map[string]string `json:"headers,omitempty"`
	StatusHint      int               `json:"status_hint,omitempty"` // optional auth/outcome hint from app webhook
	IsBrowserRoute  bool              `json:"is_browser_route"`
	HasClearance    bool              `json:"has_clearance"`
	Timestamp       time.Time         `json:"timestamp"`
}

// Signal is the explainable output produced by a single Detector.
type Signal struct {
	Detector   string            `json:"detector"`
	Score      float64           `json:"score"`      // normalized [0.0, 1.0]
	Confidence float64           `json:"confidence"` // normalized [0.0, 1.0]
	ReasonCode string            `json:"reason_code"`
	Evidence   map[string]string `json:"evidence,omitempty"`
	TTL        time.Duration     `json:"ttl"`
}

// Detector evaluates normalized RequestFeatures and emits a Signal.
type Detector interface {
	Name() string
	Evaluate(ctx context.Context, req RequestFeatures) Signal
}
