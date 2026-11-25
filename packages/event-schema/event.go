package eventschema

import "time"

const CurrentSchemaVersion = "1.0"

// SecurityEvent represents a bounded, sanitized WAF or bot security decision.
// It intentionally excludes passwords, auth headers, cookies, and raw request bodies.
type SecurityEvent struct {
	SchemaVersion string    `json:"schema_version"`
	EventID       string    `json:"event_id"`
	CorrelationID string    `json:"correlation_id"`
	TenantID      string    `json:"tenant_id"`
	SiteID        string    `json:"site_id"`
	Route         string    `json:"route"`
	RuleID        string    `json:"rule_id"`
	CRSVersion    string    `json:"crs_version"`
	Action        string    `json:"action"` // allow | observe | block
	Confidence    float64   `json:"confidence"`
	ReasonCode    string    `json:"reason_code"`
	CreatedAt     time.Time `json:"created_at"`
}
