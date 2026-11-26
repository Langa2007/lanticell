package validator

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var domainRegex = regexp.MustCompile(`^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}$`)

type WAFExclusionRule struct {
	RoutePrefix string     `json:"route_prefix"`
	RuleID      string     `json:"rule_id"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

type RoutePolicy struct {
	ID                    string   `json:"id"`
	PathPattern           string   `json:"path_pattern"`
	Methods               []string `json:"methods"`
	RouteType             string   `json:"route_type"`
	RateLimitRPS          int      `json:"rate_limit_rps"`
	ActionOverride        string   `json:"action_override"`
	ServiceAllowlistCIDRs []string `json:"service_allowlist_cidrs,omitempty"`
	WebhookSigHeader      string   `json:"webhook_sig_header,omitempty"`
	Priority              int      `json:"priority"`
}

type EndpointSpec struct {
	Path           string   `json:"path"`
	Method         string   `json:"method"`
	RequiredParams []string `json:"required_params,omitempty"`
}

type SiteRouteConfig struct {
	SiteID              string             `json:"site_id"`
	TenantID            string             `json:"tenant_id"`
	Domain              string             `json:"domain"`
	TLSMode             string             `json:"tls_mode"`
	UpstreamURL         string             `json:"upstream_url"`
	OriginSecret        string             `json:"origin_secret"`
	ConnectTimeoutMs    int                `json:"connect_timeout_ms"`
	ReadTimeoutMs       int                `json:"read_timeout_ms"`
	MaxBodyBytes        int64              `json:"max_body_bytes"`
	RateLimitRPS        int                `json:"rate_limit_rps"`
	WAFMode             string             `json:"waf_mode"`
	CRSVersion          string             `json:"crs_version"`
	MaxInspectBodyBytes int64              `json:"max_inspect_body_bytes"`
	WAFExclusions       []WAFExclusionRule `json:"waf_exclusions,omitempty"`
	BotMode             string             `json:"bot_mode"`
	AllowlistedBots     []string           `json:"allowlisted_bots,omitempty"`
	RoutePolicies       []RoutePolicy      `json:"route_policies,omitempty"`
	APISchemaEndpoints  []EndpointSpec     `json:"api_schema_endpoints,omitempty"`
}

type ConfigBundle struct {
	SchemaVersion string            `json:"schema_version"`
	Version       int64             `json:"version"`
	GeneratedAt   time.Time         `json:"generated_at"`
	Sites         []SiteRouteConfig `json:"sites"`
	Signature     string            `json:"signature"`
}

// VerifyAndValidate checks HMAC signature (if signingKey non-empty) and validates every site route.
func VerifyAndValidate(bundle ConfigBundle, signingKey []byte) error {
	if bundle.SchemaVersion != "1.0" {
		return errors.New("unsupported bundle schema_version")
	}
	if len(signingKey) > 0 {
		unsignedBytes, err := json.Marshal(struct {
			SchemaVersion string            `json:"schema_version"`
			Version       int64             `json:"version"`
			GeneratedAt   time.Time         `json:"generated_at"`
			Sites         []SiteRouteConfig `json:"sites"`
		}{
			SchemaVersion: bundle.SchemaVersion,
			Version:       bundle.Version,
			GeneratedAt:   bundle.GeneratedAt,
			Sites:         bundle.Sites,
		})
		if err != nil {
			return err
		}
		mac := hmac.New(sha256.New, signingKey)
		mac.Write(unsignedBytes)
		expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		if subtle.ConstantTimeCompare([]byte(bundle.Signature), []byte(expected)) != 1 {
			return errors.New("invalid bundle signature")
		}
	}

	for _, site := range bundle.Sites {
		if !domainRegex.MatchString(strings.ToLower(site.Domain)) {
			return errors.New("invalid site domain in bundle: " + site.Domain)
		}
		u, err := url.ParseRequestURI(site.UpstreamURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return errors.New("invalid upstream_url in bundle for: " + site.Domain)
		}
		if strings.ContainsAny(site.OriginSecret, ";{}\n\r\"") {
			return errors.New("unsafe characters in origin_secret")
		}
		if site.WAFMode != "" && site.WAFMode != "off" && site.WAFMode != "monitor" && site.WAFMode != "block" {
			return errors.New("invalid waf_mode for: " + site.Domain)
		}
		for _, ex := range site.WAFExclusions {
			if !strings.HasPrefix(ex.RoutePrefix, "/") || strings.ContainsAny(ex.RoutePrefix, ";{}\n\r ") {
				return errors.New("unsafe waf_exclusion route_prefix for: " + site.Domain)
			}
		}
	}
	return nil
}
