package configpublish

import (
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/lanticell/control-api/internal/crypto"
	"github.com/lanticell/control-api/internal/store"
)

var (
	domainRegex = regexp.MustCompile(`^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}$`)
	ruleIDRegex = regexp.MustCompile(`^[0-9]{3,7}$`)
)

// WAFExclusionRule represents a scoped rule exclusion in the data-plane bundle.
type WAFExclusionRule struct {
	RoutePrefix string     `json:"route_prefix"`
	RuleID      string     `json:"rule_id"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// SiteRouteConfig is the validated data-plane routing entry for one verified site.
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
}

// ConfigBundle is the signed, versioned payload fetched by gateway-agent.
type ConfigBundle struct {
	SchemaVersion string            `json:"schema_version"`
	Version       int64             `json:"version"`
	GeneratedAt   time.Time         `json:"generated_at"`
	Sites         []SiteRouteConfig `json:"sites"`
	Signature     string            `json:"signature"`
}

// ValidateDomain ensures a domain is a valid hostname without injection characters.
func ValidateDomain(domain string) error {
	d := strings.TrimSpace(strings.ToLower(domain))
	if len(d) == 0 || len(d) > 253 {
		return errors.New("invalid domain length")
	}
	if !domainRegex.MatchString(d) {
		return errors.New("invalid domain format")
	}
	return nil
}

// ValidateOrigin ensures upstream URL and limits are safe and well-formed.
func ValidateOrigin(upstreamURL string, connectMs, readMs int, maxBody int64, rps int) error {
	u, err := url.ParseRequestURI(upstreamURL)
	if err != nil {
		return errors.New("invalid upstream_url")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("upstream_url scheme must be http or https")
	}
	if u.Host == "" || strings.ContainsAny(u.Host, ";{}\n\r ") {
		return errors.New("invalid upstream_url host")
	}
	if connectMs < 100 || connectMs > 30000 {
		return errors.New("connect_timeout_ms must be between 100 and 30000")
	}
	if readMs < 500 || readMs > 120000 {
		return errors.New("read_timeout_ms must be between 500 and 120000")
	}
	if maxBody < 1024 || maxBody > 104857600 {
		return errors.New("max_body_bytes must be between 1KB and 100MB")
	}
	if rps < 1 || rps > 100000 {
		return errors.New("rate_limit_rps must be between 1 and 100000")
	}
	return nil
}

// ValidateWAFPolicy validates WAF mode and inspection limits.
func ValidateWAFPolicy(mode, crsVersion string, maxInspect int64) error {
	if mode != "off" && mode != "monitor" && mode != "block" {
		return errors.New("waf mode must be off, monitor, or block")
	}
	if strings.TrimSpace(crsVersion) == "" || strings.ContainsAny(crsVersion, ";{}\n\r ") {
		return errors.New("invalid crs_version")
	}
	if maxInspect < 1024 || maxInspect > 10485760 {
		return errors.New("max_inspect_body_bytes must be between 1KB and 10MB")
	}
	return nil
}

// ValidateWAFExclusion validates a scoped WAF rule exclusion.
func ValidateWAFExclusion(routePrefix, ruleID, reason string) error {
	if !strings.HasPrefix(routePrefix, "/") || strings.ContainsAny(routePrefix, ";{}\n\r ") {
		return errors.New("route_prefix must start with / and contain no whitespace or control chars")
	}
	if !ruleIDRegex.MatchString(ruleID) {
		return errors.New("rule_id must be a numeric CRS rule ID")
	}
	if strings.TrimSpace(reason) == "" {
		return errors.New("reason is required for auditability")
	}
	return nil
}

// BuildSignedBundle builds and signs the active gateway configuration bundle.
func BuildSignedBundle(st *store.Store, encKey, signingKey []byte) (ConfigBundle, error) {
	version, sites, origins := st.ActiveSitesWithOrigins()
	routes := make([]SiteRouteConfig, 0, len(sites))
	now := time.Now().UTC()

	for _, site := range sites {
		if err := ValidateDomain(site.Domain); err != nil {
			return ConfigBundle{}, err
		}
		origin := origins[site.ID]
		if err := ValidateOrigin(origin.UpstreamURL, origin.ConnectTimeoutMs, origin.ReadTimeoutMs, origin.MaxBodyBytes, origin.RateLimitRPS); err != nil {
			return ConfigBundle{}, err
		}
		secret, err := crypto.DecryptAESGCM(encKey, origin.OriginSecretEnc)
		if err != nil {
			return ConfigBundle{}, err
		}
		wafPol := st.GetWAFPolicy(site.TenantID, site.ID)
		rawExclusions, _ := st.ListWAFExclusions(site.TenantID, site.ID)
		activeExclusions := make([]WAFExclusionRule, 0, len(rawExclusions))
		for _, ex := range rawExclusions {
			if ex.ExpiresAt != nil && ex.ExpiresAt.Before(now) {
				continue
			}
			activeExclusions = append(activeExclusions, WAFExclusionRule{
				RoutePrefix: ex.RoutePrefix,
				RuleID:      ex.RuleID,
				ExpiresAt:   ex.ExpiresAt,
			})
		}

		routes = append(routes, SiteRouteConfig{
			SiteID:              site.ID,
			TenantID:            site.TenantID,
			Domain:              site.Domain,
			TLSMode:             site.TLSMode,
			UpstreamURL:         origin.UpstreamURL,
			OriginSecret:        secret,
			ConnectTimeoutMs:    origin.ConnectTimeoutMs,
			ReadTimeoutMs:       origin.ReadTimeoutMs,
			MaxBodyBytes:        origin.MaxBodyBytes,
			RateLimitRPS:        origin.RateLimitRPS,
			WAFMode:             wafPol.Mode,
			CRSVersion:          wafPol.CRSVersion,
			MaxInspectBodyBytes: wafPol.MaxInspectBodyBytes,
			WAFExclusions:       activeExclusions,
		})
	}

	bundle := ConfigBundle{
		SchemaVersion: "1.0",
		Version:       version,
		GeneratedAt:   time.Now().UTC(),
		Sites:         routes,
	}
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
		return ConfigBundle{}, err
	}
	bundle.Signature = crypto.SignHMAC(signingKey, unsignedBytes)
	return bundle, nil
}
