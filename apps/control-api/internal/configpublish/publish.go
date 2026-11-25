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

var domainRegex = regexp.MustCompile(`^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}$`)

// SiteRouteConfig is the validated data-plane routing entry for one verified site.
type SiteRouteConfig struct {
	SiteID           string `json:"site_id"`
	TenantID         string `json:"tenant_id"`
	Domain           string `json:"domain"`
	TLSMode          string `json:"tls_mode"`
	UpstreamURL      string `json:"upstream_url"`
	OriginSecret     string `json:"origin_secret"`
	ConnectTimeoutMs int    `json:"connect_timeout_ms"`
	ReadTimeoutMs    int    `json:"read_timeout_ms"`
	MaxBodyBytes     int64  `json:"max_body_bytes"`
	RateLimitRPS     int    `json:"rate_limit_rps"`
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

// BuildSignedBundle builds and signs the active gateway configuration bundle.
func BuildSignedBundle(st *store.Store, encKey, signingKey []byte) (ConfigBundle, error) {
	version, sites, origins := st.ActiveSitesWithOrigins()
	routes := make([]SiteRouteConfig, 0, len(sites))

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
		routes = append(routes, SiteRouteConfig{
			SiteID:           site.ID,
			TenantID:         site.TenantID,
			Domain:           site.Domain,
			TLSMode:          site.TLSMode,
			UpstreamURL:      origin.UpstreamURL,
			OriginSecret:     secret,
			ConnectTimeoutMs: origin.ConnectTimeoutMs,
			ReadTimeoutMs:    origin.ReadTimeoutMs,
			MaxBodyBytes:     origin.MaxBodyBytes,
			RateLimitRPS:     origin.RateLimitRPS,
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
