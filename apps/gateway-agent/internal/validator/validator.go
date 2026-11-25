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
	}
	return nil
}
