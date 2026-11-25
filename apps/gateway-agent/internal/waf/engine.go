package waf

import (
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/lanticell/gateway-agent/internal/validator"
)

type RequestInput struct {
	Method  string
	Path    string
	Query   string
	Headers map[string]string
	Body    string
}

type Decision struct {
	Action          string
	RuleID          string
	ReasonCode      string
	Confidence      float64
	CRSVersion      string
	NormalizedRoute string
	BodyTruncated   bool
}

type ruleDef struct {
	ID         string
	ReasonCode string
	Confidence float64
	Pattern    *regexp.Regexp
}

var coreRules = []ruleDef{
	{
		ID:         "920100",
		ReasonCode: "protocol_crlf_anomaly",
		Confidence: 0.98,
		Pattern:    regexp.MustCompile(`(?i)(\r|\n|%0d|%0a|\x00)`),
	},
	{
		ID:         "930100",
		ReasonCode: "path_traversal_lfi",
		Confidence: 0.96,
		Pattern:    regexp.MustCompile(`(?i)(\.\./|\.\.\\|/etc/passwd|/etc/shadow|boot\.ini)`),
	},
	{
		ID:         "942100",
		ReasonCode: "sqli_pattern",
		Confidence: 0.95,
		Pattern:    regexp.MustCompile(`(?i)(union\s+(all\s+)?select|'\s+or\s+1\s*=\s*1|\bor\s+1\s*=\s*1\b|;\s*drop\s+table|--\s*$|'\s*--)`) ,
	},
	{
		ID:         "941100",
		ReasonCode: "xss_pattern",
		Confidence: 0.95,
		Pattern:    regexp.MustCompile(`(?i)(<\s*script\b|javascript:|on(error|load|click|mouseover)\s*=)`),
	},
	{
		ID:         "932100",
		ReasonCode: "command_injection",
		Confidence: 0.94,
		Pattern:    regexp.MustCompile(`(?i)(;\s*(cat|ls|id|whoami|curl|wget|sh|bash)\b|\|\s*(sh|bash|nc)\b|\$\([^)]+\))`),
	},
}

// NormalizeIterative URL-decodes up to maxPasses times to prevent double-encoding evasion.
func NormalizeIterative(raw string, maxPasses int) string {
	cur := raw
	for i := 0; i < maxPasses; i++ {
		dec, err := url.QueryUnescape(cur)
		if err != nil || dec == cur {
			break
		}
		cur = dec
	}
	return cur
}

// NormalizePath canonicalizes slashes and dot segments consistently with NGINX.
func NormalizePath(rawPath string) string {
	decoded := NormalizeIterative(rawPath, 3)
	if decoded == "" {
		return "/"
	}
	cleaned := path.Clean("/" + decoded)
	return cleaned
}

// Evaluate inspects a request against pinned CRS-aligned rules within bounded limits.
func Evaluate(site validator.SiteRouteConfig, req RequestInput, now time.Time) Decision {
	normRoute := NormalizePath(req.Path)
	crsVer := site.CRSVersion
	if crsVer == "" {
		crsVer = "4.10.0"
	}
	if site.WAFMode == "off" {
		return Decision{Action: "allow", CRSVersion: crsVer, NormalizedRoute: normRoute}
	}

	maxBody := site.MaxInspectBodyBytes
	if maxBody <= 0 {
		maxBody = 131072
	}
	body := req.Body
	truncated := false
	if int64(len(body)) > maxBody {
		body = body[:maxBody]
		truncated = true
	}

	normQuery := NormalizeIterative(req.Query, 3)
	normBody := NormalizeIterative(body, 2)

	var headerBuf strings.Builder
	for k, v := range req.Headers {
		headerBuf.WriteString(k)
		headerBuf.WriteString(": ")
		headerBuf.WriteString(v)
		headerBuf.WriteByte(' ')
	}

	// Inspect raw + normalized surfaces (CRLF checked before stripping)
	surfaces := []string{
		req.Path,
		req.Query,
		NormalizeIterative(req.Path, 3),
		normRoute,
		normQuery,
		normBody,
		headerBuf.String(),
	}

	for _, rule := range coreRules {
		if isExcluded(site.WAFExclusions, normRoute, rule.ID, now) {
			continue
		}
		for _, surface := range surfaces {
			if rule.Pattern.MatchString(surface) {
				action := "observe"
				if site.WAFMode == "block" {
					action = "block"
				}
				return Decision{
					Action:          action,
					RuleID:          rule.ID,
					ReasonCode:      rule.ReasonCode,
					Confidence:      rule.Confidence,
					CRSVersion:      crsVer,
					NormalizedRoute: normRoute,
					BodyTruncated:   truncated,
				}
			}
		}
	}

	return Decision{
		Action:          "allow",
		CRSVersion:      crsVer,
		NormalizedRoute: normRoute,
		BodyTruncated:   truncated,
	}
}

func isExcluded(exclusions []validator.WAFExclusionRule, route, ruleID string, now time.Time) bool {
	for _, ex := range exclusions {
		if ex.RuleID != ruleID {
			continue
		}
		if ex.ExpiresAt != nil && ex.ExpiresAt.Before(now) {
			continue
		}
		if strings.HasPrefix(route, ex.RoutePrefix) {
			return true
		}
	}
	return false
}
