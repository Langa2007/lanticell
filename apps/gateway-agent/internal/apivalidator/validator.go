package apivalidator

import (
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/lanticell/gateway-agent/internal/validator"
)

type EvalResult struct {
	Allowed        bool
	Action         string // allow | observe | rate_limit | block
	ReasonCode     string
	Documented     bool
	MatchedPolicy  string
	EffectiveRPS   int
}

// Evaluate validates an API/webhook request against route policies and active OpenAPI schema specs.
func Evaluate(site validator.SiteRouteConfig, method, rawPath, rawQuery, clientIP string, headers map[string]string) EvalResult {
	upperMethod := strings.ToUpper(method)
	normPath := strings.TrimSuffix(rawPath, "/")
	if normPath == "" {
		normPath = "/"
	}

	documented := isDocumented(site.APISchemaEndpoints, upperMethod, normPath)
	if len(site.APISchemaEndpoints) > 0 && documented {
		// Check required query params if specified in schema
		qVals, _ := url.ParseQuery(rawQuery)
		for _, ep := range site.APISchemaEndpoints {
			if ep.Method == upperMethod && pathMatches(ep.Path, normPath) {
				for _, reqParam := range ep.RequiredParams {
					if qVals.Get(reqParam) == "" {
						return EvalResult{
							Allowed:    false,
							Action:     "block",
							ReasonCode: "missing_required_query_param:" + reqParam,
							Documented: true,
						}
					}
				}
			}
		}
	}

	// Sort policies by priority ascending (lower number = higher priority)
	policies := make([]validator.RoutePolicy, len(site.RoutePolicies))
	copy(policies, site.RoutePolicies)
	sort.SliceStable(policies, func(i, j int) bool {
		return policies[i].Priority < policies[j].Priority
	})

	for _, pol := range policies {
		if !pathMatches(pol.PathPattern, normPath) || !methodMatches(pol.Methods, upperMethod) {
			continue
		}

		// Service-to-service / webhook CIDR allowlist enforcement
		if len(pol.ServiceAllowlistCIDRs) > 0 && !ipInCIDRs(clientIP, pol.ServiceAllowlistCIDRs) {
			return EvalResult{
				Allowed:       false,
				Action:        "block",
				ReasonCode:    "service_cidr_not_allowlisted",
				Documented:    documented,
				MatchedPolicy: pol.ID,
			}
		}

		// Webhook signature header presence check
		if pol.WebhookSigHeader != "" && headers[pol.WebhookSigHeader] == "" {
			return EvalResult{
				Allowed:       false,
				Action:        "block",
				ReasonCode:    "missing_webhook_signature_header",
				Documented:    documented,
				MatchedPolicy: pol.ID,
			}
		}

		if pol.ActionOverride == "block" {
			return EvalResult{
				Allowed:       false,
				Action:        "block",
				ReasonCode:    "route_policy_block",
				Documented:    documented,
				MatchedPolicy: pol.ID,
				EffectiveRPS:  pol.RateLimitRPS,
			}
		}

		return EvalResult{
			Allowed:       true,
			Action:        "allow",
			ReasonCode:    "route_policy_matched",
			Documented:    documented,
			MatchedPolicy: pol.ID,
			EffectiveRPS:  pol.RateLimitRPS,
		}
	}

	reason := "default_allow"
	if len(site.APISchemaEndpoints) > 0 && !documented {
		reason = "undocumented_shadow_endpoint"
	}
	return EvalResult{
		Allowed:      true,
		Action:       "allow",
		ReasonCode:   reason,
		Documented:   documented,
		EffectiveRPS: site.RateLimitRPS,
	}
}

func isDocumented(endpoints []validator.EndpointSpec, method, path string) bool {
	for _, ep := range endpoints {
		if ep.Method == method && pathMatches(ep.Path, path) {
			return true
		}
	}
	return false
}

func pathMatches(pattern, actual string) bool {
	if pattern == actual {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(actual, strings.TrimSuffix(pattern, "*"))
	}
	// Support OpenAPI {param} templates
	pSegs := strings.Split(strings.Trim(pattern, "/"), "/")
	aSegs := strings.Split(strings.Trim(actual, "/"), "/")
	if len(pSegs) != len(aSegs) {
		return false
	}
	for i := range pSegs {
		if strings.HasPrefix(pSegs[i], "{") && strings.HasSuffix(pSegs[i], "}") {
			continue
		}
		if pSegs[i] != aSegs[i] {
			return false
		}
	}
	return true
}

func methodMatches(methods []string, method string) bool {
	for _, m := range methods {
		if strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}

func ipInCIDRs(ipStr string, cidrs []string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, c := range cidrs {
		if _, netw, err := net.ParseCIDR(c); err == nil && netw.Contains(ip) {
			return true
		}
	}
	return false
}
