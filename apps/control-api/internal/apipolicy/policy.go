package apipolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
)

type RoutePolicy struct {
	ID                    string   `json:"id"`
	TenantID              string   `json:"tenant_id"`
	SiteID                string   `json:"site_id"`
	PathPattern           string   `json:"path_pattern"`
	Methods               []string `json:"methods"`
	RouteType             string   `json:"route_type"`
	RateLimitRPS          int      `json:"rate_limit_rps"`
	ActionOverride        string   `json:"action_override"`
	ServiceAllowlistCIDRs []string `json:"service_allowlist_cidrs,omitempty"`
	WebhookSigHeader      string   `json:"webhook_sig_header,omitempty"`
	Priority              int      `json:"priority"`
}

type PolicyConflict struct {
	ExistingPolicyID string `json:"existing_policy_id"`
	Reason           string `json:"reason"`
}

type EndpointSpec struct {
	Path           string   `json:"path"`
	Method         string   `json:"method"`
	RequiredParams []string `json:"required_params,omitempty"`
}

// ValidateRoutePolicy validates syntax, CIDRs, and limits for a route policy.
func ValidateRoutePolicy(p RoutePolicy) error {
	if !strings.HasPrefix(p.PathPattern, "/") || strings.ContainsAny(p.PathPattern, ";{}\n\r ") {
		return errors.New("path_pattern must start with / and contain no whitespace or control characters")
	}
	if len(p.Methods) == 0 {
		return errors.New("at least one HTTP method is required")
	}
	for _, m := range p.Methods {
		switch strings.ToUpper(m) {
		case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		default:
			return fmt.Errorf("unsupported HTTP method: %s", m)
		}
	}
	if p.RateLimitRPS < 1 || p.RateLimitRPS > 100000 {
		return errors.New("rate_limit_rps must be between 1 and 100000")
	}
	for _, cidr := range p.ServiceAllowlistCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid CIDR in service_allowlist_cidrs: %s", cidr)
		}
	}
	if strings.ContainsAny(p.WebhookSigHeader, ";{}\n\r ") {
		return errors.New("invalid webhook_sig_header")
	}
	return nil
}

// DetectConflicts checks whether candidate conflicts with any existing route policy.
func DetectConflicts(existing []RoutePolicy, candidate RoutePolicy) []PolicyConflict {
	var conflicts []PolicyConflict
	for _, cur := range existing {
		if cur.ID == candidate.ID {
			continue
		}
		if !pathsOverlap(cur.PathPattern, candidate.PathPattern) {
			continue
		}
		if !methodsOverlap(cur.Methods, candidate.Methods) {
			continue
		}
		if cur.Priority == candidate.Priority {
			conflicts = append(conflicts, PolicyConflict{
				ExistingPolicyID: cur.ID,
				Reason: fmt.Sprintf(
					"overlapping path %q and methods %v share identical priority %d with existing policy (%s)",
					candidate.PathPattern, candidate.Methods, candidate.Priority, cur.PathPattern,
				),
			})
			continue
		}
		if cur.Priority < candidate.Priority && cur.ActionOverride == "block" && candidate.ActionOverride == "allow" {
			conflicts = append(conflicts, PolicyConflict{
				ExistingPolicyID: cur.ID,
				Reason: fmt.Sprintf(
					"higher-priority block policy on %q (priority %d) shadows allow policy on %q (priority %d)",
					cur.PathPattern, cur.Priority, candidate.PathPattern, candidate.Priority,
				),
			})
		}
	}
	return conflicts
}

func pathsOverlap(a, b string) bool {
	if a == b {
		return true
	}
	return strings.HasPrefix(a, strings.TrimSuffix(b, "*")) || strings.HasPrefix(b, strings.TrimSuffix(a, "*"))
}

func methodsOverlap(a, b []string) bool {
	set := make(map[string]struct{}, len(a))
	for _, m := range a {
		set[strings.ToUpper(m)] = struct{}{}
	}
	for _, m := range b {
		if _, ok := set[strings.ToUpper(m)]; ok {
			return true
		}
	}
	return false
}

// ParseOpenAPI extracts normalized EndpointSpecs from an OpenAPI 3.x JSON document.
func ParseOpenAPI(raw []byte) ([]EndpointSpec, error) {
	var doc struct {
		OpenAPI string `json:"openapi"`
		Paths   map[string]map[string]struct {
			Parameters []struct {
				Name     string `json:"name"`
				In       string `json:"in"`
				Required bool   `json:"required"`
			} `json:"parameters"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, errors.New("invalid OpenAPI JSON")
	}
	if !strings.HasPrefix(doc.OpenAPI, "3.") || len(doc.Paths) == 0 {
		return nil, errors.New("expected OpenAPI 3.x document with at least one path")
	}

	var specs []EndpointSpec
	for p, methods := range doc.Paths {
		if !strings.HasPrefix(p, "/") {
			return nil, fmt.Errorf("invalid OpenAPI path: %s", p)
		}
		for m, op := range methods {
			upper := strings.ToUpper(m)
			switch upper {
			case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
			default:
				continue
			}
			var reqParams []string
			for _, param := range op.Parameters {
				if param.In == "query" && param.Required && param.Name != "" {
					reqParams = append(reqParams, param.Name)
				}
			}
			specs = append(specs, EndpointSpec{
				Path:           p,
				Method:         upper,
				RequiredParams: reqParams,
			})
		}
	}
	if len(specs) == 0 {
		return nil, errors.New("no valid HTTP operations found in OpenAPI paths")
	}
	return specs, nil
}
