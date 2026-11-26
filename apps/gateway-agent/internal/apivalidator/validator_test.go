package apivalidator_test

import (
	"testing"

	"github.com/lanticell/gateway-agent/internal/apivalidator"
	"github.com/lanticell/gateway-agent/internal/validator"
)

func TestOpenAPIValidationAndShadowDiscovery(t *testing.T) {
	site := validator.SiteRouteConfig{
		SiteID:       "s1",
		RateLimitRPS: 50,
		APISchemaEndpoints: []validator.EndpointSpec{
			{Path: "/api/v1/orders/{id}", Method: "GET", RequiredParams: []string{"currency"}},
		},
	}

	// Missing required query param -> blocked
	resMissing := apivalidator.Evaluate(site, "GET", "/api/v1/orders/42", "", "102.1.2.3", nil)
	if resMissing.Allowed || resMissing.Action != "block" {
		t.Fatalf("expected missing required query param to block, got %+v", resMissing)
	}

	// Valid documented endpoint
	resOK := apivalidator.Evaluate(site, "GET", "/api/v1/orders/42", "currency=KES", "102.1.2.3", nil)
	if !resOK.Allowed || !resOK.Documented {
		t.Fatalf("expected documented endpoint to pass, got %+v", resOK)
	}

	// Undocumented shadow endpoint flagged
	resShadow := apivalidator.Evaluate(site, "POST", "/api/v1/internal/debug", "", "102.1.2.3", nil)
	if resShadow.Documented || resShadow.ReasonCode != "undocumented_shadow_endpoint" {
		t.Fatalf("expected undocumented_shadow_endpoint, got %+v", resShadow)
	}
}

func TestWebhookCIDRAndSignatureProtection(t *testing.T) {
	site := validator.SiteRouteConfig{
		SiteID: "s1",
		RoutePolicies: []validator.RoutePolicy{
			{
				ID:                    "rp1",
				PathPattern:           "/api/webhooks/mpesa",
				Methods:               []string{"POST"},
				RouteType:             "webhook",
				RateLimitRPS:          200,
				ServiceAllowlistCIDRs: []string{"196.201.214.0/24"},
				WebhookSigHeader:      "X-Mpesa-Signature",
				Priority:              10,
			},
		},
	}

	// Spoofed IP rejected
	badIP := apivalidator.Evaluate(site, "POST", "/api/webhooks/mpesa", "", "198.51.100.5", map[string]string{"X-Mpesa-Signature": "abc"})
	if badIP.Allowed || badIP.ReasonCode != "service_cidr_not_allowlisted" {
		t.Fatalf("expected CIDR block, got %+v", badIP)
	}

	// Missing signature header rejected
	noSig := apivalidator.Evaluate(site, "POST", "/api/webhooks/mpesa", "", "196.201.214.10", map[string]string{})
	if noSig.Allowed || noSig.ReasonCode != "missing_webhook_signature_header" {
		t.Fatalf("expected missing signature block, got %+v", noSig)
	}

	// Valid partner IP + signature allowed
	valid := apivalidator.Evaluate(site, "POST", "/api/webhooks/mpesa", "", "196.201.214.10", map[string]string{"X-Mpesa-Signature": "sig123"})
	if !valid.Allowed || valid.EffectiveRPS != 200 {
		t.Fatalf("expected valid webhook to pass with 200 RPS, got %+v", valid)
	}
}
