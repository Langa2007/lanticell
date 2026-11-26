package httpserver_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lanticell/control-api/internal/httpserver"
	"github.com/lanticell/control-api/internal/store"
)

func newTestServer() *httpserver.Server {
	st := store.NewStore()
	jwtSecret := []byte("test-jwt-secret-key-32-bytes-long!")
	encKey := []byte("0123456789abcdef0123456789abcdef")
	return httpserver.NewServer(st, jwtSecret, encKey, "test-agent-token")
}

func doJSON(t *testing.T, h http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestEndToEndOnboardingAndTenantIsolation(t *testing.T) {
	srv := newTestServer()
	h := srv.Handler()

	// 1. Register Tenant A
	regA := doJSON(t, h, http.MethodPost, "/api/v1/auth/register", "", map[string]string{
		"tenant_name": "Nairobi Pay",
		"email":       "owner@nairobipay.co.ke",
		"password":    "StrongPass123!",
	})
	if regA.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", regA.Code, regA.Body.String())
	}
	var regAResp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(regA.Body.Bytes(), &regAResp)

	// 2. Create Site
	siteRes := doJSON(t, h, http.MethodPost, "/api/v1/sites", regAResp.Token, map[string]string{
		"domain":   "api.nairobipay.co.ke",
		"tls_mode": "acme",
	})
	if siteRes.Code != http.StatusCreated {
		t.Fatalf("expected 201 creating site, got %d: %s", siteRes.Code, siteRes.Body.String())
	}
	var site store.Site
	_ = json.Unmarshal(siteRes.Body.Bytes(), &site)

	// 3. Mock DNS TXT verification
	srv.LookupTXT = func(_ context.Context, name string) ([]string, error) {
		if name == "_lanticell-verify.api.nairobipay.co.ke" {
			return []string{site.TXTVerificationToken}, nil
		}
		return nil, nil
	}
	verRes := doJSON(t, h, http.MethodPost, "/api/v1/sites/"+site.ID+"/verify-dns", regAResp.Token, nil)
	if verRes.Code != http.StatusOK {
		t.Fatalf("expected 200 verifying dns, got %d: %s", verRes.Code, verRes.Body.String())
	}

	// 4. Add Origin with secret; verify secret is NOT leaked in API response
	origRes := doJSON(t, h, http.MethodPut, "/api/v1/sites/"+site.ID+"/origin", regAResp.Token, map[string]any{
		"upstream_url":  "https://origin.nairobipay.co.ke:8443",
		"origin_secret": "super-secret-origin-header-value",
	})
	if origRes.Code != http.StatusOK {
		t.Fatalf("expected 200 upserting origin, got %d: %s", origRes.Code, origRes.Body.String())
	}
	if strings.Contains(origRes.Body.String(), "super-secret-origin-header-value") {
		t.Fatalf("origin secret leaked in API response!")
	}

	// 5. Gateway agent fetches signed config bundle
	bundleRes := doJSON(t, h, http.MethodGet, "/api/v1/agent/config", "test-agent-token", nil)
	if bundleRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for agent config, got %d: %s", bundleRes.Code, bundleRes.Body.String())
	}
	if !strings.Contains(bundleRes.Body.String(), "api.nairobipay.co.ke") {
		t.Fatalf("expected verified site in agent config bundle")
	}

	// 6. Tenant B cannot access Tenant A's site
	regB := doJSON(t, h, http.MethodPost, "/api/v1/auth/register", "", map[string]string{
		"tenant_name": "Lagos Shop",
		"email":       "admin@lagosshop.ng",
		"password":    "StrongPass123!",
	})
	var regBResp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(regB.Body.Bytes(), &regBResp)

	forbiddenRes := doJSON(t, h, http.MethodPut, "/api/v1/sites/"+site.ID+"/origin", regBResp.Token, map[string]any{
		"upstream_url": "https://evil.example.com",
	})
	if forbiddenRes.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-tenant access, got %d", forbiddenRes.Code)
	}
}

func TestInvalidDomainAndOriginRejected(t *testing.T) {
	srv := newTestServer()
	h := srv.Handler()

	reg := doJSON(t, h, http.MethodPost, "/api/v1/auth/register", "", map[string]string{
		"tenant_name": "Test Co",
		"email":       "dev@test.co.za",
		"password":    "StrongPass123!",
	})
	var regResp struct{ Token string `json:"token"` }
	_ = json.Unmarshal(reg.Body.Bytes(), &regResp)

	badSite := doJSON(t, h, http.MethodPost, "/api/v1/sites", regResp.Token, map[string]string{
		"domain": "evil.com; return 200;",
	})
	if badSite.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for domain injection attempt, got %d", badSite.Code)
	}
}

func TestWAFPolicyExclusionsAndSecurityEvents(t *testing.T) {
	srv := newTestServer()
	h := srv.Handler()

	reg := doJSON(t, h, http.MethodPost, "/api/v1/auth/register", "", map[string]string{
		"tenant_name": "Kigali Fintech",
		"email":       "sec@kigalifintech.rw",
		"password":    "StrongPass123!",
	})
	var regResp struct{ Token string `json:"token"` }
	_ = json.Unmarshal(reg.Body.Bytes(), &regResp)

	siteRes := doJSON(t, h, http.MethodPost, "/api/v1/sites", regResp.Token, map[string]string{
		"domain": "pay.kigalifintech.rw",
	})
	var site store.Site
	_ = json.Unmarshal(siteRes.Body.Bytes(), &site)

	// Enable block mode
	wafRes := doJSON(t, h, http.MethodPut, "/api/v1/sites/"+site.ID+"/waf", regResp.Token, map[string]any{
		"mode":                   "block",
		"crs_version":            "4.10.0",
		"max_inspect_body_bytes": 65536,
	})
	if wafRes.Code != http.StatusOK {
		t.Fatalf("expected 200 updating WAF policy, got %d: %s", wafRes.Code, wafRes.Body.String())
	}

	// Add scoped exclusion
	exRes := doJSON(t, h, http.MethodPost, "/api/v1/sites/"+site.ID+"/waf/exclusions", regResp.Token, map[string]any{
		"route_prefix": "/api/webhooks/momo",
		"rule_id":      "942100",
		"reason":       "MoMo callback payload contains SQL-like key names",
	})
	if exRes.Code != http.StatusCreated {
		t.Fatalf("expected 201 creating exclusion, got %d: %s", exRes.Code, exRes.Body.String())
	}

	// Agent records a security event
	evRes := doJSON(t, h, http.MethodPost, "/api/v1/agent/events", "test-agent-token", map[string]any{
		"tenant_id":      site.TenantID,
		"site_id":        site.ID,
		"correlation_id": "req-abc-123",
		"route":          "/login",
		"rule_id":        "942100",
		"crs_version":    "4.10.0",
		"action":         "block",
		"confidence":     0.95,
		"reason_code":    "sqli_detected",
	})
	if evRes.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for agent event, got %d", evRes.Code)
	}

	listEv := doJSON(t, h, http.MethodGet, "/api/v1/security-events", regResp.Token, nil)
	if listEv.Code != http.StatusOK || !strings.Contains(listEv.Body.String(), "req-abc-123") {
		t.Fatalf("expected security event in tenant list, got %d: %s", listEv.Code, listEv.Body.String())
	}

	// Update bot policy
	botRes := doJSON(t, h, http.MethodPut, "/api/v1/sites/"+site.ID+"/bot-policy", regResp.Token, map[string]any{
		"mode":                 "enforce",
		"challenge_difficulty": 3,
		"allowlisted_bots":     []string{"UptimeRobot"},
	})
	if botRes.Code != http.StatusOK || !strings.Contains(botRes.Body.String(), "enforce") {
		t.Fatalf("expected 200 updating bot policy, got %d: %s", botRes.Code, botRes.Body.String())
	}

	// Phase 4: Route policy + conflict detection
	rp1 := doJSON(t, h, http.MethodPost, "/api/v1/sites/"+site.ID+"/route-policies", regResp.Token, map[string]any{
		"path_pattern": "/api/v1/transfer",
		"methods":      []string{"POST"},
		"route_type":   "checkout",
		"rate_limit_rps": 10,
		"priority":     100,
	})
	if rp1.Code != http.StatusCreated {
		t.Fatalf("expected 201 creating route policy, got %d: %s", rp1.Code, rp1.Body.String())
	}

	rpConflict := doJSON(t, h, http.MethodPost, "/api/v1/sites/"+site.ID+"/route-policies", regResp.Token, map[string]any{
		"path_pattern":   "/api/v1/transfer",
		"methods":        []string{"POST"},
		"rate_limit_rps": 50,
		"priority":       100,
	})
	if rpConflict.Code != http.StatusConflict {
		t.Fatalf("expected 409 on conflicting route policy, got %d: %s", rpConflict.Code, rpConflict.Body.String())
	}

	// OpenAPI schema import v1, v2, and rollback to v1
	schemaV1 := doJSON(t, h, http.MethodPost, "/api/v1/sites/"+site.ID+"/api-schemas", regResp.Token, map[string]any{
		"openapi": map[string]any{
			"openapi": "3.0.3",
			"paths": map[string]any{
				"/api/v1/transfer": map[string]any{"post": map[string]any{}},
			},
		},
	})
	if schemaV1.Code != http.StatusCreated {
		t.Fatalf("expected 201 importing schema v1, got %d: %s", schemaV1.Code, schemaV1.Body.String())
	}
	_ = doJSON(t, h, http.MethodPost, "/api/v1/sites/"+site.ID+"/api-schemas", regResp.Token, map[string]any{
		"openapi": map[string]any{
			"openapi": "3.0.3",
			"paths": map[string]any{
				"/api/v1/payments": map[string]any{"post": map[string]any{}},
			},
		},
	})
	rb := doJSON(t, h, http.MethodPost, "/api/v1/sites/"+site.ID+"/api-schemas/1/rollback", regResp.Token, nil)
	if rb.Code != http.StatusOK || !strings.Contains(rb.Body.String(), `"version":1`) {
		t.Fatalf("expected 200 rolling back schema to v1, got %d: %s", rb.Code, rb.Body.String())
	}
}

func TestBillingUsageStatusAndMetrics(t *testing.T) {
	srv := newTestServer()
	h := srv.Handler()

	reg := doJSON(t, h, http.MethodPost, "/api/v1/auth/register", "", map[string]string{
		"tenant_name": "Accra Commerce",
		"email":       "ops@accracommerce.gh",
		"password":    "StrongPass123!",
	})
	var regResp struct {
		Token  string `json:"token"`
		Tenant struct {
			ID string `json:"id"`
		} `json:"tenant"`
	}
	_ = json.Unmarshal(reg.Body.Bytes(), &regResp)

	// Upgrade plan & record agent usage
	planRes := doJSON(t, h, http.MethodPut, "/api/v1/billing/plan", regResp.Token, map[string]string{"plan_tier": "growth"})
	if planRes.Code != http.StatusOK || !strings.Contains(planRes.Body.String(), "growth") {
		t.Fatalf("expected 200 updating plan, got %d: %s", planRes.Code, planRes.Body.String())
	}
	usagePost := doJSON(t, h, http.MethodPost, "/api/v1/agent/usage", "test-agent-token", map[string]any{
		"tenant_id":          regResp.Tenant.ID,
		"inspected_requests": 1200,
		"blocked_requests":   45,
		"bytes_inspected":    980000,
	})
	if usagePost.Code != http.StatusAccepted {
		t.Fatalf("expected 202 recording usage, got %d", usagePost.Code)
	}
	usageGet := doJSON(t, h, http.MethodGet, "/api/v1/billing/usage", regResp.Token, nil)
	if usageGet.Code != http.StatusOK || !strings.Contains(usageGet.Body.String(), "1200") {
		t.Fatalf("expected usage count 1200, got %d: %s", usageGet.Code, usageGet.Body.String())
	}

	// Incident & public status page
	incRes := doJSON(t, h, http.MethodPost, "/api/v1/operator/incidents", regResp.Token, map[string]string{
		"title":    "Nairobi PoP maintenance",
		"severity": "minor",
		"status":   "monitoring",
		"summary":  "Traffic shifted to secondary zone.",
	})
	if incRes.Code != http.StatusCreated {
		t.Fatalf("expected 201 creating incident, got %d", incRes.Code)
	}
	statusRes := doJSON(t, h, http.MethodGet, "/status", "", nil)
	if statusRes.Code != http.StatusOK || !strings.Contains(statusRes.Body.String(), "degraded") {
		t.Fatalf("expected degraded public status, got %d: %s", statusRes.Code, statusRes.Body.String())
	}

	// Prometheus metrics
	metricsRes := doJSON(t, h, http.MethodGet, "/metrics", "", nil)
	if metricsRes.Code != http.StatusOK || !strings.Contains(metricsRes.Body.String(), "lanticell_http_requests_total") {
		t.Fatalf("expected Prometheus metrics output, got %d", metricsRes.Code)
	}
}
