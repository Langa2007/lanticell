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
