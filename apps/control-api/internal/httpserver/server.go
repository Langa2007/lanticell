package httpserver

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/lanticell/control-api/internal/configpublish"
	"github.com/lanticell/control-api/internal/crypto"
	"github.com/lanticell/control-api/internal/store"
)

type contextKey string

const claimsContextKey contextKey = "claims"

// Server serves the Lanticell control-plane API.
type Server struct {
	Store         *store.Store
	JWTSecret     []byte
	EncKey        []byte
	AgentToken    string
	LookupTXT     func(ctx context.Context, name string) ([]string, error)
	HTTPClient    *http.Client
}

func NewServer(st *store.Store, jwtSecret, encKey []byte, agentToken string) *Server {
	return &Server{
		Store:      st,
		JWTSecret:  jwtSecret,
		EncKey:     encKey,
		AgentToken: agentToken,
		LookupTXT: func(ctx context.Context, name string) ([]string, error) {
			return net.DefaultResolver.LookupTXT(ctx, name)
		},
		HTTPClient: &http.Client{Timeout: 5 * time.Second},
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("POST /api/v1/auth/register", s.handleRegister)
	mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)

	mux.Handle("GET /api/v1/sites", s.requireAuth(http.HandlerFunc(s.handleListSites)))
	mux.Handle("POST /api/v1/sites", s.requireAuth(s.requireWriteRole(http.HandlerFunc(s.handleCreateSite))))
	mux.Handle("POST /api/v1/sites/{id}/verify-dns", s.requireAuth(s.requireWriteRole(http.HandlerFunc(s.handleVerifyDNS))))
	mux.Handle("PUT /api/v1/sites/{id}/origin", s.requireAuth(s.requireWriteRole(http.HandlerFunc(s.handleUpsertOrigin))))
	mux.Handle("POST /api/v1/sites/{id}/verify-lockdown", s.requireAuth(http.HandlerFunc(s.handleVerifyLockdown)))
	mux.Handle("GET /api/v1/sites/{id}/waf", s.requireAuth(http.HandlerFunc(s.handleGetWAFPolicy)))
	mux.Handle("PUT /api/v1/sites/{id}/waf", s.requireAuth(s.requireWriteRole(http.HandlerFunc(s.handleUpsertWAFPolicy))))
	mux.Handle("GET /api/v1/sites/{id}/bot-policy", s.requireAuth(http.HandlerFunc(s.handleGetBotPolicy)))
	mux.Handle("PUT /api/v1/sites/{id}/bot-policy", s.requireAuth(s.requireWriteRole(http.HandlerFunc(s.handleUpsertBotPolicy))))
	mux.Handle("GET /api/v1/sites/{id}/waf/exclusions", s.requireAuth(http.HandlerFunc(s.handleListWAFExclusions)))
	mux.Handle("POST /api/v1/sites/{id}/waf/exclusions", s.requireAuth(s.requireWriteRole(http.HandlerFunc(s.handleAddWAFExclusion))))
	mux.Handle("DELETE /api/v1/sites/{id}/waf/exclusions/{exclusionId}", s.requireAuth(s.requireWriteRole(http.HandlerFunc(s.handleDeleteWAFExclusion))))
	mux.Handle("GET /api/v1/security-events", s.requireAuth(http.HandlerFunc(s.handleListSecurityEvents)))
	mux.Handle("GET /api/v1/audit-logs", s.requireAuth(http.HandlerFunc(s.handleListAuditLogs)))

	mux.Handle("GET /api/v1/agent/config", s.requireAgentAuth(http.HandlerFunc(s.handleAgentConfig)))
	mux.Handle("POST /api/v1/agent/health", s.requireAgentAuth(http.HandlerFunc(s.handleAgentHealth)))
	mux.Handle("POST /api/v1/agent/events", s.requireAgentAuth(http.HandlerFunc(s.handleAgentEvents)))

	return withCORS(mux)
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TenantName string `json:"tenant_name"`
		Email      string `json:"email"`
		Password   string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	req.TenantName = strings.TrimSpace(req.TenantName)
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.TenantName == "" || !strings.Contains(req.Email, "@") {
		writeError(w, http.StatusBadRequest, "valid tenant_name and email are required")
		return
	}
	pwHash, err := crypto.HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	tenantID, _ := crypto.RandomHex(16)
	userID, _ := crypto.RandomHex(16)
	slug := strings.ToLower(strings.ReplaceAll(req.TenantName, " ", "-")) + "-" + tenantID[:6]

	tenant := store.Tenant{ID: tenantID, Name: req.TenantName, Slug: slug, CreatedAt: time.Now().UTC()}
	user := store.User{ID: userID, Email: req.Email, PasswordHash: pwHash, CreatedAt: time.Now().UTC()}
	if err := s.Store.CreateTenantAndOwner(tenant, user); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			writeError(w, http.StatusConflict, "account already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to create account")
		return
	}

	token, err := crypto.SignToken(s.JWTSecret, crypto.TokenClaims{
		UserID:   user.ID,
		TenantID: tenant.ID,
		Email:    user.Email,
		Role:     "owner",
		Exp:      time.Now().Add(24 * time.Hour).Unix(),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to issue token")
		return
	}
	s.recordAudit(tenant.ID, user.ID, "tenant.register", "tenant", tenant.ID, nil)
	writeJSON(w, http.StatusCreated, map[string]any{
		"token":  token,
		"tenant": tenant,
		"user":   user,
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	email := strings.TrimSpace(strings.ToLower(req.Email))
	user, membership, err := s.Store.GetUserByEmail(email)
	if err != nil || !crypto.VerifyPassword(req.Password, user.PasswordHash) {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	token, err := crypto.SignToken(s.JWTSecret, crypto.TokenClaims{
		UserID:   user.ID,
		TenantID: membership.TenantID,
		Email:    user.Email,
		Role:     membership.Role,
		Exp:      time.Now().Add(24 * time.Hour).Unix(),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to issue token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token": token,
		"user":  user,
		"role":  membership.Role,
	})
}

func (s *Server) handleListSites(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	sites := s.Store.ListSites(claims.TenantID)
	writeJSON(w, http.StatusOK, map[string]any{"sites": sites})
}

func (s *Server) handleCreateSite(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	var req struct {
		Domain  string `json:"domain"`
		TLSMode string `json:"tls_mode"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	domain := strings.TrimSpace(strings.ToLower(req.Domain))
	if err := configpublish.ValidateDomain(domain); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	tlsMode := req.TLSMode
	if tlsMode == "" {
		tlsMode = "acme"
	}
	if tlsMode != "acme" && tlsMode != "custom" && tlsMode != "dev_self_signed" {
		writeError(w, http.StatusBadRequest, "invalid tls_mode")
		return
	}
	siteID, _ := crypto.RandomHex(16)
	txtToken, _ := crypto.RandomHex(16)
	site := store.Site{
		ID:                   siteID,
		TenantID:             claims.TenantID,
		Domain:               domain,
		TXTVerificationToken: "lanticell-verify=" + txtToken,
		TLSMode:              tlsMode,
		Status:               "pending_verification",
		CreatedAt:            time.Now().UTC(),
	}
	if err := s.Store.CreateSite(site); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			writeError(w, http.StatusConflict, "domain already registered")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to create site")
		return
	}
	s.recordAudit(claims.TenantID, claims.UserID, "site.create", "site", site.ID, map[string]string{"domain": site.Domain})
	writeJSON(w, http.StatusCreated, site)
}

func (s *Server) handleVerifyDNS(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	siteID := r.PathValue("id")
	site, err := s.Store.GetSite(claims.TenantID, siteID)
	if err != nil {
		writeStoreError(w, err)
		return
	}

	records, err := s.LookupTXT(r.Context(), "_lanticell-verify."+site.Domain)
	if err != nil {
		writeError(w, http.StatusBadGateway, "DNS TXT lookup failed: "+err.Error())
		return
	}
	matched := false
	for _, rec := range records {
		if strings.TrimSpace(rec) == site.TXTVerificationToken {
			matched = true
			break
		}
	}
	if !matched {
		writeError(w, http.StatusUnprocessableEntity, "matching TXT record not found for _lanticell-verify."+site.Domain)
		return
	}

	updated, err := s.Store.MarkSiteVerified(claims.TenantID, siteID, time.Now().UTC())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.recordAudit(claims.TenantID, claims.UserID, "site.verify_dns", "site", siteID, map[string]string{"domain": site.Domain})
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleUpsertOrigin(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	siteID := r.PathValue("id")
	if _, err := s.Store.GetSite(claims.TenantID, siteID); err != nil {
		writeStoreError(w, err)
		return
	}

	var req struct {
		UpstreamURL      string `json:"upstream_url"`
		OriginSecret     string `json:"origin_secret"`
		ConnectTimeoutMs int    `json:"connect_timeout_ms"`
		ReadTimeoutMs    int    `json:"read_timeout_ms"`
		MaxBodyBytes     int64  `json:"max_body_bytes"`
		RateLimitRPS     int    `json:"rate_limit_rps"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.ConnectTimeoutMs == 0 {
		req.ConnectTimeoutMs = 3000
	}
	if req.ReadTimeoutMs == 0 {
		req.ReadTimeoutMs = 15000
	}
	if req.MaxBodyBytes == 0 {
		req.MaxBodyBytes = 10 * 1024 * 1024
	}
	if req.RateLimitRPS == 0 {
		req.RateLimitRPS = 50
	}
	if err := configpublish.ValidateOrigin(req.UpstreamURL, req.ConnectTimeoutMs, req.ReadTimeoutMs, req.MaxBodyBytes, req.RateLimitRPS); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.OriginSecret == "" {
		generated, err := crypto.RandomHex(24)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to generate origin secret")
			return
		}
		req.OriginSecret = generated
	}
	encSecret, err := crypto.EncryptAESGCM(s.EncKey, req.OriginSecret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to encrypt origin secret")
		return
	}

	originID, _ := crypto.RandomHex(16)
	origin := store.Origin{
		ID:               originID,
		SiteID:           siteID,
		TenantID:         claims.TenantID,
		UpstreamURL:      req.UpstreamURL,
		OriginSecretEnc:  encSecret,
		ConnectTimeoutMs: req.ConnectTimeoutMs,
		ReadTimeoutMs:    req.ReadTimeoutMs,
		MaxBodyBytes:     req.MaxBodyBytes,
		RateLimitRPS:     req.RateLimitRPS,
		CreatedAt:        time.Now().UTC(),
	}
	if err := s.Store.UpsertOrigin(origin); err != nil {
		writeStoreError(w, err)
		return
	}
	s.recordAudit(claims.TenantID, claims.UserID, "origin.upsert", "origin", originID, map[string]string{"site_id": siteID})
	writeJSON(w, http.StatusOK, origin)
}

func (s *Server) handleVerifyLockdown(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	siteID := r.PathValue("id")
	origin, err := s.Store.GetOrigin(claims.TenantID, siteID)
	if err != nil {
		writeStoreError(w, err)
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodHead, origin.UpstreamURL, nil)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid origin url")
		return
	}
	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		// Unreachable directly from public probe is consistent with firewall lockdown.
		writeJSON(w, http.StatusOK, map[string]any{
			"locked_down": true,
			"detail":      "direct unauthenticated probe failed or timed out (origin unreachable directly)",
		})
		return
	}
	defer resp.Body.Close()

	lockedDown := resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized
	writeJSON(w, http.StatusOK, map[string]any{
		"locked_down": lockedDown,
		"status_code": resp.StatusCode,
		"detail":      "direct unauthenticated probe received HTTP response",
	})
}

func (s *Server) handleListAuditLogs(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	logs := s.Store.ListAuditLogs(claims.TenantID)
	writeJSON(w, http.StatusOK, map[string]any{"audit_logs": logs})
}

func (s *Server) handleAgentConfig(w http.ResponseWriter, _ *http.Request) {
	bundle, err := configpublish.BuildSignedBundle(s.Store, s.EncKey, s.JWTSecret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to build config bundle")
		return
	}
	writeJSON(w, http.StatusOK, bundle)
}

func (s *Server) handleAgentHealth(w http.ResponseWriter, r *http.Request) {
	var node store.GatewayNode
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&node); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if node.ID == "" {
		writeError(w, http.StatusBadRequest, "gateway id is required")
		return
	}
	node.LastSeenAt = time.Now().UTC()
	s.Store.UpsertGatewayHealth(node)
	writeJSON(w, http.StatusOK, map[string]string{"status": "recorded"})
}

func (s *Server) handleGetWAFPolicy(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	siteID := r.PathValue("id")
	if _, err := s.Store.GetSite(claims.TenantID, siteID); err != nil {
		writeStoreError(w, err)
		return
	}
	pol := s.Store.GetWAFPolicy(claims.TenantID, siteID)
	writeJSON(w, http.StatusOK, pol)
}

func (s *Server) handleUpsertWAFPolicy(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	siteID := r.PathValue("id")
	if _, err := s.Store.GetSite(claims.TenantID, siteID); err != nil {
		writeStoreError(w, err)
		return
	}
	var req struct {
		Mode                string `json:"mode"`
		CRSVersion          string `json:"crs_version"`
		MaxInspectBodyBytes int64  `json:"max_inspect_body_bytes"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.CRSVersion == "" {
		req.CRSVersion = "4.10.0"
	}
	if req.MaxInspectBodyBytes == 0 {
		req.MaxInspectBodyBytes = 131072
	}
	if err := configpublish.ValidateWAFPolicy(req.Mode, req.CRSVersion, req.MaxInspectBodyBytes); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	pol := store.WAFPolicy{
		SiteID:              siteID,
		TenantID:            claims.TenantID,
		Mode:                req.Mode,
		CRSVersion:          req.CRSVersion,
		MaxInspectBodyBytes: req.MaxInspectBodyBytes,
		UpdatedAt:           time.Now().UTC(),
	}
	if err := s.Store.UpsertWAFPolicy(pol); err != nil {
		writeStoreError(w, err)
		return
	}
	s.recordAudit(claims.TenantID, claims.UserID, "waf.policy_update", "site", siteID, map[string]string{"mode": pol.Mode, "crs_version": pol.CRSVersion})
	writeJSON(w, http.StatusOK, pol)
}

func (s *Server) handleListWAFExclusions(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	siteID := r.PathValue("id")
	list, err := s.Store.ListWAFExclusions(claims.TenantID, siteID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"exclusions": list})
}

func (s *Server) handleAddWAFExclusion(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	siteID := r.PathValue("id")
	var req struct {
		RoutePrefix string     `json:"route_prefix"`
		RuleID      string     `json:"rule_id"`
		Reason      string     `json:"reason"`
		ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.RoutePrefix == "" {
		req.RoutePrefix = "/"
	}
	if err := configpublish.ValidateWAFExclusion(req.RoutePrefix, req.RuleID, req.Reason); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	exID, _ := crypto.RandomHex(12)
	ex := store.WAFExclusion{
		ID:          exID,
		TenantID:    claims.TenantID,
		SiteID:      siteID,
		RoutePrefix: req.RoutePrefix,
		RuleID:      req.RuleID,
		Reason:      req.Reason,
		ExpiresAt:   req.ExpiresAt,
		CreatedBy:   claims.UserID,
		CreatedAt:   time.Now().UTC(),
	}
	if err := s.Store.AddWAFExclusion(ex); err != nil {
		writeStoreError(w, err)
		return
	}
	s.recordAudit(claims.TenantID, claims.UserID, "waf.exclusion_add", "waf_exclusion", ex.ID, map[string]string{"site_id": siteID, "rule_id": ex.RuleID})
	writeJSON(w, http.StatusCreated, ex)
}

func (s *Server) handleDeleteWAFExclusion(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	siteID := r.PathValue("id")
	exID := r.PathValue("exclusionId")
	if err := s.Store.DeleteWAFExclusion(claims.TenantID, siteID, exID); err != nil {
		writeStoreError(w, err)
		return
	}
	s.recordAudit(claims.TenantID, claims.UserID, "waf.exclusion_delete", "waf_exclusion", exID, map[string]string{"site_id": siteID})
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleListSecurityEvents(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	events := s.Store.ListSecurityEvents(claims.TenantID)
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *Server) handleAgentEvents(w http.ResponseWriter, r *http.Request) {
	var ev store.SecurityEvent
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32*1024)).Decode(&ev); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if ev.TenantID == "" || ev.SiteID == "" || ev.RuleID == "" {
		writeError(w, http.StatusBadRequest, "tenant_id, site_id, and rule_id are required")
		return
	}
	if ev.ID == "" {
		ev.ID, _ = crypto.RandomHex(12)
	}
	if ev.SchemaVersion == "" {
		ev.SchemaVersion = "1.0"
	}
	if ev.CreatedAt.IsZero() {
		ev.CreatedAt = time.Now().UTC()
	}
	s.Store.AppendSecurityEvent(ev)
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

func (s *Server) handleGetBotPolicy(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	siteID := r.PathValue("id")
	if _, err := s.Store.GetSite(claims.TenantID, siteID); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.Store.GetBotPolicy(claims.TenantID, siteID))
}

func (s *Server) handleUpsertBotPolicy(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	siteID := r.PathValue("id")
	if _, err := s.Store.GetSite(claims.TenantID, siteID); err != nil {
		writeStoreError(w, err)
		return
	}
	var req struct {
		Mode                string   `json:"mode"`
		ChallengeDifficulty int      `json:"challenge_difficulty"`
		AllowlistedBots     []string `json:"allowlisted_bots"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Mode != "off" && req.Mode != "observe" && req.Mode != "enforce" {
		writeError(w, http.StatusBadRequest, "bot mode must be off, observe, or enforce")
		return
	}
	if req.ChallengeDifficulty == 0 {
		req.ChallengeDifficulty = 3
	}
	if req.ChallengeDifficulty < 1 || req.ChallengeDifficulty > 6 {
		writeError(w, http.StatusBadRequest, "challenge_difficulty must be between 1 and 6")
		return
	}
	pol := store.BotPolicy{
		SiteID:              siteID,
		TenantID:            claims.TenantID,
		Mode:                req.Mode,
		ChallengeDifficulty: req.ChallengeDifficulty,
		AllowlistedBots:     req.AllowlistedBots,
		UpdatedAt:           time.Now().UTC(),
	}
	if err := s.Store.UpsertBotPolicy(pol); err != nil {
		writeStoreError(w, err)
		return
	}
	s.recordAudit(claims.TenantID, claims.UserID, "bot.policy_update", "site", siteID, map[string]string{"mode": pol.Mode})
	writeJSON(w, http.StatusOK, pol)
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		if !strings.HasPrefix(authz, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		claims, err := crypto.VerifyToken(s.JWTSecret, strings.TrimPrefix(authz, "Bearer "))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}
		ctx := context.WithValue(r.Context(), claimsContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) requireWriteRole(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := claimsFromContext(r.Context())
		if claims.Role != "owner" && claims.Role != "admin" {
			writeError(w, http.StatusForbidden, "insufficient role")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireAgentAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		token := strings.TrimPrefix(authz, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.AgentToken)) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized gateway agent")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) recordAudit(tenantID, userID, action, resourceType, resourceID string, meta map[string]string) {
	id, _ := crypto.RandomHex(12)
	s.Store.AppendAuditLog(store.AuditLog{
		ID:           id,
		TenantID:     tenantID,
		ActorUserID:  userID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Metadata:     meta,
		CreatedAt:    time.Now().UTC(),
	})
}

func claimsFromContext(ctx context.Context) crypto.TokenClaims {
	c, _ := ctx.Value(claimsContextKey).(crypto.TokenClaims)
	return c
}

func writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "resource not found")
	case errors.Is(err, store.ErrForbidden):
		writeError(w, http.StatusForbidden, "forbidden")
	default:
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
