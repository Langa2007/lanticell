package store

import (
	"errors"
	"sync"
	"time"

	"github.com/lanticell/control-api/internal/apipolicy"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
	ErrForbidden     = errors.New("forbidden")
)

type Tenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"created_at"`
}

type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	MFAEnabled   bool      `json:"mfa_enabled"`
	CreatedAt    time.Time `json:"created_at"`
}

type Membership struct {
	TenantID string `json:"tenant_id"`
	UserID   string `json:"user_id"`
	Role     string `json:"role"` // owner | admin | viewer
}

type Site struct {
	ID                   string     `json:"id"`
	TenantID             string     `json:"tenant_id"`
	Domain               string     `json:"domain"`
	TXTVerificationToken string     `json:"txt_verification_token"`
	VerifiedAt           *time.Time `json:"verified_at,omitempty"`
	TLSMode              string     `json:"tls_mode"` // acme | custom | dev_self_signed
	Status               string     `json:"status"`   // pending_verification | active | paused
	CreatedAt            time.Time  `json:"created_at"`
}

type Origin struct {
	ID              string    `json:"id"`
	SiteID          string    `json:"site_id"`
	TenantID        string    `json:"tenant_id"`
	UpstreamURL     string    `json:"upstream_url"`
	OriginSecretEnc []byte    `json:"-"`
	ConnectTimeoutMs int      `json:"connect_timeout_ms"`
	ReadTimeoutMs   int       `json:"read_timeout_ms"`
	MaxBodyBytes    int64     `json:"max_body_bytes"`
	RateLimitRPS    int       `json:"rate_limit_rps"`
	CreatedAt       time.Time `json:"created_at"`
}

type AuditLog struct {
	ID           string            `json:"id"`
	TenantID     string            `json:"tenant_id"`
	ActorUserID  string            `json:"actor_user_id"`
	Action       string            `json:"action"`
	ResourceType string            `json:"resource_type"`
	ResourceID   string            `json:"resource_id"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
}

type GatewayNode struct {
	ID             string    `json:"id"`
	Region         string    `json:"region"`
	AppliedVersion int64     `json:"applied_version"`
	Healthy        bool      `json:"healthy"`
	LastSeenAt     time.Time `json:"last_seen_at"`
}

type WAFPolicy struct {
	SiteID              string    `json:"site_id"`
	TenantID            string    `json:"tenant_id"`
	Mode                string    `json:"mode"` // off | monitor | block
	CRSVersion          string    `json:"crs_version"`
	MaxInspectBodyBytes int64     `json:"max_inspect_body_bytes"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type BotPolicy struct {
	SiteID              string    `json:"site_id"`
	TenantID            string    `json:"tenant_id"`
	Mode                string    `json:"mode"` // off | observe | enforce
	ChallengeDifficulty int       `json:"challenge_difficulty"`
	AllowlistedBots     []string  `json:"allowlisted_bots,omitempty"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type APISchemaVersion struct {
	ID        string                   `json:"id"`
	TenantID  string                   `json:"tenant_id"`
	SiteID    string                   `json:"site_id"`
	Version   int64                    `json:"version"`
	Endpoints []apipolicy.EndpointSpec `json:"endpoints"`
	Active    bool                     `json:"active"`
	CreatedBy string                   `json:"created_by"`
	CreatedAt time.Time                `json:"created_at"`
}

type APIInventoryEntry struct {
	SiteID         string    `json:"site_id"`
	TenantID       string    `json:"tenant_id"`
	Method         string    `json:"method"`
	NormalizedPath string    `json:"normalized_path"`
	Documented     bool      `json:"documented"`
	HitCount       int64     `json:"hit_count"`
	LastSeenAt     time.Time `json:"last_seen_at"`
}

type WAFExclusion struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"tenant_id"`
	SiteID      string     `json:"site_id"`
	RoutePrefix string     `json:"route_prefix"`
	RuleID      string     `json:"rule_id"`
	Reason      string     `json:"reason"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
}

type SecurityEvent struct {
	ID            string    `json:"id"`
	SchemaVersion string    `json:"schema_version"`
	CorrelationID string    `json:"correlation_id"`
	TenantID      string    `json:"tenant_id"`
	SiteID        string    `json:"site_id"`
	Route         string    `json:"route"`
	RuleID        string    `json:"rule_id"`
	CRSVersion    string    `json:"crs_version"`
	Action        string    `json:"action"` // allow | observe | block
	Confidence    float64   `json:"confidence"`
	ReasonCode    string    `json:"reason_code"`
	CreatedAt     time.Time `json:"created_at"`
}

// Store defines tenant-isolated persistence operations.
type Store struct {
	mu             sync.RWMutex
	tenants        map[string]Tenant
	usersByMail    map[string]User
	memberships    map[string]Membership // key: userID + ":" + tenantID
	sites          map[string]Site
	origins        map[string]Origin // key: siteID
	wafPolicies    map[string]WAFPolicy // key: siteID
	botPolicies    map[string]BotPolicy // key: siteID
	wafExclusions  map[string][]WAFExclusion // key: siteID
	routePolicies  map[string][]apipolicy.RoutePolicy // key: siteID
	apiSchemas     map[string][]APISchemaVersion      // key: siteID
	apiInventory   map[string][]APIInventoryEntry     // key: siteID
	securityEvents []SecurityEvent
	auditLogs      []AuditLog
	gateways       map[string]GatewayNode
	version        int64
}

func NewStore() *Store {
	return &Store{
		tenants:       make(map[string]Tenant),
		usersByMail:   make(map[string]User),
		memberships:   make(map[string]Membership),
		sites:         make(map[string]Site),
		origins:       make(map[string]Origin),
		wafPolicies:   make(map[string]WAFPolicy),
		botPolicies:   make(map[string]BotPolicy),
		wafExclusions: make(map[string][]WAFExclusion),
		routePolicies: make(map[string][]apipolicy.RoutePolicy),
		apiSchemas:    make(map[string][]APISchemaVersion),
		apiInventory:  make(map[string][]APIInventoryEntry),
		gateways:      make(map[string]GatewayNode),
		version:       1,
	}
}

func (s *Store) CreateTenantAndOwner(t Tenant, u User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.usersByMail[u.Email]; exists {
		return ErrAlreadyExists
	}
	for _, existing := range s.tenants {
		if existing.Slug == t.Slug {
			return ErrAlreadyExists
		}
	}
	s.tenants[t.ID] = t
	s.usersByMail[u.Email] = u
	s.memberships[u.ID+":"+t.ID] = Membership{
		TenantID: t.ID,
		UserID:   u.ID,
		Role:     "owner",
	}
	return nil
}

func (s *Store) GetUserByEmail(email string) (User, Membership, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.usersByMail[email]
	if !ok {
		return User{}, Membership{}, ErrNotFound
	}
	for _, m := range s.memberships {
		if m.UserID == u.ID {
			return u, m, nil
		}
	}
	return u, Membership{}, ErrNotFound
}

func (s *Store) CreateSite(site Site) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.sites {
		if existing.Domain == site.Domain {
			return ErrAlreadyExists
		}
	}
	s.sites[site.ID] = site
	s.version++
	return nil
}

func (s *Store) ListSites(tenantID string) []Site {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Site, 0)
	for _, site := range s.sites {
		if site.TenantID == tenantID {
			out = append(out, site)
		}
	}
	return out
}

func (s *Store) GetSite(tenantID, siteID string) (Site, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	site, ok := s.sites[siteID]
	if !ok {
		return Site{}, ErrNotFound
	}
	if site.TenantID != tenantID {
		return Site{}, ErrForbidden
	}
	return site, nil
}

func (s *Store) MarkSiteVerified(tenantID, siteID string, verifiedAt time.Time) (Site, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	site, ok := s.sites[siteID]
	if !ok {
		return Site{}, ErrNotFound
	}
	if site.TenantID != tenantID {
		return Site{}, ErrForbidden
	}
	site.VerifiedAt = &verifiedAt
	site.Status = "active"
	s.sites[siteID] = site
	s.version++
	return site, nil
}

func (s *Store) UpsertOrigin(origin Origin) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	site, ok := s.sites[origin.SiteID]
	if !ok {
		return ErrNotFound
	}
	if site.TenantID != origin.TenantID {
		return ErrForbidden
	}
	s.origins[origin.SiteID] = origin
	s.version++
	return nil
}

func (s *Store) GetOrigin(tenantID, siteID string) (Origin, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	origin, ok := s.origins[siteID]
	if !ok {
		return Origin{}, ErrNotFound
	}
	if origin.TenantID != tenantID {
		return Origin{}, ErrForbidden
	}
	return origin, nil
}

func (s *Store) AppendAuditLog(entry AuditLog) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditLogs = append(s.auditLogs, entry)
}

func (s *Store) ListAuditLogs(tenantID string) []AuditLog {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AuditLog, 0)
	for _, entry := range s.auditLogs {
		if entry.TenantID == tenantID {
			out = append(out, entry)
		}
	}
	return out
}

func (s *Store) UpsertGatewayHealth(node GatewayNode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gateways[node.ID] = node
}

func (s *Store) ActiveSitesWithOrigins() (int64, []Site, map[string]Origin) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sites := make([]Site, 0)
	origins := make(map[string]Origin)
	for _, site := range s.sites {
		if site.Status == "active" {
			if origin, ok := s.origins[site.ID]; ok {
				sites = append(sites, site)
				origins[site.ID] = origin
			}
		}
	}
	return s.version, sites, origins
}

func (s *Store) UpsertWAFPolicy(p WAFPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	site, ok := s.sites[p.SiteID]
	if !ok {
		return ErrNotFound
	}
	if site.TenantID != p.TenantID {
		return ErrForbidden
	}
	s.wafPolicies[p.SiteID] = p
	s.version++
	return nil
}

func (s *Store) GetWAFPolicy(tenantID, siteID string) WAFPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if p, ok := s.wafPolicies[siteID]; ok && p.TenantID == tenantID {
		return p
	}
	return WAFPolicy{
		SiteID:              siteID,
		TenantID:            tenantID,
		Mode:                "monitor",
		CRSVersion:          "4.10.0",
		MaxInspectBodyBytes: 131072,
	}
}

func (s *Store) AddWAFExclusion(ex WAFExclusion) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	site, ok := s.sites[ex.SiteID]
	if !ok {
		return ErrNotFound
	}
	if site.TenantID != ex.TenantID {
		return ErrForbidden
	}
	s.wafExclusions[ex.SiteID] = append(s.wafExclusions[ex.SiteID], ex)
	s.version++
	return nil
}

func (s *Store) ListWAFExclusions(tenantID, siteID string) ([]WAFExclusion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	site, ok := s.sites[siteID]
	if !ok {
		return nil, ErrNotFound
	}
	if site.TenantID != tenantID {
		return nil, ErrForbidden
	}
	list := s.wafExclusions[siteID]
	out := make([]WAFExclusion, len(list))
	copy(out, list)
	return out, nil
}

func (s *Store) DeleteWAFExclusion(tenantID, siteID, exclusionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	site, ok := s.sites[siteID]
	if !ok {
		return ErrNotFound
	}
	if site.TenantID != tenantID {
		return ErrForbidden
	}
	list := s.wafExclusions[siteID]
	for i, ex := range list {
		if ex.ID == exclusionID {
			s.wafExclusions[siteID] = append(list[:i], list[i+1:]...)
			s.version++
			return nil
		}
	}
	return ErrNotFound
}

func (s *Store) AppendSecurityEvent(ev SecurityEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Keep bounded in-memory buffer of recent events
	if len(s.securityEvents) >= 5000 {
		s.securityEvents = s.securityEvents[1:]
	}
	s.securityEvents = append(s.securityEvents, ev)
}

func (s *Store) ListSecurityEvents(tenantID string) []SecurityEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]SecurityEvent, 0)
	for i := len(s.securityEvents) - 1; i >= 0; i-- {
		if s.securityEvents[i].TenantID == tenantID {
			out = append(out, s.securityEvents[i])
		}
	}
	return out
}

func (s *Store) UpsertBotPolicy(p BotPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	site, ok := s.sites[p.SiteID]
	if !ok {
		return ErrNotFound
	}
	if site.TenantID != p.TenantID {
		return ErrForbidden
	}
	s.botPolicies[p.SiteID] = p
	s.version++
	return nil
}

func (s *Store) GetBotPolicy(tenantID, siteID string) BotPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if p, ok := s.botPolicies[siteID]; ok && p.TenantID == tenantID {
		return p
	}
	return BotPolicy{
		SiteID:              siteID,
		TenantID:            tenantID,
		Mode:                "observe",
		ChallengeDifficulty: 3,
	}
}

func (s *Store) AddRoutePolicy(p apipolicy.RoutePolicy) ([]apipolicy.PolicyConflict, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	site, ok := s.sites[p.SiteID]
	if !ok {
		return nil, ErrNotFound
	}
	if site.TenantID != p.TenantID {
		return nil, ErrForbidden
	}
	existing := s.routePolicies[p.SiteID]
	if conflicts := apipolicy.DetectConflicts(existing, p); len(conflicts) > 0 {
		return conflicts, nil
	}
	s.routePolicies[p.SiteID] = append(existing, p)
	s.version++
	return nil, nil
}

func (s *Store) ListRoutePolicies(tenantID, siteID string) ([]apipolicy.RoutePolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	site, ok := s.sites[siteID]
	if !ok {
		return nil, ErrNotFound
	}
	if site.TenantID != tenantID {
		return nil, ErrForbidden
	}
	list := s.routePolicies[siteID]
	out := make([]apipolicy.RoutePolicy, len(list))
	copy(out, list)
	return out, nil
}

func (s *Store) DeleteRoutePolicy(tenantID, siteID, policyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	site, ok := s.sites[siteID]
	if !ok {
		return ErrNotFound
	}
	if site.TenantID != tenantID {
		return ErrForbidden
	}
	list := s.routePolicies[siteID]
	for i, p := range list {
		if p.ID == policyID {
			s.routePolicies[siteID] = append(list[:i], list[i+1:]...)
			s.version++
			return nil
		}
	}
	return ErrNotFound
}

func (s *Store) AddAPISchema(schema APISchemaVersion) (APISchemaVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	site, ok := s.sites[schema.SiteID]
	if !ok {
		return APISchemaVersion{}, ErrNotFound
	}
	if site.TenantID != schema.TenantID {
		return APISchemaVersion{}, ErrForbidden
	}
	list := s.apiSchemas[schema.SiteID]
	for i := range list {
		list[i].Active = false
	}
	schema.Version = int64(len(list) + 1)
	schema.Active = true
	s.apiSchemas[schema.SiteID] = append(list, schema)
	s.version++
	return schema, nil
}

func (s *Store) ListAPISchemas(tenantID, siteID string) ([]APISchemaVersion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	site, ok := s.sites[siteID]
	if !ok {
		return nil, ErrNotFound
	}
	if site.TenantID != tenantID {
		return nil, ErrForbidden
	}
	list := s.apiSchemas[siteID]
	out := make([]APISchemaVersion, len(list))
	copy(out, list)
	return out, nil
}

func (s *Store) RollbackAPISchema(tenantID, siteID string, targetVersion int64) (APISchemaVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	site, ok := s.sites[siteID]
	if !ok {
		return APISchemaVersion{}, ErrNotFound
	}
	if site.TenantID != tenantID {
		return APISchemaVersion{}, ErrForbidden
	}
	list := s.apiSchemas[siteID]
	foundIdx := -1
	for i := range list {
		if list[i].Version == targetVersion {
			foundIdx = i
		}
		list[i].Active = false
	}
	if foundIdx == -1 {
		return APISchemaVersion{}, ErrNotFound
	}
	list[foundIdx].Active = true
	s.apiSchemas[siteID] = list
	s.version++
	return list[foundIdx], nil
}

func (s *Store) ActiveAPISchemaEndpoints(siteID string) []apipolicy.EndpointSpec {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sc := range s.apiSchemas[siteID] {
		if sc.Active {
			return sc.Endpoints
		}
	}
	return nil
}

func (s *Store) RecordAPIInventory(entry APIInventoryEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.apiInventory[entry.SiteID]
	for i := range list {
		if list[i].Method == entry.Method && list[i].NormalizedPath == entry.NormalizedPath {
			list[i].HitCount += entry.HitCount
			list[i].Documented = entry.Documented
			list[i].LastSeenAt = entry.LastSeenAt
			s.apiInventory[entry.SiteID] = list
			return
		}
	}
	s.apiInventory[entry.SiteID] = append(list, entry)
}

func (s *Store) ListAPIInventory(tenantID, siteID string) ([]APIInventoryEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	site, ok := s.sites[siteID]
	if !ok {
		return nil, ErrNotFound
	}
	if site.TenantID != tenantID {
		return nil, ErrForbidden
	}
	list := s.apiInventory[siteID]
	out := make([]APIInventoryEntry, len(list))
	copy(out, list)
	return out, nil
}
