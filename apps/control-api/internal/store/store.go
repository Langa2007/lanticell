package store

import (
	"errors"
	"sync"
	"time"
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

// Store defines tenant-isolated persistence operations.
type Store struct {
	mu          sync.RWMutex
	tenants     map[string]Tenant
	usersByMail map[string]User
	memberships map[string]Membership // key: userID + ":" + tenantID
	sites       map[string]Site
	origins     map[string]Origin // key: siteID
	auditLogs   []AuditLog
	gateways    map[string]GatewayNode
	version     int64
}

func NewStore() *Store {
	return &Store{
		tenants:     make(map[string]Tenant),
		usersByMail: make(map[string]User),
		memberships: make(map[string]Membership),
		sites:       make(map[string]Site),
		origins:     make(map[string]Origin),
		gateways:    make(map[string]GatewayNode),
		version:     1,
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
