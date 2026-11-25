package reload_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lanticell/gateway-agent/internal/reload"
	"github.com/lanticell/gateway-agent/internal/validator"
)

func signBundle(t *testing.T, bundle *validator.ConfigBundle, key []byte) {
	t.Helper()
	unsignedBytes, err := json.Marshal(struct {
		SchemaVersion string                      `json:"schema_version"`
		Version       int64                       `json:"version"`
		GeneratedAt   time.Time                   `json:"generated_at"`
		Sites         []validator.SiteRouteConfig `json:"sites"`
	}{
		SchemaVersion: bundle.SchemaVersion,
		Version:       bundle.Version,
		GeneratedAt:   bundle.GeneratedAt,
		Sites:         bundle.Sites,
	})
	if err != nil {
		t.Fatalf("marshal unsigned: %v", err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(unsignedBytes)
	bundle.Signature = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestApplyBundleAndPreserveLastGood(t *testing.T) {
	tmp := t.TempDir()
	nginxDir := filepath.Join(tmp, "conf.d")
	lastGoodDir := filepath.Join(tmp, "last-good")
	key := []byte("test-signing-key-32-bytes-secret")

	valid := validator.ConfigBundle{
		SchemaVersion: "1.0",
		Version:       2,
		GeneratedAt:   time.Now().UTC(),
		Sites: []validator.SiteRouteConfig{
			{
				SiteID:           "s1",
				TenantID:         "t1",
				Domain:           "app.example.co.ke",
				TLSMode:          "acme",
				UpstreamURL:      "http://sample-origin:9000",
				OriginSecret:     "secret-123",
				ConnectTimeoutMs: 3000,
				ReadTimeoutMs:    15000,
				MaxBodyBytes:     10485760,
				RateLimitRPS:     50,
			},
		},
	}
	signBundle(t, &valid, key)

	if err := reload.ApplyBundle(valid, key, nginxDir, lastGoodDir); err != nil {
		t.Fatalf("expected valid bundle to apply, got: %v", err)
	}

	confBytes, err := os.ReadFile(filepath.Join(nginxDir, "lanticell-sites.conf"))
	if err != nil {
		t.Fatalf("read nginx conf: %v", err)
	}
	if !strings.Contains(string(confBytes), "server_name app.example.co.ke;") {
		t.Fatalf("missing server_name in generated config")
	}

	// Attempt to apply a tampered / invalid bundle; must fail and preserve v2
	tampered := valid
	tampered.Version = 3
	tampered.Sites[0].Domain = "bad.com; evil"
	if err := reload.ApplyBundle(tampered, key, nginxDir, lastGoodDir); err == nil {
		t.Fatalf("expected tampered bundle to be rejected")
	}

	lastGood, err := reload.LoadLastGood(lastGoodDir)
	if err != nil || lastGood.Version != 2 {
		t.Fatalf("expected last-good version 2 preserved, got v%d (err=%v)", lastGood.Version, err)
	}
}
