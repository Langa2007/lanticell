package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/lanticell/gateway-agent/internal/reload"
	"github.com/lanticell/gateway-agent/internal/validator"
)

func main() {
	gatewayID := envOr("GATEWAY_ID", "gw-local-01")
	controlURL := envOr("CONTROL_API_URL", "http://control-api:8080")
	agentToken := envOr("AGENT_TOKEN", "dev-agent-token")
	signingKey := []byte(envOr("JWT_SECRET", "dev-jwt-secret-change-in-prod-32bytes"))
	nginxDir := envOr("NGINX_CONFIG_DIR", "/etc/nginx/conf.d")
	lastGoodDir := envOr("LAST_GOOD_DIR", "/var/lib/lanticell/last-good")

	client := &http.Client{Timeout: 5 * time.Second}
	var currentVersion int64

	// Restore last-known-good config on startup if available
	if prev, err := reload.LoadLastGood(lastGoodDir); err == nil {
		if err := reload.ApplyBundle(prev, signingKey, nginxDir, lastGoodDir); err == nil {
			currentVersion = prev.Version
			log.Printf("restored last-known-good bundle v%d", currentVersion)
		}
	}

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		bundle, err := fetchBundle(client, controlURL, agentToken)
		if err != nil {
			log.Printf("control-plane unreachable (%v); retaining last-known-good v%d", err, currentVersion)
		} else if bundle.Version != currentVersion {
			if err := reload.ApplyBundle(bundle, signingKey, nginxDir, lastGoodDir); err != nil {
				log.Printf("rejected invalid bundle v%d: %v", bundle.Version, err)
			} else {
				currentVersion = bundle.Version
				log.Printf("applied bundle v%d (%d sites)", currentVersion, len(bundle.Sites))
			}
		}
		reportHealth(client, controlURL, agentToken, gatewayID, currentVersion)
		<-ticker.C
	}
}

func fetchBundle(client *http.Client, baseURL, token string) (validator.ConfigBundle, error) {
	var bundle validator.ConfigBundle
	req, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/agent/config", nil)
	if err != nil {
		return bundle, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return bundle, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return bundle, os.ErrInvalid
	}
	err = json.NewDecoder(resp.Body).Decode(&bundle)
	return bundle, err
}

func reportHealth(client *http.Client, baseURL, token, id string, version int64) {
	payload, _ := json.Marshal(map[string]any{
		"id":              id,
		"region":          "local",
		"applied_version": version,
		"healthy":         true,
	})
	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/agent/health", bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}

func envOr(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
