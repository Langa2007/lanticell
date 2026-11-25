package main

import (
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/lanticell/control-api/internal/httpserver"
	"github.com/lanticell/control-api/internal/store"
)

func main() {
	port := envOr("CONTROL_API_PORT", "8080")
	jwtSecret := []byte(envOr("JWT_SECRET", "dev-jwt-secret-change-in-prod-32bytes"))
	encKeyHex := envOr("ORIGIN_ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	agentToken := envOr("AGENT_TOKEN", "dev-agent-token")

	encKey, err := hex.DecodeString(encKeyHex)
	if err != nil || len(encKey) != 32 {
		log.Fatalf("ORIGIN_ENCRYPTION_KEY must be 64 hex chars (32 bytes)")
	}

	st := store.NewStore()
	srv := httpserver.NewServer(st, jwtSecret, encKey, agentToken)

	httpSrv := &http.Server{
		Addr:              ":" + port,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
	}

	log.Printf("lanticell control-api listening on :%s", port)
	log.Fatal(httpSrv.ListenAndServe())
}

func envOr(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
