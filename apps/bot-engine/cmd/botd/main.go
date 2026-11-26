package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/lanticell/bot-engine/challenge"
	"github.com/lanticell/bot-engine/detector/accountabuse"
	"github.com/lanticell/bot-engine/detector/clientconsistency"
	"github.com/lanticell/bot-engine/detector/rate"
	"github.com/lanticell/bot-engine/detector/reputation"
	"github.com/lanticell/bot-engine/detector/scraping"
	"github.com/lanticell/bot-engine/detector/sequence"
	"github.com/lanticell/bot-engine/scoring"
	"github.com/lanticell/bot-engine/state"
	detectorsdk "github.com/lanticell/detector-sdk"
)

func main() {
	port := envOr("BOTD_PORT", "8090")
	secret := []byte(envOr("BOT_CHALLENGE_SECRET", "dev-bot-challenge-secret-32bytes"))

	mem := state.NewMemoryStore(20000)
	rep := reputation.New()
	agg := scoring.NewAggregator(
		rate.New(mem, 10*time.Second, 30),
		sequence.New(mem),
		clientconsistency.New(),
		accountabuse.New(mem, 1*time.Minute, 8),
		scraping.New(mem, 1*time.Minute, 40),
		rep,
	)
	chal := challenge.NewManager(secret, 3, 30*time.Minute)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("POST /evaluate", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Features detectorsdk.RequestFeatures `json:"features"`
			Policy   scoring.SiteBotPolicy       `json:"policy"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32*1024)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if req.Features.Timestamp.IsZero() {
			req.Features.Timestamp = time.Now().UTC()
		}
		if req.Policy.Mode == "" {
			req.Policy.Mode = "observe"
		}
		dec := agg.Evaluate(r.Context(), req.Features, req.Policy)
		resp := map[string]any{"decision": dec}
		if dec.Action == "challenge" {
			resp["challenge_token"] = chal.CreateChallenge(req.Features.ClientPrefix, req.Features.UserAgent, req.Features.Timestamp)
			resp["difficulty"] = chal.Difficulty
		}
		writeJSON(w, http.StatusOK, resp)
	})

	mux.HandleFunc("POST /challenge/verify", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Token        string `json:"token"`
			Solution     string `json:"solution"`
			ClientPrefix string `json:"client_prefix"`
			UserAgent    string `json:"user_agent"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8*1024)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		cookie, ok := chal.VerifyPoW(req.Token, req.Solution, req.ClientPrefix, req.UserAgent, time.Now().UTC())
		if !ok {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid or expired challenge solution"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"clearance_cookie": cookie})
	})

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
	}
	log.Printf("lanticell botd listening on :%s", port)
	log.Fatal(srv.ListenAndServe())
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func envOr(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
