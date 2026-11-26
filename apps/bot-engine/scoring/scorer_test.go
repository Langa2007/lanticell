package scoring_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
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

func newTestAggregator() (*scoring.Aggregator, *reputation.Detector) {
	mem := state.NewMemoryStore(5000)
	rep := reputation.New()
	agg := scoring.NewAggregator(
		rate.New(mem, 10*time.Second, 15),
		sequence.New(mem),
		clientconsistency.New(),
		accountabuse.New(mem, 1*time.Minute, 5),
		scraping.New(mem, 1*time.Minute, 10),
		rep,
	)
	return agg, rep
}

func TestCGNATAndOperaMiniNotHardBlocked(t *testing.T) {
	agg, _ := newTestAggregator()
	ctx := context.Background()
	now := time.Now().UTC()
	pol := scoring.SiteBotPolicy{Mode: "enforce"}

	// Simulate 25 requests from a shared Safaricom CGNAT IPv4 using Opera Mini
	for i := 0; i < 25; i++ {
		dec := agg.Evaluate(ctx, detectorsdk.RequestFeatures{
			SiteID:         "s1",
			Method:         "GET",
			Route:          "/news",
			RouteType:      "public",
			ClientPrefix:   "41.90.64.0/24",
			UserAgent:      "Opera/9.80 (Android; Opera Mini/72.0; en)",
			Headers:        map[string]string{"X-OperaMini-Features": "advanced"},
			IsBrowserRoute: true,
			Timestamp:      now.Add(time.Duration(i) * 100 * time.Millisecond),
		}, pol)
		if dec.Action == "block" {
			t.Fatalf("CGNAT/Opera Mini user must never be hard-blocked solely on IP velocity (got block at req %d)", i)
		}
	}
}

func TestCredentialStuffingAndScrapingDetected(t *testing.T) {
	agg, rep := newTestAggregator()
	ctx := context.Background()
	now := time.Now().UTC()
	pol := scoring.SiteBotPolicy{Mode: "enforce"}

	// Add reputation hit for attacker prefix
	rep.Upsert("198.51.100.0/24", reputation.FeedEntry{
		Source:     "crowdsec",
		Confidence: 0.9,
		ExpiresAt:  now.Add(1 * time.Hour),
	})

	// Credential stuffing burst with 401 failures from scripted client
	var lastDec scoring.Decision
	for i := 0; i < 8; i++ {
		lastDec = agg.Evaluate(ctx, detectorsdk.RequestFeatures{
			SiteID:         "s1",
			Method:         "POST",
			Route:          "/api/v1/login",
			RouteType:      "login",
			ClientPrefix:   "198.51.100.0/24",
			UserAgent:      "python-requests/2.32.3",
			StatusHint:     401,
			IsBrowserRoute: true,
			Timestamp:      now.Add(time.Duration(i) * time.Second),
		}, pol)
	}
	if lastDec.Action != "block" && lastDec.Action != "challenge" {
		t.Fatalf("expected block or challenge for credential stuffing, got %s (score=%.2f reasons=%v)", lastDec.Action, lastDec.RiskScore, lastDec.ReasonCodes)
	}

	// Conservative observe mode never blocks
	obsDec := agg.Evaluate(ctx, detectorsdk.RequestFeatures{
		SiteID:         "s1",
		Method:         "POST",
		Route:          "/api/v1/login",
		RouteType:      "login",
		ClientPrefix:   "198.51.100.0/24",
		UserAgent:      "python-requests/2.32.3",
		StatusHint:     401,
		IsBrowserRoute: true,
		Timestamp:      now.Add(10 * time.Second),
	}, scoring.SiteBotPolicy{Mode: "observe"})
	if obsDec.Action != "observe" {
		t.Fatalf("expected observe in monitor mode, got %s", obsDec.Action)
	}
}

func TestAllowlistedBotsAndWebhooks(t *testing.T) {
	agg, _ := newTestAggregator()
	ctx := context.Background()
	now := time.Now().UTC()
	pol := scoring.SiteBotPolicy{
		Mode:            "enforce",
		AllowlistedBots: []string{"UptimeRobot", "Googlebot"},
	}

	botDec := agg.Evaluate(ctx, detectorsdk.RequestFeatures{
		SiteID:         "s1",
		Method:         "GET",
		Route:          "/",
		RouteType:      "public",
		UserAgent:      "Mozilla/5.0 (compatible; UptimeRobot/2.0)",
		IsBrowserRoute: true,
		Timestamp:      now,
	}, pol)
	if botDec.Action != "allow" {
		t.Fatalf("expected allowlisted bot to pass, got %s", botDec.Action)
	}

	hookDec := agg.Evaluate(ctx, detectorsdk.RequestFeatures{
		SiteID:         "s1",
		Method:         "POST",
		Route:          "/api/webhooks/mpesa",
		RouteType:      "webhook",
		UserAgent:      "Daraja/1.0",
		IsBrowserRoute: false,
		Timestamp:      now,
	}, pol)
	if hookDec.Action != "allow" {
		t.Fatalf("expected fintech webhook to pass, got %s", hookDec.Action)
	}
}

func TestInbuiltPoWChallengeAndClearanceCookie(t *testing.T) {
	mgr := challenge.NewManager([]byte("super-secret-challenge-key-32b!!"), 2, 15*time.Minute)
	now := time.Now().UTC()
	prefix := "102.89.10.0/24"
	ua := "Mozilla/5.0"

	token := mgr.CreateChallenge(prefix, ua, now)
	var solution string
	for i := 0; i < 100000; i++ {
		cand := fmt.Sprintf("%d", i)
		sum := sha256.Sum256([]byte(token + ":" + cand))
		if strings.HasPrefix(hex.EncodeToString(sum[:]), "00") {
			solution = cand
			break
		}
	}
	if solution == "" {
		t.Fatalf("failed to solve test PoW")
	}

	cookie, ok := mgr.VerifyPoW(token, solution, prefix, ua, now)
	if !ok || cookie == "" {
		t.Fatalf("expected valid PoW solution to issue clearance cookie")
	}
	if !mgr.VerifyClearance(cookie, prefix, ua, now.Add(5*time.Minute)) {
		t.Fatalf("expected clearance cookie to verify")
	}
	if mgr.VerifyClearance(cookie, "10.0.0.0/24", ua, now.Add(5*time.Minute)) {
		t.Fatalf("clearance cookie must be bound to client prefix")
	}
}
