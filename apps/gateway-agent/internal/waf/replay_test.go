package waf_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lanticell/gateway-agent/internal/validator"
	"github.com/lanticell/gateway-agent/internal/waf"
)

type replayCase struct {
	Name           string            `json:"name"`
	Method         string            `json:"method"`
	Path           string            `json:"path"`
	Query          string            `json:"query"`
	Headers        map[string]string `json:"headers"`
	Body           string            `json:"body"`
	ExpectedRuleID string            `json:"expected_rule_id"`
}

func loadCorpus(t *testing.T, relPath string) []replayCase {
	t.Helper()
	abs := filepath.Join("..", "..", "..", "..", relPath)
	data, err := os.ReadFile(abs)
	if err != nil {
		t.Fatalf("read corpus %s: %v", abs, err)
	}
	var cases []replayCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatalf("unmarshal corpus %s: %v", abs, err)
	}
	return cases
}

func TestAttackAndBenignReplayCorpora(t *testing.T) {
	site := validator.SiteRouteConfig{
		SiteID:              "s1",
		TenantID:            "t1",
		Domain:              "api.example.co.ke",
		WAFMode:             "block",
		CRSVersion:          "4.10.0",
		MaxInspectBodyBytes: 131072,
	}
	now := time.Now().UTC()

	attacks := loadCorpus(t, filepath.Join("data", "replay", "attacks", "phase2_attacks.json"))
	for _, tc := range attacks {
		dec := waf.Evaluate(site, waf.RequestInput{
			Method:  tc.Method,
			Path:    tc.Path,
			Query:   tc.Query,
			Headers: tc.Headers,
			Body:    tc.Body,
		}, now)
		if dec.Action != "block" || dec.RuleID != tc.ExpectedRuleID {
			t.Errorf("attack %s: expected block with rule %s, got action=%s rule=%s", tc.Name, tc.ExpectedRuleID, dec.Action, dec.RuleID)
		}
	}

	benign := loadCorpus(t, filepath.Join("data", "replay", "benign", "phase2_benign.json"))
	for _, tc := range benign {
		dec := waf.Evaluate(site, waf.RequestInput{
			Method:  tc.Method,
			Path:    tc.Path,
			Query:   tc.Query,
			Headers: tc.Headers,
			Body:    tc.Body,
		}, now)
		if dec.Action != "allow" {
			t.Errorf("benign %s: false positive! got action=%s rule=%s", tc.Name, dec.Action, dec.RuleID)
		}
	}
}

func TestScopedExclusionAndBodyLimit(t *testing.T) {
	now := time.Now().UTC()
	expired := now.Add(-1 * time.Hour)
	site := validator.SiteRouteConfig{
		SiteID:              "s1",
		TenantID:            "t1",
		Domain:              "api.example.co.ke",
		WAFMode:             "block",
		CRSVersion:          "4.10.0",
		MaxInspectBodyBytes: 1024,
		WAFExclusions: []validator.WAFExclusionRule{
			{RoutePrefix: "/api/webhooks/momo", RuleID: "942100"},
			{RoutePrefix: "/expired", RuleID: "942100", ExpiresAt: &expired},
		},
	}

	// Excluded route allows matching rule
	decExcluded := waf.Evaluate(site, waf.RequestInput{
		Method: "POST",
		Path:   "/api/webhooks/momo",
		Body:   "note=1' OR 1=1--",
	}, now)
	if decExcluded.Action != "allow" {
		t.Fatalf("expected scoped exclusion to allow, got %s", decExcluded.Action)
	}

	// Expired exclusion still blocks
	decExpired := waf.Evaluate(site, waf.RequestInput{
		Method: "GET",
		Path:   "/expired",
		Query:  "id=1' OR 1=1--",
	}, now)
	if decExpired.Action != "block" {
		t.Fatalf("expected expired exclusion to block, got %s", decExpired.Action)
	}

	// Oversized body is safely bounded
	hugeBody := strings.Repeat("a", 5000)
	decBounded := waf.Evaluate(site, waf.RequestInput{
		Method: "POST",
		Path:   "/upload",
		Body:   hugeBody,
	}, now)
	if !decBounded.BodyTruncated || decBounded.Action != "allow" {
		t.Fatalf("expected bounded truncation and allow, got truncated=%v action=%s", decBounded.BodyTruncated, decBounded.Action)
	}
}
