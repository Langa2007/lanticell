#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
BOTD_URL="${BOTD_URL:-http://localhost:8090}"

echo "Checking control-api healthz, status, and metrics..."
curl -fsS "${BASE_URL}/healthz" > /dev/null
curl -fsS "${BASE_URL}/status" > /dev/null
curl -fsS "${BASE_URL}/metrics" | grep -q "lanticell_http_requests_total"

echo "Checking botd healthz and metrics..."
curl -fsS "${BOTD_URL}/healthz" > /dev/null
curl -fsS "${BOTD_URL}/metrics" | grep -q "lanticell_botd_evaluations_total"

echo "Phase 5 smoke checks passed."
