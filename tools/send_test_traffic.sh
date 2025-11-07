#!/usr/bin/env bash
set -euo pipefail

# This script sends benign test traffic to the honeypot.
# Replace placeholders with your own (testing) payloads if desired.

HOST="127.0.0.1"
HTTP_PORT="${HTTP_PORT:-80}"
HTTPS_PORT="${HTTPS_PORT:-443}"
SSH_PORT="${SSH_PORT:-22}"

echo "[*] Sending HTTP GET with placeholder payloads to ${HOST}:${HTTP_PORT}"
curl -sS -A "curl-test/1.0" \
  -H "X-Test: <INJECTION_PLACEHOLDER>" \
  "http://${HOST}:${HTTP_PORT}/?q=%3CINJECTION_PLACEHOLDER%3E" -o /dev/null -D - || true

echo "[*] Sending HTTPS (simulated) GET to ${HOST}:${HTTPS_PORT}"
curl -sS -A "curl-test/1.0" \
  -H "X-Test: <XSS_PLACEHOLDER>" \
  "http://${HOST}:${HTTPS_PORT}/path?x=%3CXSS_PLACEHOLDER%3E" -o /dev/null -D - || true

echo "[*] Connecting to SSH port ${SSH_PORT} to receive banner"
if command -v nc >/dev/null 2>&1; then
  printf "\n" | nc -v -w 2 "${HOST}" "${SSH_PORT}" || true
else
  echo "[!] 'nc' not found; skipping SSH test"
fi

echo "[*] Testing rate-limiting with parallel HTTP requests (20 quick connections)"
for i in $(seq 1 20); do
  (curl -sS "http://${HOST}:${HTTP_PORT}/rate-test?i=${i}" -o /dev/null || true) &
done
wait || true

echo "[+] Done. Check logs at logs/events.jsonl and dashboard at http://localhost:8080"


