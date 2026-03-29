#!/bin/bash
# ============================================================================
# Jabali Security — ZAP Automated Security Scan
# ============================================================================
# Runs OWASP ZAP against a target site using the ZAP API.
# Performs spider crawl, active scan, and generates a report.
#
# Usage:
#   ./tests/test_zap_scan.sh <target_url> [--zap-api <zap_api_url>]
#
# Examples:
#   ./tests/test_zap_scan.sh https://123123.com
#   ./tests/test_zap_scan.sh https://123123.com --zap-api http://192.168.100.100:8090
#
# Requirements: curl, jq, running ZAP instance with API enabled
# ============================================================================
set -uo pipefail

# ── Config ──────────────────────────────────────────────────────────────────

TARGET="${1:-}"
shift || true

ZAP_API="http://192.168.100.100:8090"
ZAP_API_KEY=""
REPORT_DIR="/tmp"
MAX_SPIDER_MINS=5
MAX_SCAN_MINS=30

while [[ $# -gt 0 ]]; do
    case "$1" in
        --zap-api) ZAP_API="$2"; shift 2 ;;
        --api-key) ZAP_API_KEY="$2"; shift 2 ;;
        --report-dir) REPORT_DIR="$2"; shift 2 ;;
        --max-spider) MAX_SPIDER_MINS="$2"; shift 2 ;;
        --max-scan) MAX_SCAN_MINS="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_url> [--zap-api <url>] [--api-key <key>]"
    echo "Example: $0 https://123123.com --zap-api http://192.168.100.100:8090"
    exit 1
fi

REPORT_FILE="${REPORT_DIR}/jabali-zap-$(date +%Y%m%d-%H%M%S).html"
REPORT_JSON="${REPORT_DIR}/jabali-zap-$(date +%Y%m%d-%H%M%S).json"

# ── Helpers ────────────────────────────────────────────────────────────────

red()    { printf "\033[0;31m%s\033[0m\n" "$*"; }
green()  { printf "\033[0;32m%s\033[0m\n" "$*"; }
yellow() { printf "\033[0;33m%s\033[0m\n" "$*"; }
bold()   { printf "\033[1m%s\033[0m\n" "$*"; }

zap_api() {
    local endpoint="$1"
    shift
    local url="${ZAP_API}${endpoint}"
    if [ -n "$ZAP_API_KEY" ]; then
        url="${url}$(echo "$endpoint" | grep -q '?' && echo '&' || echo '?')apikey=${ZAP_API_KEY}"
    fi
    curl -s --max-time 30 "$url" "$@" 2>/dev/null
}

zap_api_val() {
    zap_api "$1" | jq -r "$2" 2>/dev/null
}

spinner() {
    local pid=$1
    local msg="$2"
    local chars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    while kill -0 "$pid" 2>/dev/null; do
        for (( i=0; i<${#chars}; i++ )); do
            printf "\r  %s %s" "${chars:$i:1}" "$msg"
            sleep 0.1
        done
    done
    printf "\r"
}

# ── Verify ZAP is running ──────────────────────────────────────────────────

bold "╔════════════════════════════════════════════════════════════════╗"
bold "║      Jabali Security — ZAP Automated Security Scan          ║"
bold "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "  Target:    ${TARGET}"
echo "  ZAP API:   ${ZAP_API}"
echo "  Report:    ${REPORT_FILE}"
echo ""

VERSION=$(zap_api_val "/JSON/core/view/version/" ".version")
if [ -z "$VERSION" ] || [ "$VERSION" = "null" ]; then
    red "ERROR: Cannot connect to ZAP API at ${ZAP_API}"
    red "Make sure ZAP is running and the API is accessible."
    exit 1
fi
green "  ZAP version: ${VERSION}"
echo ""

# ── Phase 1: Configure scan policies ───────────────────────────────────────

bold "Phase 1: Configuring scan policies"

# Set scan strength and threshold
zap_api "/JSON/ascan/action/setOptionDefaultPolicy/?id=0" > /dev/null
zap_api "/JSON/ascan/action/setOptionAttackStrength/?String=MEDIUM" > /dev/null
zap_api "/JSON/ascan/action/setOptionAlertThreshold/?String=LOW" > /dev/null

# Exclude common false-positive paths
for exclude in ".*logout.*" ".*signout.*" ".*wp-cron\.php.*"; do
    zap_api "/JSON/spider/action/excludeFromScan/?regex=${exclude}" > /dev/null
done

# Set max scan duration
zap_api "/JSON/ascan/action/setOptionMaxScanDurationInMins/?Integer=${MAX_SCAN_MINS}" > /dev/null

green "  Scan policies configured"

# ── Phase 2: Spider (crawl) ────────────────────────────────────────────────

bold "Phase 2: Spider crawl"

SPIDER_ID=$(zap_api_val "/JSON/spider/action/scan/?url=${TARGET}&maxChildren=50&recurse=true" ".scan")
if [ -z "$SPIDER_ID" ] || [ "$SPIDER_ID" = "null" ]; then
    red "  Failed to start spider"
    exit 1
fi
echo "  Spider started (ID: ${SPIDER_ID})"

# Wait for spider to complete
DEADLINE=$((SECONDS + MAX_SPIDER_MINS * 60))
while [ "$SECONDS" -lt "$DEADLINE" ]; do
    STATUS=$(zap_api_val "/JSON/spider/view/status/?scanId=${SPIDER_ID}" ".status")
    if [ "$STATUS" = "100" ]; then
        break
    fi
    printf "\r  Crawling... %s%%" "$STATUS"
    sleep 2
done
printf "\r"

URLS_FOUND=$(zap_api_val "/JSON/spider/view/results/?scanId=${SPIDER_ID}" ".results | length")
green "  Spider complete: ${URLS_FOUND} URLs discovered"

# ── Phase 3: Ajax Spider (optional, for JS-heavy sites) ────────────────────

bold "Phase 3: Ajax Spider (10 seconds for JS rendering)"

zap_api "/JSON/ajaxSpider/action/scan/?url=${TARGET}" > /dev/null
sleep 10
zap_api "/JSON/ajaxSpider/action/stop/" > /dev/null

AJAX_RESULTS=$(zap_api_val "/JSON/ajaxSpider/view/numberOfResults/" ".numberOfResults")
green "  Ajax spider found ${AJAX_RESULTS:-0} additional resources"

# ── Phase 4: Active Scan ──────────────────────────────────────────────────

bold "Phase 4: Active scan (max ${MAX_SCAN_MINS} minutes)"

SCAN_ID=$(zap_api_val "/JSON/ascan/action/scan/?url=${TARGET}&recurse=true" ".scan")
if [ -z "$SCAN_ID" ] || [ "$SCAN_ID" = "null" ]; then
    red "  Failed to start active scan"
    exit 1
fi
echo "  Active scan started (ID: ${SCAN_ID})"

DEADLINE=$((SECONDS + MAX_SCAN_MINS * 60))
while [ "$SECONDS" -lt "$DEADLINE" ]; do
    STATUS=$(zap_api_val "/JSON/ascan/view/status/?scanId=${SCAN_ID}" ".status")
    if [ "$STATUS" = "100" ]; then
        break
    fi
    printf "\r  Scanning... %s%%" "$STATUS"
    sleep 5
done
printf "\r"

green "  Active scan complete"

# ── Phase 5: Collect results ──────────────────────────────────────────────

bold "Phase 5: Results"

# Get alert summary
ALERTS_JSON=$(zap_api "/JSON/alert/view/alertsSummary/?baseurl=${TARGET}")

HIGH=$(echo "$ALERTS_JSON" | jq -r '.alertsSummary.High // 0')
MEDIUM=$(echo "$ALERTS_JSON" | jq -r '.alertsSummary.Medium // 0')
LOW=$(echo "$ALERTS_JSON" | jq -r '.alertsSummary.Low // 0')
INFO=$(echo "$ALERTS_JSON" | jq -r '.alertsSummary.Informational // 0')

echo ""
if [ "$HIGH" -gt 0 ] 2>/dev/null; then
    red "  HIGH:          ${HIGH}"
else
    green "  HIGH:          ${HIGH}"
fi
if [ "$MEDIUM" -gt 0 ] 2>/dev/null; then
    yellow "  MEDIUM:        ${MEDIUM}"
else
    green "  MEDIUM:        ${MEDIUM}"
fi
echo "  LOW:           ${LOW}"
echo "  INFORMATIONAL: ${INFO}"
echo ""

# Show individual alerts
bold "  Findings:"
ALERTS=$(zap_api "/JSON/alert/view/alerts/?baseurl=${TARGET}&start=0&count=100")
echo "$ALERTS" | jq -r '.alerts[] | "  [\(.risk)] \(.alert) — \(.url[:80])"' 2>/dev/null | sort -u | head -50

# ── Phase 6: Generate reports ─────────────────────────────────────────────

bold "Phase 6: Generating reports"

# HTML report
zap_api "/OTHER/core/other/htmlreport/" > "$REPORT_FILE"
green "  HTML report: ${REPORT_FILE}"

# JSON report
zap_api "/JSON/alert/view/alerts/?baseurl=${TARGET}&start=0&count=500" > "$REPORT_JSON"
green "  JSON report: ${REPORT_JSON}"

# ── Summary ───────────────────────────────────────────────────────────────

echo ""
bold "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
bold "SCAN COMPLETE"
bold "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Target:         ${TARGET}"
echo "  URLs crawled:   ${URLS_FOUND}"
echo "  HIGH alerts:    ${HIGH}"
echo "  MEDIUM alerts:  ${MEDIUM}"
echo "  LOW alerts:     ${LOW}"
echo "  INFO alerts:    ${INFO}"
echo ""
echo "  HTML report:    ${REPORT_FILE}"
echo "  JSON report:    ${REPORT_JSON}"
echo ""

TOTAL_ISSUES=$((HIGH + MEDIUM))
if [ "$TOTAL_ISSUES" -eq 0 ]; then
    green "  No HIGH or MEDIUM vulnerabilities found!"
elif [ "$HIGH" -gt 0 ]; then
    red "  ${HIGH} HIGH severity issues need immediate attention."
else
    yellow "  ${MEDIUM} MEDIUM severity issues found."
fi
echo ""
