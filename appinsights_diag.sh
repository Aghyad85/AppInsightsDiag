#!/usr/bin/env bash
# appinsights_diag.sh - Application Insights diagnostic (Linux Kudu Bash)
# Supports: Linux Dedicated / Premium / Elastic Premium App Service + Functions (plans with Kudu).
# Not supported: Linux Consumption / Flex Consumption (no Kudu shell available).
#
# Exit Codes: 0=Success 2=MissingConfig 3=ConnectivityFail 4=TelemetryFail 5=SamplingParseFail
#
# Features:
# 1. Config detection (connection string vs legacy instrumentation key)
# 2. Connectivity (HEAD request to ingestion endpoint /v2/track)
# 3. Minimal telemetry event send (EventData) OR AvailabilityData sample (--availability)
# 4. Sampling check (host.json parsing) + retention query snippet
# 5. HTML report + redacted log
# 6. Optional silent GET for site endpoint statistics (expect 404)
#
# Flags:
#   -v / --verbose            Verbose output (now default)
#   -F / --full               Full mode (prints all guidance + extra context)
#   -q / --quiet              Minimal output (override default verbose)
#   --emit-payload            Print the exact telemetry JSON payload inline (not redacted)
#   --hide-payload            Force redaction even if verbose/full (override default inline payload)
#   --availability            Send AvailabilityData sample envelope via /v2.1/track
#   --host-json <path>        Explicit host.json path override (sampling diagnostics)
#   -o / --output-dir <dir>   Output directory (default: "Application Insights Diagnostic")
#   -r / --report <file>      HTML report path/name (auto timestamp if omitted)
#   --site-path <relative>    Relative path for silent GET (default: /AppInsightsDiag)
#   --disable-site-ping       Skip silent GET
#   --no-redact               Do NOT redact connection string / iKey in log
#   --help                    Show usage help

set -euo pipefail

SCRIPT_START_UTC=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
OUTPUT_DIR="Application Insights Diagnostic"
HTML_REPORT=""
SITE_RELATIVE_PATH="/AppInsightsDiag"
VERBOSE=1  # default verbose; use --quiet to suppress guidance
SITE_PING=1
REDACT=1
FULL_MODE=0
EMIT_PAYLOAD=0
HIDE_PAYLOAD=0
AVAILABILITY_MODE=0
HOST_JSON_OVERRIDE=""

# Helper: safe extraction of key/value pairs from connection string without failing under pipefail
extract_from_conn() {
  local key="$1"; local src="$2"; printf '%s\n' "$src" | tr ';' '\n' | awk -F= -v k="$key" 'BEGIN{IGNORECASE=1} $1 ~ "^"k"$" {print $2}' | head -1 || true
}

print_help() {
  cat <<EOF
Usage: ./appinsights_diag.sh [options]

Options:
  -v, --verbose              (Default) Verbose output
  -F, --full                 Full mode (all guidance + hidden details; implies --verbose)
  -q, --quiet                Minimal output (suppress guidance lines)
  --emit-payload         Print raw telemetry JSON payload inline
  --hide-payload         Redact telemetry JSON (override default inline)
  --availability         Send AvailabilityData sample instead of EventData
      --host-json <file>     Explicit host.json path (override autodetect)
  -o, --output-dir <dir>     Output directory (default: "$OUTPUT_DIR")
  -r, --report <file>        HTML report file path (auto timestamp if omitted)
      --site-path <rel>      Relative path for silent GET (default: /AppInsightsDiag)
      --disable-site-ping    Skip silent GET statistics call
      --no-redact            Do NOT redact secrets in log
      --help                 Show this help

Exit Codes:
  0 Success
  2 Missing configuration (connection string)
  3 Connectivity failed
  4 Telemetry send failed
  5 Sampling parse failed

Unsupported Plans: Linux Consumption / Flex Consumption (no Kudu shell).
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--verbose) VERBOSE=1; shift;;
    -F|--full) FULL_MODE=1; VERBOSE=1; shift;;
    -q|--quiet) VERBOSE=0; shift;;
    --emit-payload) EMIT_PAYLOAD=1; shift;;
  --hide-payload) HIDE_PAYLOAD=1; shift;;
  --availability) AVAILABILITY_MODE=1; shift;;
  --host-json) HOST_JSON_OVERRIDE="$2"; shift 2;;
    -o|--output-dir) OUTPUT_DIR="$2"; shift 2;;
    -r|--report) HTML_REPORT="$2"; shift 2;;
    --site-path) SITE_RELATIVE_PATH="$2"; shift 2;;
    --disable-site-ping) SITE_PING=0; shift;;
    --no-redact) REDACT=0; shift;;
    --help) print_help; exit 0;;
    *) echo "[WARN] Unknown argument: $1"; shift;;
  esac
done

mkdir -p "$OUTPUT_DIR"
LOG_PATH="$OUTPUT_DIR/ai_diag_log.txt"

log() { printf "%s %s\n" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$*" >> "$LOG_PATH"; }
out() { echo "$*"; log "$*"; }
verb() { [[ $VERBOSE -eq 1 ]] && out "$*"; }

# Validate telemetry JSON payload before sending
validate_payload() {
  local payload="$1"
  local errors=()
  # Ensure last non-whitespace char is a closing brace for single-object envelope
  local trimmed
  trimmed=$(printf '%s' "$payload" | sed 's/[[:space:]]*$//')
  if [[ ${trimmed: -1} != '}' ]]; then
    errors+=("Payload does not end with '}' (last char='${trimmed: -1}')")
  fi
  if command -v jq >/dev/null 2>&1; then
    if ! printf '%s' "$payload" | jq . >/dev/null 2>&1; then
      errors+=("jq failed to parse payload JSON (not a valid single object)")
    else
      # Required fields minimal schema check
      local hasVer hasName hasIKey hasBaseType hasEventName
      hasVer=$(printf '%s' "$payload" | jq -r '.ver // empty')
      hasName=$(printf '%s' "$payload" | jq -r '.name // empty')
      hasIKey=$(printf '%s' "$payload" | jq -r '.iKey // empty')
      hasBaseType=$(printf '%s' "$payload" | jq -r '.data.baseType // empty')
      hasEventName=$(printf '%s' "$payload" | jq -r '.data.baseData.name // empty')
      [[ -z "$hasVer" ]] && errors+=("Missing .ver (envelope version)")
      [[ -z "$hasName" ]] && errors+=("Missing .name")
      [[ -z "$hasIKey" ]] && errors+=("Missing .iKey")
      [[ -z "$hasBaseType" ]] && errors+=("Missing .data.baseType")
      [[ -z "$hasEventName" ]] && errors+=("Missing .data.baseData.name")
    fi
  else
    verb "[Validator] jq not available; skipping deep JSON validation."
  fi
  if (( ${#errors[@]} > 0 )); then
    out "[ERROR] Payload validation failed:"; for e in "${errors[@]}"; do out "  - $e"; done
    return 1
  else
    verb "[Validator] Payload JSON passed basic checks."; return 0
  fi
}

# Deep debug for phantom second envelope scenario
debug_payload_tail() {
  local payload="$1"
  out "[Debug] Payload character count: ${#payload}"
  if command -v od >/dev/null 2>&1; then
    local hexTail
    # Use last 64 bytes for better visibility
    hexTail=$(printf '%s' "$payload" | tail -c 64 | od -An -tx1 | tr -s ' ' | sed 's/^ //')
    out "[Debug] Last bytes (hex): $hexTail"
  else
    out "[Debug] od not available; skipping hex dump"
  fi
  out "[Debug] Escaped tail snippet: $(printf '%s' "$payload" | tail -c 64 | sed -E 's/\r/\\r/g; s/\n/\\n/g')"
}

if [[ $FULL_MODE -eq 1 ]]; then
  out "[Mode] FULL output enabled (includes verbose guidance and hidden steps)."
  # Show environment snapshot for additional context
  out "Env Snapshot: WEBSITE_SITE_NAME='${WEBSITE_SITE_NAME:-}' WEBSITE_RESOURCE_GROUP='${WEBSITE_RESOURCE_GROUP:-}'"
fi

APP_NAME="${WEBSITE_SITE_NAME:-}"; RESOURCE_GROUP="${WEBSITE_RESOURCE_GROUP:-}";
log "AppName=$APP_NAME ResourceGroup=$RESOURCE_GROUP"
out "=== Application Insights Diagnostic (Linux) ==="
out "Expanded step list:"
out "  1) Configuration status detection"
out "  2) Connectivity curl command"
out "  3) Telemetry send + validation query"
out "  4) Sampling query + host.json samplingSettings"
out "  5) Worker runtime guidance"
out "============================================="
out "Start (UTC): $SCRIPT_START_UTC"
out "Output directory: $OUTPUT_DIR"

CONN_STRING="${APPLICATIONINSIGHTS_CONNECTION_STRING:-}"; IKEY="${APPINSIGHTS_INSTRUMENTATIONKEY:-}";
CONFIG_STATUS="Missing"
verb "[Step 1] Starting configuration detection"
if [[ -n "$CONN_STRING" && -n "$IKEY" ]]; then CONFIG_STATUS="Both exist (remove APPINSIGHTS_INSTRUMENTATIONKEY, keep APPLICATIONINSIGHTS_CONNECTION_STRING)";
elif [[ -n "$IKEY" ]]; then CONFIG_STATUS="APPINSIGHTS_INSTRUMENTATIONKEY only (migrate)";
elif [[ -n "$CONN_STRING" ]]; then CONFIG_STATUS="OK"; fi
out "Configuration: $CONFIG_STATUS"
case "$CONFIG_STATUS" in
  "OK") verb "Guidance: Using connection string." ;;
  "Both exist*") verb "Guidance: Remove legacy instrumentation key; keep connection string." ;;
  "iKey only*") verb "Guidance: Migrate to connection string for future features & endpoint flexibility." ;;
  "Missing") out "Guidance: Add APPLICATIONINSIGHTS_CONNECTION_STRING (Portal -> Application Insights -> Overview)." ;;
esac

if [[ -z "$CONN_STRING" ]]; then
  out "[ERROR] APPLICATIONINSIGHTS_CONNECTION_STRING missing. Connectivity / telemetry steps skipped.";
  MISSING_CONFIG=1
else
  MISSING_CONFIG=0
fi

# Step 1 complete separator
out "============================================="

# Silent site ping
SITE_STATUS="Skipped"
if [[ $SITE_PING -eq 1 && -n "$APP_NAME" ]]; then
  REL="$SITE_RELATIVE_PATH"; [[ $REL != /* ]] && REL="/$REL"
  FULL_URL="https://${APP_NAME}.azurewebsites.net${REL}"
  HTTP_SITE=$(curl -s -o /dev/null -w '%{http_code}' -L "$FULL_URL" || echo "ERR")
  case "$HTTP_SITE" in
    200|301|302) SITE_STATUS="Reachable";;
    404) SITE_STATUS="Expected404";;
    ERR) SITE_STATUS="Error";;
    *) SITE_STATUS="Status:$HTTP_SITE";;
  esac
  log "SitePing url=$FULL_URL http=$HTTP_SITE classification=$SITE_STATUS"
fi

###############################################
# Step 2: Connectivity curl command
###############################################
CONNECTIVITY_CLASS="Skipped"
INGEST_ENDPOINT=""
EXIT_CODE=0
if [[ $MISSING_CONFIG -eq 0 ]]; then
  verb "[Step 2] Starting connectivity check"
  INGEST_ENDPOINT=$(extract_from_conn "IngestionEndpoint" "$CONN_STRING")
  [[ -n "$INGEST_ENDPOINT" ]] && INGEST_ENDPOINT="${INGEST_ENDPOINT%/}"
  if [[ -z "$INGEST_ENDPOINT" ]]; then
    out "[WARN] IngestionEndpoint not found in connection string."; CONNECTIVITY_CLASS="MissingEndpoint"; EXIT_CODE=3
    verb "[Insight] The connection string should contain IngestionEndpoint=...; regenerate it from the Application Insights resource Overview page if absent."
    verb "[Insight] Verify you copied the Connection String (not just the instrumentation key)."
  else
    TRACK_URL="${INGEST_ENDPOINT}/v2/track"
    out "Connectivity command: curl -I $TRACK_URL"
    HTTP_CONN=$(curl -s -o /dev/null -w '%{http_code}' -I "$TRACK_URL" || echo "ERR")
    case "$HTTP_CONN" in
      200|405) CONNECTIVITY_CLASS="Reachable";;
      404) CONNECTIVITY_CLASS="NotFound(404)"; EXIT_CODE=3;;
      ERR) CONNECTIVITY_CLASS="Error"; EXIT_CODE=3;;
      *) CONNECTIVITY_CLASS="Status:$HTTP_CONN"; EXIT_CODE=3;;
    esac
    out "Connectivity result: HTTP $HTTP_CONN -> $CONNECTIVITY_CLASS"
    log "Connectivity http=$HTTP_CONN classification=$CONNECTIVITY_CLASS"
    if [[ "$CONNECTIVITY_CLASS" != "Reachable" ]]; then
      verb "[Insight] Connectivity issue. Quick checklist:";
      verb "  - Region match: IngestionEndpoint host vs AI resource region";
      verb "  - curl -v $TRACK_URL for DNS/TLS details";
      verb "  - Outbound 443 allowed to *.applicationinsights.azure.com";
      verb "  - Re-copy connection string if stale";
      if [[ "$CONNECTIVITY_CLASS" == NotFound* ]]; then verb "  - 404: usually region mismatch or wrong endpoint"; fi
    fi
  fi
fi

# Step 2 complete separator (connectivity phase)
out "============================================="

###############################################
# Step 3: Telemetry send + validation query
###############################################
EVENT_RESULT="Skipped"
EVENT_NAME=""
if [[ $MISSING_CONFIG -eq 0 && "$CONNECTIVITY_CLASS" == "Reachable" ]]; then
  verb "[Step 3] Sending telemetry payload"
  if [[ -z "$IKEY" ]]; then IKEY=$(extract_from_conn "InstrumentationKey" "$CONN_STRING" || true); fi
  if [[ -n "$IKEY" ]]; then
    EVENT_ID=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)
    EVENT_NAME="curlConnectivityTestEvent-${EVENT_ID}"
    CURRENT_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    if [[ ${AVAILABILITY_MODE:-0} -eq 1 ]]; then
      AVAIL_RUN_ID="SampleRunId"
      AVAIL_NAME="MicrosoftSupportSampleWebtestResultUsingCurl"
      AVAIL_DURATION="00.00:00:10"
      AVAIL_REGION="RegionName"
      TRACK_URL="${INGEST_ENDPOINT}/v2.1/track"
      JSON_PAYLOAD="{\"ver\":1,\"name\":\"Microsoft.ApplicationInsights.Availability\",\"time\":\"$CURRENT_TIME\",\"iKey\":\"$IKEY\",\"data\":{\"baseType\":\"AvailabilityData\",\"baseData\":{\"ver\":2,\"id\":\"$AVAIL_RUN_ID\",\"name\":\"$AVAIL_NAME\",\"duration\":\"$AVAIL_DURATION\",\"success\":true,\"runLocation\":\"$AVAIL_REGION\",\"message\":\"SampleWebtestResult\",\"properties\":{\"SampleProperty\":\"SampleValue\"}}}}"
    else
      JSON_PAYLOAD="{\"ver\":1,\"name\":\"Microsoft.ApplicationInsights.Event\",\"time\":\"$CURRENT_TIME\",\"iKey\":\"$IKEY\",\"data\":{\"baseType\":\"EventData\",\"baseData\":{\"ver\":2,\"name\":\"$EVENT_NAME\",\"properties\":{\"Source\":\"ConnectivityCheckScript\",\"App\":\"$APP_NAME\",\"EventId\":\"$EVENT_ID\"}}}}"
      TRACK_URL="${INGEST_ENDPOINT}/v2/track"
    fi
    # Default now shows payload inline unless explicitly hidden
    if [[ $HIDE_PAYLOAD -eq 1 ]]; then
      out "Telemetry command: curl -v -X POST $TRACK_URL -H 'Content-Type: application/json' -d '[REDACTED_OBJECT]'"
      verb "(Use --emit-payload or omit --hide-payload to view raw JSON)"
    else
      # If user forced emit or default inline, print the actual JSON
  out "Telemetry command: curl -v -X POST $TRACK_URL -H 'Content-Type: application/json' -d '$(echo "$JSON_PAYLOAD" | sed "s/'/\\'/g")'"
  if [[ ${AVAILABILITY_MODE:-0} -eq 1 ]]; then verb "[Mode] AvailabilityData (--availability) using endpoint /v2.1/track"; fi
    fi
  # Validate before sending; if invalid we still attempt send but mark failure pre-emptively.
  PAYLOAD_VALID=1
  if ! validate_payload "$JSON_PAYLOAD"; then PAYLOAD_VALID=0; fi
  RAW=$(curl -s -w 'HTTPSTATUS:%{http_code}' -H 'Content-Type: application/json' -X POST "$TRACK_URL" -d "$JSON_PAYLOAD") || true
    HTTP_TELEM=${RAW##*HTTPSTATUS:}
    BODY_TELEM=${RAW%HTTPSTATUS:*}
  # Safe extraction: avoid pipefail-induced exit when patterns absent
  RECEIVED=$( { echo "$BODY_TELEM" | grep -o '"itemsReceived"[[:space:]]*:[[:space:]]*[0-9]*' | cut -d: -f2 | tr -d ' ' ; } || true )
  ACCEPTED=$( { echo "$BODY_TELEM" | grep -o '"itemsAccepted"[[:space:]]*:[[:space:]]*[0-9]*' | cut -d: -f2 | tr -d ' ' ; } || true )
  ERROR_MSG=$( { echo "$BODY_TELEM" | grep -o '"message":"[^"]*"' | head -1 | sed 's/"message":"\([^"]*\)"/\1/' ; } || true )
  # Count errors (number of 'index' fields in errors array)
  ERRORS_COUNT=$( { echo "$BODY_TELEM" | grep -o '"index"' | wc -l | tr -d ' ' ; } || true )
    if [[ $PAYLOAD_VALID -eq 0 ]]; then
      verb "[Validator] Proceeded with send despite validation errors (telemetry result may be partial)."
    fi
    if [[ "$HTTP_TELEM" == "200" ]]; then
      out "Telemetry send result: HTTP $HTTP_TELEM itemsReceived=${RECEIVED:-?} itemsAccepted=${ACCEPTED:-?} errors=0"
      EVENT_RESULT="HTTP $HTTP_TELEM Rec:${RECEIVED:-?} Acc:${ACCEPTED:-?} Err:0"
    elif [[ "$HTTP_TELEM" == "206" ]]; then
      # Partial success. Treat as success if at least one item accepted.
      if [[ -n "$ACCEPTED" && "$ACCEPTED" -gt 0 ]]; then
        out "Telemetry send result: HTTP 206 (Partial Success) itemsReceived=${RECEIVED:-?} itemsAccepted=${ACCEPTED:-0} errors=${ERRORS_COUNT}";
        # Guidance for common single-item payload anomaly producing a phantom second invalid item
        if [[ "$RECEIVED" == "2" && "$ACCEPTED" == "1" && "$ERROR_MSG" == *"Invalid JSON"* ]]; then
          verb "[Guidance] You likely have a trailing newline or stray character causing ingestion to attempt a second envelope. Ensure payload is a single JSON object (no extra blank lines or partial second object). Use: curl -H 'Content-Type: application/json' --data-raw '<payload>' ... (avoid echo adding newline)."
        fi
        EVENT_RESULT="HTTP 206 Rec:${RECEIVED:-?} Acc:${ACCEPTED:-0} Err:${ERRORS_COUNT} (Partial)"
        # Do not mark telemetry failure when at least one accepted.
      else
        out "Telemetry send result: HTTP 206 but zero items accepted raw body: $BODY_TELEM"
        EVENT_RESULT="HTTP206 NoneAccepted"
        [[ $EXIT_CODE -eq 0 ]] && EXIT_CODE=4
      fi
    else
      out "Telemetry send result: HTTP $HTTP_TELEM raw body: $BODY_TELEM"
      EVENT_RESULT="HTTP:$HTTP_TELEM Raw"
      [[ $EXIT_CODE -eq 0 ]] && EXIT_CODE=4
    fi
    log "Telemetry http=$HTTP_TELEM bodyLen=${#BODY_TELEM}"
  else
    out "[WARN] Instrumentation key not found; telemetry skipped."; EVENT_RESULT="Missing iKey"; [[ $EXIT_CODE -eq 0 ]] && EXIT_CODE=4
  fi
fi

# Step 3 complete separator (telemetry phase)
out "============================================="

###############################################
# Step 4: Sampling query + host.json samplingSettings (with runtime override)
###############################################
# Runtime override detection using LINUX_FX_VERSION (linux functions runtime string)
verb "[Step 4] Evaluating sampling + host.json"
RUNTIME_VALUE="${LINUX_FX_VERSION:-}"  # Example patterns: DOTNET-ISOLATED|8.0, JAVA|17, JAVA|11, DOTNET|8.0
RUNTIME_OVERRIDE=0
if [[ -n "$RUNTIME_VALUE" ]]; then
  rt_lower=$(echo "$RUNTIME_VALUE" | tr '[:upper:]' '[:lower:]')
  if echo "$rt_lower" | grep -q 'java'; then RUNTIME_OVERRIDE=1; fi
  if echo "$rt_lower" | grep -q 'dotnet-isolated'; then RUNTIME_OVERRIDE=1; fi
fi
if [[ $RUNTIME_OVERRIDE -eq 1 ]]; then
  out "[Runtime] LINUX_FX_VERSION='$RUNTIME_VALUE' indicates code-managed telemetry & sampling (host.json samplingSettings not applicable)."
  out "Reference: https://learn.microsoft.com/en-us/troubleshoot/azure/azure-functions/monitoring/functions-monitoring-appinsightslogs#custom-application-logs"
fi
SAMPLING_FLAG="NotFound"
HOST_JSON_PARSE_ERROR=""

# Construct candidate list (override first if provided)
declare -a HOST_JSON_CANDIDATES
if [[ -n "$HOST_JSON_OVERRIDE" ]]; then HOST_JSON_CANDIDATES+=("$HOST_JSON_OVERRIDE"); fi
HOST_JSON_CANDIDATES+=(
  "/home/site/wwwroot/host.json" 
)

FOUND_HOST_JSON=""
for c in "${HOST_JSON_CANDIDATES[@]}"; do
  log "[Sampling] candidate=$c"
  if [[ -f "$c" ]]; then FOUND_HOST_JSON="$c"; break; fi
done

if [[ -z "$FOUND_HOST_JSON" && -z "$HOST_JSON_OVERRIDE" ]]; then
  if command -v find >/dev/null 2>&1; then
    log "[Sampling] breadth search /home/site (maxdepth 3)"
    FOUND_HOST_JSON=$(find /home/site -maxdepth 3 -type f -name host.json 2>/dev/null | head -1 || true)
  fi
fi

if [[ $RUNTIME_OVERRIDE -eq 1 ]]; then
  # Skip host.json parsing entirely for code-managed runtimes
  SAMPLING_FLAG="CodeManaged"
  out "Sampling host.json path: (skipped for runtime override)"
else
  if [[ -n "$FOUND_HOST_JSON" ]]; then
  HOST_JSON="$FOUND_HOST_JSON"
  out "Sampling host.json path: $HOST_JSON"
  SIZE=$(stat -c %s "$HOST_JSON" 2>/dev/null || echo 0)
  PREVIEW=$(head -c 200 "$HOST_JSON" | tr '\n' ' ' | tr '\r' ' ')
  if command -v sha256sum >/dev/null 2>&1; then HASH=$(sha256sum "$HOST_JSON" | awk '{print $1}'); else HASH="(sha256 unavailable)"; fi
  log "[Sampling] host.json size=${SIZE}B sha256=${HASH} head200='${PREVIEW}'"
  if command -v jq >/dev/null 2>&1; then
    PARSE_OUT=$(jq -r '.logging.applicationInsights.samplingSettings.isEnabled // "__MISSING__"' "$HOST_JSON" 2>&1) || true
    if echo "$PARSE_OUT" | grep -q '^parse error'; then
      SAMPLING_FLAG="ParseFailed"; HOST_JSON_PARSE_ERROR="$PARSE_OUT"; [[ $EXIT_CODE -eq 0 ]] && EXIT_CODE=5
    else
      case "$PARSE_OUT" in
        true|false) SAMPLING_FLAG="$PARSE_OUT";;
        __MISSING__) SAMPLING_FLAG="NotFound";;
        *) SAMPLING_FLAG="ParseFailed"; HOST_JSON_PARSE_ERROR="Unexpected jq output: $PARSE_OUT"; [[ $EXIT_CODE -eq 0 ]] && EXIT_CODE=5;;
      esac
    fi
  else
    LINE=$(grep -i 'samplingSettings' -A5 "$HOST_JSON" | grep -i 'isEnabled' | head -1 || true)
    if echo "$LINE" | grep -qi 'false'; then SAMPLING_FLAG="false";
    elif echo "$LINE" | grep -qi 'true'; then SAMPLING_FLAG="true";
    elif [[ -n "$LINE" ]]; then SAMPLING_FLAG="ParseFailed"; HOST_JSON_PARSE_ERROR="Could not parse boolean from line: $LINE"; [[ $EXIT_CODE -eq 0 ]] && EXIT_CODE=5; fi
  fi
  else
    out "Sampling host.json path: (not found)"
    SAMPLING_FLAG="NotFound"
  fi
fi

out "SamplingFlag: $SAMPLING_FLAG"
if [[ "$SAMPLING_FLAG" == "ParseFailed" ]]; then
  out "[Info] host.json parse failed. See log: $LOG_PATH"
  verb "host.json parse failure detail: $HOST_JSON_PARSE_ERROR"
elif [[ "$SAMPLING_FLAG" == "false" ]]; then
  verb "[Info] Sampling disabled -> retention full; skipping retention impact guidance."
elif [[ "$SAMPLING_FLAG" == "true" ]]; then
  out "[Action] Sampling enabled. Use retention query below to measure retained vs original volume."
elif [[ "$SAMPLING_FLAG" == "CodeManaged" ]]; then
  out "[Info] Runtime override: sampling & logging configured in code. Host.json snippet suppressed."
else
  # Treat NotFound (unspecified) as assumed enabled per user request
  if [[ "$SAMPLING_FLAG" == "NotFound" ]]; then
    SAMPLING_FLAG="NotFound(AssumedEnabled)"
    out "[Info] samplingSettings.isEnabled not present; assuming platform default sampling is ENABLED. Use retention query to confirm (RetainedPercentage <100 indicates reduction)."
  else
    out "[Info] Sampling status unknown (host.json missing or samplingSettings.isEnabled not specified); showing query for manual inspection."
  fi
fi

# Step 4 complete separator (sampling evaluation)
out "============================================="

# Decide HTML report name if omitted
if [[ -z "$HTML_REPORT" ]]; then HTML_REPORT="AI-Diagnostic-Report-$(date -u +"%Y%m%d-%H%M%S").html"; fi
verb "[Step 5] Generating HTML report and runtime guidance section"
REPORT_PATH="$OUTPUT_DIR/$HTML_REPORT"

# Prepare additional report context variables
REPORT_EVENT_NAME="$EVENT_NAME"
REPORT_INGEST_ENDPOINT="$INGEST_ENDPOINT"
if [[ $CONNECTIVITY_CLASS == "Reachable" && -n "$REPORT_INGEST_ENDPOINT" ]]; then
  if [[ ${AVAILABILITY_MODE:-0} -eq 1 ]]; then
    REPORT_TRACK_URL="${REPORT_INGEST_ENDPOINT}/v2.1/track"
  else
    REPORT_TRACK_URL="${REPORT_INGEST_ENDPOINT}/v2/track"
  fi
else
  REPORT_TRACK_URL="(not established)"
fi
if [[ ${HIDE_PAYLOAD:-0} -eq 1 ]]; then
  HTML_TELEM_PAYLOAD="[REDACTED_OBJECT]"
else
  HTML_TELEM_PAYLOAD="${JSON_PAYLOAD:-'(not generated)'}"
fi

# Redaction
if [[ $REDACT -eq 1 ]]; then
  if [[ -n "$CONN_STRING" ]]; then sed -i "s#${CONN_STRING}#[REDACTED_CONNECTION_STRING]#g" "$LOG_PATH" || true; fi
  if [[ -n "$IKEY" ]]; then sed -i "s#${IKEY}#[REDACTED_IKEY]#g" "$LOG_PATH" || true; fi
fi

RETENTION_QUERY="union requests, dependencies, pageViews, browserTimings, exceptions, traces | where timestamp > ago(24h) | summarize RetainedPercentage = 100/avg(coalesce(itemCount,1)) by bin(timestamp,1h), itemType"
if [[ ${AVAILABILITY_MODE:-0} -eq 1 ]]; then
  VALIDATION_QUERY="availabilityResults | where timestamp > ago(1h) | where name == 'MicrosoftSupportSampleWebtestResultUsingCurl' or id == 'SampleRunId' | project timestamp,name,id,success,runLocation,message"
else
  VALIDATION_QUERY="customEvents | where timestamp > ago(1h) | where name == '$EVENT_NAME' | project timestamp,name,customDimensions | order by timestamp desc"
fi

tail_sanitized() { tail -n 50 "$LOG_PATH" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }

DISABLE_SNIPPET='<h3>Disable Sampling Snippet</h3>\n    <pre><code class="json">{\n  "logging": {\n    "applicationInsights": {\n      "samplingSettings": {\n        "isEnabled": false\n      }\n    }\n  }\n}</code></pre>'
SAMPLING_EXTRA_MSG=""

cat > "$REPORT_PATH" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Application Insights Diagnostic Report (Linux)</title>
  <style>
    body { font-family: Arial, Helvetica, sans-serif; margin: 1.5rem; line-height:1.4; }
    h1 { border-bottom: 2px solid #444; padding-bottom: .3rem; }
    table { border-collapse: collapse; margin-top: .5rem; }
    th, td { border:1px solid #ccc; padding:4px 8px; text-align:left; }
    th { background:#f2f2f2; }
    code, pre { font-family: Consolas, Menlo, monospace; font-size: .9rem; }
    pre { background:#f8f8f8; padding:8px; border:1px solid #ddd; overflow:auto; }
    .section { margin-top:1.2rem; }
    .callout { border-left:6px solid #0b74de; background:#eef6ff; padding:12px 14px; box-shadow:0 0 4px rgba(0,0,0,0.08); }
    .callout h2 { margin-top:0; }
  </style>
</head>
<body>
  <h1>Application Insights Diagnostic Report (Linux)</h1>
  <p><strong>Generated (UTC):</strong> $SCRIPT_START_UTC</p>
  <div class="section">
  <h2>Step 1: Configuration Summary</h2>
    <table>
      <tr><th>Category</th><th>Status</th></tr>
      <tr><td>Configuration</td><td>$CONFIG_STATUS</td></tr>
      <tr><td>Connectivity</td><td>$CONNECTIVITY_CLASS</td></tr>
      <tr><td>Telemetry</td><td>$EVENT_RESULT</td></tr>
  <tr><td>SamplingFlag</td><td>$( [[ "$SAMPLING_FLAG" == "CodeManaged" ]] && echo "CodeManaged (not via host.json)" || echo "$SAMPLING_FLAG" )</td></tr>
  <tr><td>Runtime</td><td>$( [[ $RUNTIME_OVERRIDE -eq 1 ]] && echo "${RUNTIME_VALUE:-'(unset)'} CodeManaged (not via host.json)" || echo "${RUNTIME_VALUE:-'(unset)'}" )</td></tr>
    </table>
    <p><strong>Guidance:</strong> $( [[ "$CONFIG_STATUS" == "OK" ]] && echo "Connection string detected." || echo "If legacy instrumentation key present, migrate to connection string." )</p>
  </div>
  <div class="section">
    <h2>Step 2: Connectivity</h2>
    <p>Status: <strong>$CONNECTIVITY_CLASS</strong></p>
    <p>Ingestion Endpoint: <code>${REPORT_INGEST_ENDPOINT:-'(unset)'}</code></p>
    <p>Track URL: <code>${REPORT_TRACK_URL}</code></p>
    $( [[ $CONNECTIVITY_CLASS == "Reachable" ]] && echo "<p>Reachable: HTTP 200/405 indicates endpoint responsive.</p>" || echo "<p>Non-reachable or error: verify networking, firewall, or connection string correctness.</p>" )
  </div>
  <div class="section">
  <h2>Step 3: Telemetry Send & Validation</h2>
  <p>Event Name: <code>${REPORT_EVENT_NAME:-'(none)'}$( [[ ${AVAILABILITY_MODE:-0} -eq 1 ]] && echo " (AvailabilityData)" )</code></p>
  <p>Payload (inline): <code>${HTML_TELEM_PAYLOAD}</code></p>
  <pre><code class='kusto'>$VALIDATION_QUERY</code></pre>
  </div>
  <div class="section">
  <h2>Step 4: Sampling</h2>
  <p>Sampling flag: $( [[ "$SAMPLING_FLAG" == "CodeManaged" ]] && echo "CodeManaged (not via host.json)" || echo "$SAMPLING_FLAG" )</p>
    <h3>Retention query (24h window)</h3>
    <pre><code class='kusto'>$RETENTION_QUERY</code></pre>
    <p><em>Interpretation:</em> RetainedPercentage ~100 =&gt; none/zero sampling; &lt;100 =&gt; sampling active; fluctuating =&gt; adaptive sampling.</p>
    $( [[ "$SAMPLING_FLAG" == "CodeManaged" ]] && echo "<p><strong>Runtime override:</strong> Configure sampling & logging in application code for this worker runtime. See <a href=\"https://learn.microsoft.com/en-us/troubleshoot/azure/azure-functions/monitoring/functions-monitoring-appinsightslogs#custom-application-logs\" target=\"_blank\">guidance</a>.</p>" || echo "$DISABLE_SNIPPET" )
  </div>
  <div class="section">
  <h2>Step 5: Worker Runtime Guidance</h2>
    <p>LINUX_FX_VERSION: ${RUNTIME_VALUE:-'(unset)'}</p>
    $( if [[ $RUNTIME_OVERRIDE -eq 1 ]]; then cat <<'RHTML'
<p><strong>Guidance:</strong> For this runtime, sampling & custom logs are configured in application code; host.json samplingSettings is ignored.</p>
<h3>.NET isolated example: disable adaptive sampling</h3>
<pre><code class='csharp'>// Program.cs (.NET isolated)
builder.Services.AddApplicationInsightsTelemetryWorkerService(options => {
    options.EnableAdaptiveSampling = false; // disables adaptive sampling
});
// Additional telemetry processors / initializers can be added via DI.
</code></pre>
<h3>Java example: remove sampling processor</h3>
<pre><code class='java'>TelemetryConfiguration config = TelemetryConfiguration.getActive();
config.getTelemetryProcessors()
      .removeIf(p -> p.getClass().getSimpleName().equals("AdaptiveSamplingTelemetryProcessor"));
// Spring Boot starter alternative:
// azure.application-insights.enable-adaptive-sampling=false
</code></pre>
<p>After disabling, RetainedPercentage in the retention query should remain ~100 indicating full retention.</p>
<p>Reference: <a href="https://learn.microsoft.com/en-us/troubleshoot/azure/azure-functions/monitoring/functions-monitoring-appinsightslogs#custom-application-logs" target="_blank">Custom application logs guidance</a>.</p>
RHTML
else cat <<'RHTML'
<p>Host.json samplingSettings apply for this runtime. To disable sampling add:</p>
<pre><code class='json'>{
  "logging": {
    "applicationInsights": {
      "samplingSettings": {
        "isEnabled": false
      }
    }
  }
}</code></pre>
<p>Restart the Function App after editing host.json then confirm RetainedPercentage ~100 (no sampling).</p>
RHTML
fi )
  </div>
  <div class="section">
  <h2>Auxiliary: Redacted Log (tail)</h2>
    <pre><code class='text'>$(tail_sanitized)</code></pre>
  </div>
  <div class="section">
  <h2>Auxiliary: Silent Site GET</h2>
    <p>Classification: $SITE_STATUS (path: $SITE_RELATIVE_PATH)</p>
  </div>
  <div class="section callout">
  <h2>Next Steps: Portal Detectors</h2>
    <ol>
      <li><strong>Azure Portal</strong> → Open your Function App.</li>
      <li>Go to <strong>Diagnose and solve problems</strong>.</li>
      <li>Run <strong>Function App Missing Telemetry in Application Insights</strong> detector.</li>
      <li>(Optional) Run <strong>Open Telemetry</strong> detector if you rely on OpenTelemetry exporters.</li>
    </ol>
    <p><em>Why:</em> These detectors highlight platform-side issues (ingestion latency, quotas, sampling impact, outages, extension/SDK misconfiguration) and provide guided remediation.</p>
  </div>
  <hr />
  <p>Exit Codes: 0=Success 2=MissingConfig 3=ConnectivityFail 4=TelemetryFail 5=SamplingParseFail</p>
</body>
</html>
EOF

out "[Info] HTML report saved: $REPORT_PATH"
out "[Info] Detailed log saved: $LOG_PATH"

# Step 5 complete separator (report generation)
out "============================================="

cat <<'NEXT'
================ NEXT STEPS (Linux) ================
Portal: Function App -> Diagnose and solve problems -> Run "Function App Missing Telemetry" detector.
If still missing telemetry: open Azure Support and attach HTML report + redacted log.
===================================================
NEXT

# Determine final exit code if config missing earlier
if [[ $MISSING_CONFIG -eq 1 ]]; then EXIT_CODE=2; fi
###############################################
# Summary box (terminal)
###############################################
if [[ "$SAMPLING_FLAG" == "CodeManaged" ]]; then
  SUMMARY_SAMPLING="CodeManaged (not via host.json)"
else
  SUMMARY_SAMPLING="$SAMPLING_FLAG"
fi
# Show full LINUX_FX_VERSION (including version) in summary instead of normalized language token
if [[ $RUNTIME_OVERRIDE -eq 1 ]]; then
  SUMMARY_RUNTIME="${RUNTIME_VALUE:-'(unset)'} CodeManaged (not via host.json)"
else
  SUMMARY_RUNTIME="${RUNTIME_VALUE:-'(unset)'}"
fi
SUM_LINES=(
  "Configuration : $CONFIG_STATUS"
  "Connectivity  : $CONNECTIVITY_CLASS"
  "Telemetry     : $EVENT_RESULT"
  "SamplingFlag  : $SUMMARY_SAMPLING"
  "Runtime       : $SUMMARY_RUNTIME"
)
maxlen=0
for l in "${SUM_LINES[@]}"; do [[ ${#l} -gt $maxlen ]] && maxlen=${#l}; done
border="+$(printf '%*s' $((maxlen+2)) '' | tr ' ' '-')+"
out "Summary (brief):"
echo "$border"
for l in "${SUM_LINES[@]}"; do printf "| %s%*s |\n" "$l" $((maxlen-${#l})) ""; done
echo "$border"
out "[Info] Detailed log saved: $LOG_PATH"
out "[Info] Run with -v for expanded diagnostic details."

exit $EXIT_CODE
