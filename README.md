# Application Insights Diagnostics (Preview)

Minimal diagnostic script to validate **Application Insights telemetry** for **Azure Functions** or **App Service**.

> ✅ **Supported Hosting Plans:**
>
> * Windows & Linux Dedicated
> * Windows & Linux Elastic Premium
> * Windows Consumption

 ⚠️ **Not supported:** Linux Consumption or Flex Consumption (no console shell available).

---

## Overview

This tool provides quick validation of Application Insights configuration and telemetry flow for your Function App or App Service.

### Key Capabilities

* ✅ Config check (connection string vs legacy iKey)
* ✅ Ingestion endpoint reachability (curl HEAD)
* ✅ Minimal telemetry send + validation query (EventData; `--availability` flag for AvailabilityData on Linux)
* ✅ Sampling status from host.json or runtime override (`CodeManaged` for java / dotnet-isolated)
* ✅ Retention Kusto query (hourly `RetainedPercentage`) to measure sampling impact
* ✅ Silent site GET classification (Expected404 vs other)
* ✅ Worker runtime guidance (host.json vs code-managed sampling)
* ✅ HTML report + redacted log + annotated summary (SamplingFlag / Runtime)
* ✅ Structured exit codes (0/2/3/4/5)
* ✅ Portal detector guidance (Missing Telemetry / OpenTelemetry)

---

## Running from Kudu Console

### 🪟 Windows (PowerShell Console)

1. Download `AppInsightsDiag.ps1` locally
2. Navigate to:
  `https://<sitename>.scm.azurewebsites.net/DebugConsole/?shell=powershell`
3. Upload the script (e.g., to `/site/wwwroot`)
4. Run in PowerShell console:

   ```powershell
   ./AppInsightsDiag.ps1
   ```
5. A new folder **Application Insights Diagnostic** is created. Download the **HTML report** from there.

---

### 🐧 Linux (Bash Console – Dedicated / Elastic Premium only)

1. Download `appinsights_diag.sh` locally
2. Navigate to:
   `https://<sitename>.scm.azurewebsites.net/newui/fileManager`
3. Upload the script to the `home` directory
4. Open **SSH → SSH to Kudu**
5. Run the script (verbose by default):

   ```bash
   ./appinsights_diag.sh
   ```
After execution, download the HTML report and log from the **Application Insights Diagnostic** directory.

> ⚠️ Not supported on **Linux Consumption** or **Flex Consumption** — Kudu shell not available.

#### Linux Flags Summary

| Flag | Purpose |
|------|---------|
| *(default)* | Verbose output |
| `--quiet` / `-q` | Minimal output |
| `--full` / `-F` | Env snapshot & extended guidance |
| `--availability` | Send AvailabilityData envelope via `/v2.1/track` |
| `--emit-payload` | Print raw telemetry JSON inline |
| `--hide-payload` | Force redaction of telemetry JSON |
| `--host-json <file>` | Explicit host.json path override |
| `--output-dir <dir>` | Custom output directory |
| `--report <file>` | Custom HTML report path/name |
| `--site-path <rel>` | Path for silent GET (default `/AppInsightsDiag`) |
| `--disable-site-ping` | Skip silent reachability GET |
| `--no-redact` | Do not redact secrets in log |

Exit Codes: 0=Success · 2=MissingConfig · 3=ConnectivityFail · 4=TelemetryFail · 5=SamplingParseFail

---

## Troubleshooting Quick Reference

| Issue                       | Possible Cause                                  |
| --------------------------- | ----------------------------------------------- |
| ⚠️ **404 connectivity**     | Incorrect ingestion endpoint region             |
| ❌ **Telemetry HTTP 400**    | Malformed payload or legacy iKey usage          |
| ⚠️ **Sampling ParseFailed** | Invalid or malformed `host.json`                |
| ⚠️ **Missing config**       | Missing `APPLICATIONINSIGHTS_CONNECTION_STRING` |

---

## Status Indicators

| Category            | Possible Values                                                |
| ------------------- | -------------------------------------------------------------- |
| ✅ **Configuration** | OK · Both exist · iKey only · Missing                          |
| ✅ **Connectivity**  | Reachable · NotFound (404) · Status:{CODE} · Error             |
| ✅ **Telemetry**     | HTTP 200 Rec:1 Acc:1 Err:0 → success                           |
| ⚠️ **SamplingFlag** | True · False · NotFound · ParseFailed · ImplicitDefaultEnabled |

> ⚠️ `ImplicitDefaultEnabled` indicates that `samplingSettings.isEnabled` was **not explicitly set** in `host.json`. Sampling is enabled by default when missing.
> `CodeManaged` indicates runtime (java / dotnet-isolated) handles sampling/logging in code (host.json ignored).
> `NotFound(AssumedEnabled)` may appear when host.json missing; sampling assumed enabled by platform defaults.

### Sampling Detection Details

| Condition                                 | SamplingFlag             | Interpretation                |
| ----------------------------------------- | ------------------------ | ----------------------------- |
| Missing `samplingSettings` or `isEnabled` | `ImplicitDefaultEnabled` | Sampling active by default    |
| `"isEnabled": true`                       | `True`                   | Sampling explicitly enabled   |
| `"isEnabled": false`                      | `False`                  | Sampling disabled             |
| Parse error                               | `ParseFailed`            | Invalid JSON                  |
| File missing                              | `NotFound` / `NotFound(AssumedEnabled)` | Treated as enabled by default |

#### Retention Query (24h window)

```kusto
union requests, dependencies, pageViews, browserTimings, exceptions, traces
| where timestamp > ago(24h)
| summarize RetainedPercentage = 100/avg(coalesce(itemCount,1)) by bin(timestamp,1h), itemType
```

#### Interpretation

* ~100 → Full retention (no sampling)
* <100 → Sampling active (reduced telemetry)
* 90–99 fluctuating → Adaptive sampling

#### Disable sampling (host.json)

```json
{
  "logging": {
    "applicationInsights": {
      "samplingSettings": {
        "isEnabled": false
      }
    }
  }
}
```


---

### Kusto Snippets

#### Event validation

```kusto
customEvents
| where timestamp > ago(1h)
| where name == 'curlConnectivityTestEvent-<GUID>'
```

#### Sampling retention (same query)

```kusto
union requests, dependencies, pageViews, browserTimings, exceptions, traces
| where timestamp > ago(24h)
| summarize RetainedPercentage = 100/avg(coalesce(itemCount,1)) by bin(timestamp,1h), itemType
```


---

## Portal Detector

**Azure Portal → Function App → Diagnose and solve problems →**
Run **Function App Missing Telemetry in Application Insights / OpenTelemetry** detector.

---

## Security and Privacy

* 🔒 Connection strings and instrumentation keys are **redacted** in logs & HTML
* 🔒 Script performs a silent GET to `/AppInsightsDiag` for basic reachability only

  * Expected response: **404 (Expected404)**
  * No secret data or response body is stored
  * Does **not** affect telemetry or leak sensitive info

---

## Support & Escalation

If issues persist after running the script and portal detector:

* Open **Azure Support** request
* Attach:

  * ✅ Generated HTML report (`Application Insights Diagnostic` folder or custom path)
  * ✅ Redacted log file

These artifacts help accelerate triage and resolution.
