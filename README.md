# Application Insights Diagnostics (Preview)

Minimal diagnostic script to validate **Application Insights telemetry** for **Azure Functions** or **App Service**.

> ✅ **Supported Hosting Plans:**
>
> * Windows & Linux Dedicated
> * Windows & Linux Elastic Premium
> * Windows Consumption

 ⚠️ **Not supported:** Linux Consumption or Flex Consumption (Kudu/console not available).

---

## Overview

This tool provides quick validation of Application Insights configuration and telemetry flow for your Function App or App Service.

### Key Capabilities

* ✅ Config check (connection string vs legacy iKey)
* ✅ Ingestion endpoint reachability (curl)
* ✅ Minimal telemetry send + validation query
* ✅ Sampling status from `host.json` or from language worker (`CodeManaged` for java / dotnet-isolated)
* ✅ Retention Kusto query (hourly `RetainedPercentage`) for sampling impact
* ✅ Worker runtime guidance
* ✅ HTML report + redacted log + annotated summary 
* ✅ Portal detector guidance .

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

<details>
<summary>Sampling Detection Details</summary>

| Condition                                 | SamplingFlag             | Interpretation                |
| ----------------------------------------- | ------------------------ | ----------------------------- |
| Missing `samplingSettings` or `isEnabled` | `ImplicitDefaultEnabled` | Sampling active by default    |
| `"isEnabled": true`                       | `True`                   | Sampling explicitly enabled   |
| `"isEnabled": false`                      | `False`                  | Sampling disabled             |
| Parse error                               | `ParseFailed`            | Invalid JSON                  |
| File missing                              | `NotFound`               | Treated as enabled by default |

**Kusto Retention Query**

```kusto
union requests, dependencies, pageViews, browserTimings, exceptions, traces
| where timestamp > ago(24h)
| summarize RetainedPercentage = 100/avg(coalesce(itemCount,1)) by bin(timestamp,1h), itemType
```

**Interpretation:**

* ≈100 → Full retention, no sampling
* <100 → Sampling active (reduced telemetry)
* Fluctuating 90–99 → Adaptive sampling

**To disable sampling explicitly**, add to `host.json`:

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

</details>

---

<details>
<summary>Kusto Snippets</summary>

**Event validation**

```kusto
customEvents
| where timestamp > ago(1h)
| where name == 'curlConnectivityTestEvent-<GUID>'
```

**Sampling retention**

```kusto
union requests, dependencies, pageViews, browserTimings, exceptions, traces
| where timestamp > ago(24h)
| summarize RetainedPercentage = 100/avg(coalesce(itemCount,1)) by bin(timestamp,1h), itemType
```

</details>

---

## Portal Detector

**Azure Portal → Function App → Diagnose and solve problems →**
Run **Function App Missing Telemetry in Application Insights / OpenTelemetry** detector.

---

## Security and Privacy

* 🔒 Connection strings and instrumentation keys are **redacted** in logs
* 🔒 Script performs a **silent GET** to `/AppInsightsDiag` for basic reachability only

  * Expected response: **404 (Expected404)**
  * No secret data or response body is stored
  * Does **not** affect telemetry or leak sensitive info

---

## Support & Escalation

If issues persist after running the script and portal detector:

* Open **Azure Support** request
* Attach:

  * ✅ Generated **HTML report** (`Application Insights Diagnostic` folder or custom path)
  * ✅ Redacted log file

These artifacts help accelerate triage and resolution.
