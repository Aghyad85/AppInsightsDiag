# AppInsightsDiag.ps1 (Application Insights Diagnostics)

Minimal script to validate Application Insights telemetry for Azure Functions / App Service.

## What It Does
1. Checks config (connection string vs legacy iKey)
2. Tests ingestion endpoint reachability
3. Sends a small custom event
4. Detects sampling settings from host.json
5. Generates HTML report + redacted log
6. Points to portal detectors


## Run From Kudu (Azure App Service / Functions)
1. Download `AppInsightsDiag.ps1` locally.
2. Open: `https://<sitename>.scm.azurewebsites.net/DebugConsole/?shell=powershell`
3. Drag & drop `AppInsightsDiag.ps1` into the Kudu file pane (e.g. `/site/wwwroot`).
4. In the Kudu PowerShell console, execute:
	```powershell
	./AppInsightsDiag.ps1
	```
5. Locate the new `Application Insights Diagnostic` folder, download the HTML report.


## Troubleshooting (Quick)

| Issue | Hint |
|-------|------|
| 404 connectivity | Wrong ingestion endpoint region. |
| Telemetry HTTP 400 | Bad JSON or old iKey usage. |
| Sampling ParseFailed | Invalid host.json. |
| Missing config | Add APPLICATIONINSIGHTS_CONNECTION_STRING. |


## Status Cheat Sheet

* Configuration: OK | Both exist | `iKey` only | Missing
* Connectivity: Reachable | `NotFound` (404) | Status:{CODE} | Error
* Telemetry: HTTP 200 Rec:1 Acc:1 Err:0 = success (else inspect body)
* `SamplingFlag`: True | False | `NotFound` | `ParseFailed`

## Kusto Snippets

Event validation:

```
customEvents | where timestamp > ago(1h) | where name == 'curlConnectivityTestEvent-<GUID>'
```

Sampling retention:

```
union requests, dependencies, pageViews, browserTimings, exceptions, traces
| where timestamp > ago(24h)
| summarize RetainedPercentage = 100/avg(coalesce(itemCount,1)) by bin(timestamp,1h), itemType
```

## Common Options
```powershell
./AppInsightsDiag.ps1 -VerboseMode
./AppInsightsDiag.ps1 -HtmlReportPath C:\temp\ai-report.html
./AppInsightsDiag.ps1 -HostJsonPath C:\home\site\wwwroot\host.json
```

## Portal Detector

Portal → Function App → Diagnose and solve problems → Run **Function App Missing Telemetry in Application Insights** (optional **Open Telemetry**).

## Security
Instrumentation Key & Connection String redacted in log.



