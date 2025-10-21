# AppInsightsDiag.ps1 (Application Insights Diagnostics)

Minimal script to validate Application Insights telemetry for Azure Functions / App Service.

> Hosting plan support: Works on Windows & Linux Dedicated, Premium, and Elastic Premium plans, plus Windows Consumption. Not supported on **Linux Consumption** or **Flex Consumption** plans (Kudu / required console features unavailable there).

## What It Does
1. Checks config (connection string vs legacy iKey)
2. Tests ingestion endpoint reachability
3. Sends a small custom event
4. Detects sampling settings from host.json
5. Generates HTML report + redacted log
6. Points to portal detectors


## Run From Kudu (Azure App Service / Functions)

### Windows (PowerShell Console)
1. Download `AppInsightsDiag.ps1` locally.
2. Open: `https://<sitename>.scm.azurewebsites.net/DebugConsole/?shell=powershell`
3. Drag & drop `AppInsightsDiag.ps1` into the Kudu file pane (e.g. `/site/wwwroot`).
4. In the Kudu PowerShell console, execute:

	```powershell
	./AppInsightsDiag.ps1
	```
5. Locate the new `Application Insights Diagnostic` folder, download the HTML report.

### Linux (Bash Console — Dedicated / Premium / Elastic Premium only)
1. Download `appinsights_diag.sh` locally.
2. Open: `https://<sitename>.scm.azurewebsites.net/newui/fileManager` 
3. Drag & drop `appinsights_diag.sh` into `home`.
4. go to SSH then chose SSH to Kudu.

5. Make it executable (sometimes already is):

	```bash
	chmod +x appinsights_diag.sh
	```
6. Run it (default is verbose mode):

```bash
./appinsights_diag.sh
```

Quiet (minimal) output:

```bash
./appinsights_diag.sh --quiet
```

Full mode (adds environment snapshot + all guidance):

```bash
./appinsights_diag.sh --full
```
7. Download the HTML report & log from `Application Insights Diagnostic` directory.
8. (Not supported on Linux Consumption / Flex Consumption — no Kudu shell there.)

Linux flags (summary):

| Flag | Purpose |
|------|---------|
| (default) | Verbose guidance enabled |
| `--quiet` / `-q` | Minimal output (suppress guidance lines) |
| `--full` / `-F` | Full mode (verbose + extra environment snapshot) |
| `--output-dir <dir>` | Custom output directory |
| `--report <file>` | Custom HTML report path/name |
| `--site-path <rel>` | Change silent GET relative path (default `/AppInsightsDiag`) |
| `--disable-site-ping` | Skip silent site reachability GET |
| `--no-redact` | Do not redact connection string / iKey in log |
| `--verbose` / `-v` | (Redundant now) explicitly set verbose |

Example combined usage:

```bash
./appinsights_diag.sh --full --output-dir diag_out --report /home/site/wwwroot/ai-linux.html --site-path /PingStats --disable-site-ping
```


## Troubleshooting (Quick)

| Issue | Hint |
|-------|------|
| 404 connectivity | Wrong ingestion endpoint region. |
| Telemetry HTTP 400 | Bad JSON or old iKey usage. |
| Sampling ParseFailed | Invalid host.json. |
| Missing config | Add APPLICATIONINSIGHTS_CONNECTION_STRING. |


## Status Cheat Sheet

* **Configuration**: OK | Both exist | `iKey` only | Missing
* **Connectivity**: Reachable | `NotFound` (404) | Status:{CODE} | Error
* **Telemetry**: HTTP 200 Rec:1 Acc:1 Err:0 = success (else inspect body)
* `SamplingFlag`: True | False | `NotFound` | `ParseFailed`

## Kusto Snippets

Event validation:

```kusto
customEvents | where timestamp > ago(1h) | where name == 'curlConnectivityTestEvent-<GUID>'
```

Sampling retention:

```kusto
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

This script also issues a silent GET request to the relative path `/AppInsightsDiag`  purely for internal statistics / reachability tracking. A `404` response is expected and classified as `Expected404`; no response body is stored, and this call does not affect Application Insights telemetry or expose secrets.

## Support / Escalation

If issues persist after using this script and the portal detector, open an Azure Support request and attach the generated HTML report (in the `Application Insights Diagnostic` folder or the path from `-HtmlReportPath`) plus the redacted log for faster triage.



