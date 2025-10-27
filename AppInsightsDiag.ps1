param(
    [Parameter(Mandatory=$false)][switch] $VerboseMode,
    [Parameter(Mandatory=$false)][switch] $RedactTelemetry,
    [Parameter(Mandatory=$false)][string] $HostJsonPath,
    [Parameter(Mandatory=$false)][string] $HtmlReportPath,
    [Parameter(Mandatory=$false)][string] $OutputDirectory = 'Application Insights Diagnostic',
    [Parameter(Mandatory=$false)][string] $SiteRelativePath = '/AppInsightsDiag'
)

# Establish base path early (avoid null later); Kudu sets PSScriptRoot sometimes null.
$basePath = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

# Application Insights Diagnostic Script (auto-runs all steps)
Write-Output "=== Application Insights Diagnostic Script ==="
Write-Output "Expanded step list:" 
Write-Output "  Step 1) Configuration status detection" 
Write-Output "  Step 2) Connectivity curl command" 
Write-Output "  Step 3) Telemetry send + validation query" 
Write-Output "  Step 4) Sampling query (host.json where applicable)" 
Write-Output "  Step 5) Worker runtime guidance"
Write-Output "============================================="
#  Write-Output ("[Info] Script base path: {0}" -f $basePath)

# Resolve / create output directory (relative paths resolved against base)
$outputDir = if ([IO.Path]::IsPathRooted($OutputDirectory)) { $OutputDirectory } else { Join-Path $basePath $OutputDirectory }
if (-not (Test-Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir -Force | Out-Null }
#  Write-Output ("[Info] Output directory: {0}" -f $outputDir)

# Auto default HTML report if user did not specify a path (now placed in outputDir)
if (-not $HtmlReportPath) {
    $autoFile = "AI-Diagnostic-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    $HtmlReportPath = Join-Path $outputDir $autoFile
#     Write-Output ("[Info] No -HtmlReportPath supplied; defaulting to: {0}" -f $HtmlReportPath)
}

# Resolve HTML report target early
$HtmlReportResolved = $null
if ($HtmlReportPath) {
    try {
        # If user passed a directory, generate a filename
        $isDir = $false
        if (-not (Test-Path $HtmlReportPath)) {
            # Might be new file or directory that doesn't exist yet; check if ends with slash or has extension
            $ext = [IO.Path]::GetExtension($HtmlReportPath)
            if ([string]::IsNullOrWhiteSpace($ext) -and ($HtmlReportPath.TrimEnd() -match '[\\/]$')) { $isDir = $true }
        } elseif ((Get-Item $HtmlReportPath).PSIsContainer) {
            $isDir = $true
        }

        if ($isDir) {
            $dirTarget = $HtmlReportPath.TrimEnd('/','\\')
            if (-not (Test-Path $dirTarget)) { New-Item -ItemType Directory -Path $dirTarget -Force | Out-Null }
            $fileName = "AI-Diagnostic-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
            $HtmlReportResolved = Join-Path $dirTarget $fileName
        } else {
            # If path has no extension, append .md
            $ext = [IO.Path]::GetExtension($HtmlReportPath)
            if ([string]::IsNullOrWhiteSpace($ext)) { $HtmlReportPath = "$HtmlReportPath.html" }

            # Ensure parent directory exists
            $parent = [IO.Path]::GetDirectoryName((Resolve-Path -LiteralPath (Split-Path -Path $HtmlReportPath -Leaf -Resolve:$false) -ErrorAction SilentlyContinue))

            # Above might not work for relative; build absolute
            $absCandidate = if ([IO.Path]::IsPathRooted($HtmlReportPath)) { $HtmlReportPath } else { Join-Path (Get-Location).Path $HtmlReportPath }
            $parentDir = [IO.Path]::GetDirectoryName($absCandidate)
            if ($parentDir -and -not (Test-Path $parentDir)) { New-Item -ItemType Directory -Path $parentDir -Force | Out-Null }
            $HtmlReportResolved = $absCandidate
        }
        Write-Output ("[Info] HTML report will be written to: {0}" -f $HtmlReportResolved)
    } catch {
        Write-Output ("[WARN] Failed to resolve HTML report path '{0}': {1}" -f $HtmlReportPath, $_)
        $HtmlReportResolved = $null
    }
}

# Initialize detailed log accumulator early
$detailedLog = @()
function Add-Log($msg) { $script:detailedLog += "$(Get-Date -Format o) $msg" }

function Get-CurlPath {
    $candidates = @('curl','curl.exe')
    foreach ($c in $candidates) {
        $cmd = Get-Command $c -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.CommandType -eq 'Application') {
            if ($cmd.Path) { return $cmd.Path } elseif ($cmd.Source) { return $cmd.Source }
        }
    }
    return $null
}

# Derive AppName and ResourceGroup exclusively from environment variables
$AppName = (Get-Item Env:WEBSITE_SITE_NAME -ErrorAction SilentlyContinue).Value
$ResourceGroup = (Get-Item Env:WEBSITE_RESOURCE_GROUP -ErrorAction SilentlyContinue).Value
Add-Log "Script invoked. Derived AppName=$AppName ResourceGroup=$ResourceGroup"
if (-not $AppName) { Add-Log "AppName missing (WEBSITE_SITE_NAME not set)" }
if (-not $ResourceGroup) { Add-Log "ResourceGroup missing (WEBSITE_RESOURCE_GROUP not set)" }

# Helper to fetch environment app settings safely
function Get-AppSetting([string] $name) { (Get-Item -Path "Env:$name" -ErrorAction SilentlyContinue).Value }

# ---------------------------
# Step 1: Configuration status detection
# ---------------------------
$runConfig = $true; $runSiteEndpoint = $true; $runConnectivity = $true; $runTelemetry = $true; $runSampling = $true
$SamplingLookbackHours = 24

if ($VerboseMode -and $runConfig) { Write-Output "[Step 1/5] Configuration status detection (verbose)" } else { Write-Output "[Step 1/5] Configuration status detection..." }

$hasInstrumentationKey = -not [string]::IsNullOrWhiteSpace((Get-AppSetting "APPINSIGHTS_INSTRUMENTATIONKEY"))
$hasConnectionString  = -not [string]::IsNullOrWhiteSpace((Get-AppSetting "APPLICATIONINSIGHTS_CONNECTION_STRING"))

$configStatus = ""
if ($hasInstrumentationKey -and $hasConnectionString) {
    $configStatus = "Both exist (remove APPINSIGHTS_INSTRUMENTATIONKEY, keep APPLICATIONINSIGHTS_CONNECTION_STRING)"; if ($VerboseMode) { Write-Output $configStatus }
} elseif ($hasInstrumentationKey -and -not $hasConnectionString) {
    $configStatus = "APPINSIGHTS_INSTRUMENTATIONKEY only (should migrate)"; if ($VerboseMode) { Write-Output $configStatus }
} elseif ($hasConnectionString) {
    $configStatus = "OK"; if ($VerboseMode) { Write-Output "APPLICATIONINSIGHTS_CONNECTION_STRING is correctly set." }
} else {
    $configStatus = "Missing"; if ($VerboseMode) { Write-Output "Neither setting exists." }
}

$presentSettings = @()
if ($hasConnectionString) { $presentSettings += 'APPLICATIONINSIGHTS_CONNECTION_STRING' }
if ($hasInstrumentationKey) { $presentSettings += 'APPINSIGHTS_INSTRUMENTATIONKEY' }
Write-Output ("Configuration status: {0}" -f $configStatus)
Write-Output ("Present settings: {0}" -f ($(if ($presentSettings.Count -gt 0) { $presentSettings -join ', ' } else { 'None' })))
switch ($configStatus) {
    'OK'       { Write-Output 'Guidance: Using connection string (recommended). No action needed.' }
    {$_ -like 'Both exist*'} { Write-Output 'Guidance: Remove APPINSIGHTS_INSTRUMENTATIONKEY (legacy) and retain APPLICATIONINSIGHTS_CONNECTION_STRING.' }
    {$_ -like 'iKey only*'} { Write-Output 'Guidance: Migrate to APPLICATIONINSIGHTS_CONNECTION_STRING for endpoint flexibility and future features.' }
    'Missing'  { Write-Output 'Guidance: Add APPLICATIONINSIGHTS_CONNECTION_STRING (Portal: Application Insights -> Overview -> Connection string). Telemetry will not flow until set.' }
}
$summaryConfig = $configStatus
Write-Output "============================================="
# (Sampling handled in final step)

# Initialize skip flags
if (-not $skipSampling) { $skipSampling = $false }
if (-not $skipConnectivity) { $skipConnectivity = $false }
if (-not $skipTelemetry) { $skipTelemetry = $false }

# Check for native curl presence (ignore alias to Invoke-WebRequest)
$curlNativePath = Get-CurlPath
if (-not $curlNativePath) {
    Write-Output "[WARN] native curl executable not found. Auto executions will fall back or be skipped. Install curl for full functionality.";
    Add-Log "curl native missing"
} else {
    Add-Log "curl native found at $curlNativePath"
}

# Defer printing the Step 2 header until we know whether connectivity will be skipped.
if ($runConnectivity) {
    Add-Log "Connectivity section pending"
} else {
    Write-Output "[Step 2/5] Skip Connectivity test command as APPLICATIONINSIGHTS_CONNECTION_STRING is missing ..."
    Add-Log "Connectivity section skipped (runConnectivity=false)"
}

# ---------------------------
# Site Endpoint (App base URL) GET test (Step 2)
# ---------------------------
if ($runSiteEndpoint) {
    $siteEndpointStatus = 'Unknown'
    if ($AppName) {
        $siteBase = "https://$AppName.azurewebsites.net"
        $relative = if ($SiteRelativePath.StartsWith('/')) { $SiteRelativePath } else { "/$SiteRelativePath" }
        $fullUrl = "$siteBase$relative"
        if ($VerboseMode) { Write-Output "[Hidden] Site endpoint GET test (tracking only, expecting 404): $fullUrl" }
        Add-Log "Site endpoint test url=$fullUrl"
        $curlPathSite = Get-CurlPath
        try {
            if ($curlPathSite) {
                $tmpSite = Join-Path $env:TEMP '_ai_site_tmp'
                $statusSite = & $curlPathSite -s -o $tmpSite -w "%{http_code}" -L $fullUrl
                Remove-Item $tmpSite -ErrorAction SilentlyContinue
            } else {
                $respSite = Invoke-WebRequest -Uri $fullUrl -Method Get -ErrorAction Stop
                $statusSite = $respSite.StatusCode.value__
            }

            switch ($statusSite) {
                {$_ -in '200','302','301'} { $siteEndpointStatus = 'Reachable' }
                '404' { $siteEndpointStatus = 'Expected404' }
                default { $siteEndpointStatus = "Status:$statusSite" }
            }
            if ($VerboseMode) { Write-Output ("Site endpoint result: HTTP {0} -> {1}" -f $statusSite,$siteEndpointStatus) }
            Add-Log "Site endpoint status=$statusSite classification=$siteEndpointStatus"
        } catch {
            Write-Output "Site endpoint test failed: $_"
            Add-Log "Site endpoint test failed error=$_"
            $siteEndpointStatus = 'Error'
        }

        if ($VerboseMode) { Write-Output "=============================================" }
    } else {
        if ($VerboseMode) { Write-Output "[Hidden] Site endpoint test skipped (AppName env var missing)." }
        $siteEndpointStatus = 'Skipped'
    }
}

# Extract APPLICATIONINSIGHTS_CONNECTION_STRING (trim whitespace)
$connString = (Get-AppSetting "APPLICATIONINSIGHTS_CONNECTION_STRING")
if ($connString) { $connString = $connString.Trim() }
if ([string]::IsNullOrWhiteSpace($connString)) {
    Add-Log "Connection string missing"
    Write-Output "[Step 2/4] Skipping Connectivity test command as APPLICATIONINSIGHTS_CONNECTION_STRING is missing ..."
    Add-Log "Connectivity skipped: APPLICATIONINSIGHTS_CONNECTION_STRING missing"
    $skipConnectivity = $true
}

# Extract IngestionEndpoint
$endpoint = ($connString -split ";") | Where-Object { $_ -like "IngestionEndpoint*" }
$endpoint = $endpoint -replace "IngestionEndpoint=", ""

if (-not $skipConnectivity -and ($runConnectivity -or $runTelemetry)) {
    if (-not $endpoint) {
        if ($VerboseMode) { Write-Output "IngestionEndpoint not found in connection string." }
        Add-Log "IngestionEndpoint missing in connection string"
        $skipConnectivity = $true
    }
}

# Now print the Step 2 header only if connectivity will run
if ($runConnectivity -and -not $skipConnectivity) {
    if ($VerboseMode) {
        Write-Output "`n2. *******Connectivity Check.*******"
        Write-Output "NOTE: Run the curl below in Kudu (console) for in-app verification."
    } else {
    Write-Output "[Step 2/5] Connectivity test command..."
    }
    Add-Log "Connectivity section"
}

if (-not $skipConnectivity) {
    # Normalize endpoint and show curl
    $endpoint = $endpoint.TrimEnd('/')
    $testUrl = "$endpoint/v2/track"
    if ($VerboseMode) {
        Write-Output "`nRun this command in Kudu PowerShell or CMD to test connectivity , 405 indicates endpoint reachable (method not allowed for HEAD) and is treated as success:"
        Write-Output "curl -I $testUrl"
    } else {
        Write-Output "Connectivity command: curl -I $testUrl"
        Write-Output "Connectivity success criteria: HTTP 200 or 405 = reachable; 404 = region/endpoint mismatch."
    }

    # Execute connectivity test automatically
    $connectivityStatus = "Unknown"
    $curlPath = Get-CurlPath
    if ($curlPath) {
        try {
            $connectivityTemp = Join-Path $env:TEMP '_ai_connectivity_tmp'
            $statusCode = & $curlPath -s -o $connectivityTemp -w "%{http_code}" -I $testUrl
            Remove-Item $connectivityTemp -ErrorAction SilentlyContinue
            switch ($statusCode) {
                {$_ -in '200','405'} { $connectivityStatus = 'Reachable' }
                '404' { $connectivityStatus = 'NotFound(404)' }
                default { $connectivityStatus = "Status:$statusCode" }
            }
            Write-Output ("Connectivity result: HTTP {0} -> {1}" -f $statusCode, $connectivityStatus)
            Add-Log "Connectivity executed via curl status=$statusCode classification=$connectivityStatus"
            if ($connectivityStatus -ne 'Reachable') {
                if ($VerboseMode) {
                    Write-Output '[Insight] Connectivity issue. Quick checklist:'
                    Write-Output '  - Region match: IngestionEndpoint host vs AI resource region'
                    Write-Output "  - curl -v $testUrl for DNS/TLS details"
                    Write-Output '  - Outbound 443 allowed to *.applicationinsights.azure.com'
                    Write-Output '  - Re-copy connection string if stale'
                    if ($connectivityStatus -like 'NotFound*') { Write-Output '  - 404: usually region mismatch or wrong endpoint' }
                }
            }
        } catch {
            Write-Output "Connectivity execution failed (curl): $_"
            Add-Log "Connectivity curl failed: $_"
            $connectivityStatus = 'Error'
        }
    } else {
        # Fallback using Invoke-WebRequest HEAD
        try {
            $resp = Invoke-WebRequest -Uri $testUrl -Method Head -ErrorAction Stop
            $statusCode = $resp.StatusCode.value__
            $connectivityStatus = if ($statusCode -in 200,405) { 'Reachable' } elseif ($statusCode -eq 404) { 'NotFound(404)' } else { "Status:$statusCode" }
            Write-Output ("Connectivity result (Invoke-WebRequest): HTTP {0} -> {1}" -f $statusCode, $connectivityStatus)
            Add-Log "Connectivity executed via Invoke-WebRequest status=$statusCode classification=$connectivityStatus"
            if ($connectivityStatus -ne 'Reachable') {
                if ($VerboseMode) {
                    Write-Output '[Insight] Connectivity issue. Quick checklist:'
                    Write-Output '  - Region match: IngestionEndpoint host vs AI resource region'
                    Write-Output "  - curl -v $testUrl for DNS/TLS details (compare)"
                    Write-Output '  - Outbound 443 allowed to *.applicationinsights.azure.com'
                    Write-Output '  - Re-copy connection string if stale'
                    if ($connectivityStatus -like 'NotFound*') { Write-Output '  - 404: usually region mismatch or wrong endpoint' }
                }
            }
        } catch {
            $statusCode = if ($_.Exception.Response) { $_.Exception.Response.StatusCode.value__ } else { 'N/A' }
            Write-Output "Connectivity execution failed (Invoke-WebRequest): $_"
            Add-Log "Connectivity Invoke-WebRequest failed status=$statusCode error=$_"
            $connectivityStatus = 'Error'
        }
    }
    $connectivityClassification = $connectivityStatus
    $connectivityStatus = "Ready"
    Write-Output "============================================="
} else {
    # Ensure connectivity classification notes missing connection string explicitly
    if ($skipConnectivity) {
        $connectivityStatus = "Skipped"
        $connectivityClassification = "Skipped (no APPLICATIONINSIGHTS_CONNECTION_STRING)"
    } else {
        $connectivityStatus = "Skipped"
        $connectivityClassification = "Skipped"
    }
}

if ($runTelemetry -and -not $skipConnectivity -and -not $skipTelemetry) {
    if ($VerboseMode) { Write-Output "`n3. *******Send Minimal Telemetry (curl)*******" } else { Write-Output "[Step 3/5] Telemetry send + validation query..." }
} else {
    Write-Output "[Step 3/5] Skipping Telemetry send + validation query as APPLICATIONINSIGHTS_CONNECTION_STRING is missing ..."
}

# Find iKey: prefer APPINSIGHTS_INSTRUMENTATIONKEY else parse from connection string
    # Parse InstrumentationKey from connection string if needed
    $ikeyFromConn = ($connString -split ";") | Where-Object { $_ -like "InstrumentationKey*" }
    if ($ikeyFromConn) { $iKey = $ikeyFromConn -replace "InstrumentationKey=", "" }

if (-not $iKey) {
    if ($VerboseMode) { Write-Output "Telemetry: iKey missing" }
    Add-Log "iKey missing; aborting telemetry section"
    $skipTelemetry = $true
}

if (-not $skipConnectivity) {
    # Build ingestion URL (/v2/track)
    $ingestUrl = "$endpoint/v2/track"
}

# Build telemetry payload (unique event)
$now = (Get-Date).ToUniversalTime().ToString("o")
$eventId = [guid]::NewGuid().ToString()
$eventName = "curlConnectivityTestEvent-$eventId"
$payloadObj = @(
    @{
        name = "Microsoft.ApplicationInsights.Event"
        time = $now
        iKey = $iKey
        data = @{
            baseType = "EventData"
            baseData = @{
                ver = 2
                name = $eventName
                properties = @{
                    Source = "ConnectivityCheckScript"
                    App = $AppName
                    EventId = $eventId
                }
            }
        }
    }
)

# Build compact JSON
Add-Log "Building telemetry JSON"
$compactJson = $payloadObj | ConvertTo-Json -Depth 6 -Compress
Add-Log "Telemetry JSON length: $($compactJson.Length)"
Add-Log "Telemetry JSON inline begin"
Add-Log "TELEMETRY_JSON $compactJson"
Add-Log "Telemetry JSON inline end"

# Inline curl command (JSON must start with '[')
$escapedJson = $compactJson.Replace('"','\"')
$curlInline = "curl -v -X POST `"$ingestUrl`" -H `"Content-Type: application/json`" -d `"$escapedJson`""

if ($runTelemetry -and -not $skipTelemetry -and -not $skipConnectivity) {
    if ($VerboseMode) {
        Write-Output "Telemetry curl (inline):"
        Write-Output $curlInline
        Write-Output "Notes: 200=ingested 400=payload/iKey issue 405/404=head/get reachability only.`n"
        Write-Output ("Validation query (after 1-2 min): customEvents | where timestamp > ago(1h) | where name == '{0}' | project timestamp,name,customDimensions | order by timestamp desc" -f $eventName)
    } else {
        Write-Output "Telemetry command: $curlInline"
        Write-Output 'Expected response JSON: {"itemsReceived":1,"itemsAccepted":1,"appId":null,"errors":[]}'
        Write-Output ("Validation query: customEvents | where timestamp > ago(1h) | where name == '{0}' | project timestamp,name,customDimensions | order by timestamp desc" -f $eventName)
    }
    Add-Log "Telemetry curl command prepared"

    # Execute telemetry send automatically
    $telemetryStatus = 'Pending'
    $curlTelemetryPath = Get-CurlPath
    if ($curlTelemetryPath) {
        try {
            $telemetryTemp = Join-Path $env:TEMP '_ai_telemetry_payload.json'
            Set-Content -Path $telemetryTemp -Value $compactJson -Encoding UTF8
            $telemetryRaw = & $curlTelemetryPath -s -w 'HTTPSTATUS:%{http_code}' -H 'Content-Type: application/json' -X POST $ingestUrl -d @$telemetryTemp
            $httpStatusTelemetry = ($telemetryRaw -split 'HTTPSTATUS:')[-1]
            $bodyTelemetry = $telemetryRaw -replace "HTTPSTATUS:.*$",""
            Add-Log "Telemetry response status=$httpStatusTelemetry bodyLength=$($bodyTelemetry.Length)"
            $parsedTelemetry = $null
            try { $parsedTelemetry = $bodyTelemetry | ConvertFrom-Json -ErrorAction Stop } catch { Add-Log "Telemetry parse failed: $_" }
            if ($parsedTelemetry) {
                $itemsReceived = $parsedTelemetry.itemsReceived
                $itemsAccepted = $parsedTelemetry.itemsAccepted
                $errorsCount = if ($parsedTelemetry.errors) { $parsedTelemetry.errors.Count } else { 0 }
                Write-Output ("Telemetry send result: HTTP {0} itemsReceived={1} itemsAccepted={2} errors={3}" -f $httpStatusTelemetry,$itemsReceived,$itemsAccepted,$errorsCount)
                $telemetryResult = "HTTP $httpStatusTelemetry Rec:$itemsReceived Acc:$itemsAccepted Err:$errorsCount"
            } else {
                Write-Output ("Telemetry send result: HTTP {0} raw body: {1}" -f $httpStatusTelemetry,$bodyTelemetry)
                $telemetryResult = "HTTP $httpStatusTelemetry Raw"
            }
            Remove-Item $telemetryTemp -ErrorAction SilentlyContinue
            $telemetryStatus = if ($httpStatusTelemetry -eq '200') { 'Sent' } else { "HTTP:$httpStatusTelemetry" }
        } catch {
            Write-Output "Telemetry execution failed (curl): $_"
            Add-Log "Telemetry curl failed: $_"
            $telemetryStatus = 'Error'
            $telemetryResult = "Error"
        }
    } else {
        Write-Output "[INFO] native curl not found; telemetry auto-send skipped (run command manually)."
        $telemetryStatus = 'SkippedNoCurl'
        $telemetryResult = "Skipped(no curl)"
    }
    $telemetryStatus = "Ready"
    Write-Output "============================================="
} else {
    $telemetryStatus = if ($skipConnectivity) { "Skipped" } elseif ($skipTelemetry) { "Missing iKey" } else { "Unknown" }
    $telemetryResult = $telemetryStatus
}

# (Summary shown at end)

Add-Log "Sanitizing and writing detailed log"

# Silent log export (into output directory)
$logPath = Join-Path $outputDir "Check-AI-detailed-log.txt"
$sanitized = $detailedLog
if ($iKey) { $sanitized = $sanitized | ForEach-Object { $_ -replace [regex]::Escape($iKey), '[REDACTED_IKEY]' } }
if ($connString) { $sanitized = $sanitized | ForEach-Object { $_ -replace [regex]::Escape($connString), '[REDACTED_CONNECTION_STRING]' } }
Set-Content -Path $logPath -Value ($sanitized -join "`n") -Encoding UTF8
# (Log saved silently; use -VerboseMode for more details.)
## Removed early detailed log path output per user request; shown only in final summary now.

# Step 4: Combined sampling query + host.json samplingSettings
Write-Output "[Step 4/5] Sampling query (host.json where applicable)..."
# Runtime override: if FUNCTIONS_WORKER_RUNTIME is java or dotnet-isolated, sampling must be handled in code (host.json ignored for custom logs configuration).
$workerRuntime = (Get-AppSetting "FUNCTIONS_WORKER_RUNTIME")
$runtimeOverride = $false
if ($workerRuntime) {
    $rtLower = $workerRuntime.ToLowerInvariant()
    if ($rtLower -in @('java','dotnet-isolated')) {
        $runtimeOverride = $true
        Write-Output ("[Runtime] FUNCTIONS_WORKER_RUNTIME={0} detected. Sampling / logging configuration must be handled in application code; host.json samplingSettings not applicable." -f $workerRuntime)
        Write-Output "Reference: https://learn.microsoft.com/en-us/troubleshoot/azure/azure-functions/monitoring/functions-monitoring-appinsightslogs#custom-application-logs"
    }
}
$lookback = "ago(${SamplingLookbackHours}h)"
$query = "union requests, dependencies, pageViews, browserTimings, exceptions, traces | where timestamp > ${lookback} | summarize RetainedPercentage = 100/avg(coalesce(itemCount,1)) by bin(timestamp, 1h), itemType"
if (-not $runtimeOverride) {
    Write-Output "host.json samplingSettings status (evaluated first):";
    # Determine host.json path dynamically
    if ($HostJsonPath) {
        $hostJsonPath = $HostJsonPath
        $hostJsonSource = 'OverrideParameter'
    } else {
        $hostJsonPath = $null
        # Common Azure Functions layout
        if ($env:HOME) {
            $sitePath = Join-Path $env:HOME 'site'
            $wwwrootPath = Join-Path $sitePath 'wwwroot'
            if (Test-Path $wwwrootPath) {
                $candidate = Join-Path $wwwrootPath 'host.json'
                if (Test-Path $candidate) { $hostJsonPath = $candidate; $hostJsonSource = 'DetectedFunctionsRoot'; }
            }
        }
        if (-not $hostJsonPath) {
            # Fallback: script base path
            $hostJsonPath = Join-Path $basePath 'host.json'
            $hostJsonSource = 'ScriptBasePath'
        }
    }
    Write-Output ("[Info] host.json resolved from {0}: {1}" -f $hostJsonSource, $hostJsonPath)
    Add-Log ("host.json resolution source={0} path={1}" -f $hostJsonSource,$hostJsonPath)
}

$samplingEnabled = $null
${hostJsonParseError} = $null
${hostJsonStructureIssues} = @()
if (-not $runtimeOverride -and (Test-Path $hostJsonPath)) {
    try {
        $hostJsonItem = Get-Item $hostJsonPath -ErrorAction Stop
        $hostJsonSize = $hostJsonItem.Length
        Add-Log ("host.json exists size={0} bytes" -f $hostJsonSize)
        $hostJsonContent = Get-Content $hostJsonPath -Raw -ErrorAction Stop
        $trimPreview = $hostJsonContent.Substring(0,[Math]::Min(300,$hostJsonContent.Length)).Replace("`r"," ").Replace("`n"," ")
        Add-Log ("host.json head(300c)={0}" -f $trimPreview)
        $hostJsonObj = $hostJsonContent | ConvertFrom-Json -ErrorAction Stop

        if (-not $hostJsonObj.logging) { $hostJsonStructureIssues += 'Missing logging node'; Add-Log 'host.json structure: missing logging'; }
        if ($hostJsonObj.logging -and -not $hostJsonObj.logging.applicationInsights) { $hostJsonStructureIssues += 'Missing logging.applicationInsights node'; Add-Log 'host.json structure: missing logging.applicationInsights'; }
        if ($hostJsonObj.logging.applicationInsights -and -not $hostJsonObj.logging.applicationInsights.samplingSettings) { $hostJsonStructureIssues += 'Missing samplingSettings node'; Add-Log 'host.json structure: missing samplingSettings'; }
        if ($hostJsonStructureIssues.Count -gt 0) { Add-Log ("host.json structure issues: {0}" -f ($hostJsonStructureIssues -join '; ')) }

        # Detect presence of samplingSettings and isEnabled explicitly
        $hasSamplingSettingsNode = $hostJsonObj.logging.applicationInsights.samplingSettings
        $hasIsEnabledProperty = $false
        if ($hasSamplingSettingsNode) { $hasIsEnabledProperty = $hasSamplingSettingsNode.PSObject.Properties.Name -contains 'isEnabled' }

        if (-not $hasSamplingSettingsNode -or -not $hasIsEnabledProperty) {
            # Requirement: If samplingSettings or the isEnabled value not present, inform user sampling not set and therefore enabled by default.
            Add-Log 'samplingSettings.isEnabled missing -> default platform sampling ENABLED'
            Write-Output ' - samplingSettings.isEnabled not specified -> sampling not set in host.json; default platform sampling is ENABLED.'
            $samplingEnabled = $true  # Treat implicit default as enabled for downstream logic
            $samplingFlag = 'ImplicitDefaultEnabled'
        } else {
            $samplingEnabled = $hostJsonObj.logging.applicationInsights.samplingSettings.isEnabled
            if ($null -eq $samplingEnabled) {
                Add-Log 'samplingSettings.isEnabled present but null -> treating as default enabled'
                Write-Output ' - samplingSettings.isEnabled is null -> treating as default ENABLED.'
                $samplingEnabled = $true
                $samplingFlag = 'ImplicitDefaultEnabled'
            } else {
                Add-Log ("samplingSettings.isEnabled={0}" -f $samplingEnabled)
                Write-Output (" - samplingSettings.isEnabled={0}" -f $samplingEnabled)
                $samplingFlag = $samplingEnabled
            }
        }
    } catch {
        ${hostJsonParseError} = $_.Exception.Message
        Add-Log ("host.json parse failed exceptionType={0} message={1}" -f $_.Exception.GetType().FullName, ${hostJsonParseError})
        Write-Output (" - host.json parse failed: {0}" -f ${hostJsonParseError})
        $samplingFlag = 'ParseFailed'
    }
} elseif (-not $runtimeOverride) {
    Write-Output " - host.json not found"
    $samplingFlag = 'NotFound'
}

if ($runtimeOverride) {
    $samplingFlag = 'CodeManaged'
    Write-Output "[Info] Runtime indicates code-managed logging; host.json inspection skipped entirely." 
    Write-Output "Kusto query (24h retention sampling assessment):"
    Write-Output $query
    Write-Output "Interpretation: RetainedPercentage ~100 => no sampling; <100 => sampling active; fluctuations => adaptive adjustments." 
    Write-Output "(Disable sampling via code instrumentation; host.json snippet not shown.)"
}
elseif ($samplingEnabled -eq $false) {
    Write-Output "[Info] Sampling is disabled. Skipping Kusto retention query (not needed)."
} elseif (-not $runtimeOverride -and $samplingEnabled -eq $true) {
    Write-Output "[Action] Sampling enabled. Run Kusto query below to measure retained vs original volume and confirm impact:"
    Write-Output "Kusto query (24h retention sampling assessment):"
    Write-Output $query
    Write-Output ""
    Write-Output "Interpretation:"
    Write-Output " - RetainedPercentage ~100: Sampling NONE (effectively full retention)"
    Write-Output " - Drops below 100: Sampling ACTIVE (telemetry reduced)"
    Write-Output " - Variations (e.g. 95, 97): Adaptive sampling adjusting to volume"
} elseif (-not $runtimeOverride) {
    # Provide nuanced messaging if parse failed vs not found; treat NotFound as assumed enabled per user request
    if ($samplingFlag -eq 'ParseFailed') {
        Write-Output ("[Info] Sampling status UNKNOWN: host.json parse failed. Error: {0}. See detailed log for head + structure diagnostics." -f ${hostJsonParseError})
    } elseif ($samplingFlag -eq 'NotFound') {
        Write-Output "[Info] Sampling setting not found; assuming default platform sampling is ENABLED. Use retention query to confirm effective reduction."
        $samplingFlag = 'NotFound(AssumedEnabled)'
    } else {
        Write-Output "[Info] Sampling status unknown; showing query for manual inspection:"
    }
    Write-Output "Kusto query (24h retention sampling assessment):"
    Write-Output $query
    Write-Output ""
    Write-Output "Interpretation:"
    Write-Output " - RetainedPercentage ~100: Sampling NONE (full retention)"
    Write-Output " - Drops below 100: Sampling ACTIVE (reduced retention)"
    Write-Output " - Variations (e.g. 95, 97): Adaptive sampling adjusting to volume"
}
Write-Output ""
if (-not $runtimeOverride) {
    Write-Output "To disable sampling add to host.json snippet:"
    Write-Output '{'
    Write-Output '  "logging": {'
    Write-Output '    "applicationInsights": {'
    Write-Output '      "samplingSettings": {'
    Write-Output '        "isEnabled": false'
    Write-Output '      }'
    Write-Output '    }'
    Write-Output '  }'
    Write-Output '}'
} else {
    Write-Output "(Host.json disable snippet suppressed for runtime override.)"
}
Add-Log "Combined sampling & host.json step displayed"
Write-Output "============================================="
# Step 5: Worker runtime guidance (always shown)
Write-Output "[Step 5/5] Worker runtime guidance..."
if ($workerRuntime) {
    if ($runtimeOverride) {
        Write-Output ("Runtime: {0} (code-managed telemetry & sampling). See custom application logs guidance: https://learn.microsoft.com/en-us/troubleshoot/azure/azure-functions/monitoring/functions-monitoring-appinsightslogs#custom-application-logs" -f $workerRuntime)
    } else {
        Write-Output ("Runtime: {0} (host.json samplingSettings applicable)." -f $workerRuntime)
    }
} else {
    Write-Output "Runtime: (FUNCTIONS_WORKER_RUNTIME not set)"
}
Write-Output "============================================="

# ---------------------------
# Final Summary Box
# ---------------------------
Write-Output ""
# Ensure connectivityClassification explicitly reflects the missing connection string case
if ($skipConnectivity -and (-not $connectivityClassification -or $connectivityClassification -eq 'Skipped')) {
    $connectivityClassification = "Skipped (no APPLICATIONINSIGHTS_CONNECTION_STRING)"
}

$runtimeDisplay = if ($workerRuntime) { $workerRuntime } else { '(unset)' }
if ($samplingFlag -eq 'CodeManaged') {
    $samplingSummaryDisplay = 'CodeManaged (not via host.json)'
} else {
    $samplingSummaryDisplay = $samplingFlag
}
if ($runtimeOverride) {
    $runtimeSummaryDisplay = "$runtimeDisplay  CodeManaged (not via host.json)"
} else {
    $runtimeSummaryDisplay = $runtimeDisplay
}
$summaryLines = @(
    "Configuration : $summaryConfig",
    "Connectivity  : $connectivityClassification",
    "Telemetry     : $telemetryResult",
    "SamplingFlag  : $samplingSummaryDisplay",
    "Runtime       : $runtimeSummaryDisplay"
)
$maxLen = ($summaryLines | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
if (-not $maxLen) { $maxLen = 0 }
$border = "+" + ("-" * ($maxLen + 2)) + "+"
Write-Output "Summary (brief):"
Write-Output $border
foreach ($line in $summaryLines) { Write-Output ("| " + $line + (" " * ($maxLen - $line.Length)) + " |") }
Write-Output $border
Write-Output ""
Write-Output ("[Info] Detailed log saved: {0}" -f $logPath)
Write-Output "[Info] Run with -VerboseMode for expanded diagnostic details."

# High-visibility NEXT STEPS block (guard against non-interactive console color failures)
$nextStepsLines = @(
    '================ NEXT STEPS ================',
    'Portal: Function App -> Diagnose and solve problems -> Run "Function App Missing Telemetry" detector.',
    'If still missing telemetry: open Azure Support and attach the HTML report + redacted log.',
    '============================================'
)

function Write-BlockSafe {
    param(
        [string[]] $Lines,
        [ConsoleColor] $Color = [ConsoleColor]::Cyan
    )
    $colorSupported = $true
    # Heuristic: if host UI RawUI not present or output is redirected, avoid color
    try {
        $nullTest = $Host.UI.RawUI.ForegroundColor | Out-Null
    } catch {
        $colorSupported = $false
    }
    if ($env:WEBSITE_INSTANCE_ID -and -not $Host.UI) { $colorSupported = $false }
    if (-not $colorSupported) {
        # Fallback plain output with simple ASCII marker
        Write-Output '[Info] (Color output not supported in this host; displaying plain text block below)'
        foreach ($l in $Lines) { Write-Output $l }
        return
    }
    try {
        $orig = $Host.UI.RawUI.ForegroundColor
        foreach ($l in $Lines) { Write-Host $l -ForegroundColor $Color }
        $Host.UI.RawUI.ForegroundColor = $orig
    } catch {
        # On failure revert to plain output
        Write-Output '[Warn] Console color write failed; falling back to plain block.'
        foreach ($l in $Lines) { Write-Output $l }
    }
}

Write-BlockSafe -Lines $nextStepsLines -Color Cyan

if ($HtmlReportResolved) {
    $generatedUtc = (Get-Date).ToUniversalTime().ToString('u')
    $presentList = if ($presentSettings.Count -gt 0) { $presentSettings -join ', ' } else { 'None' }
    if ($eventName) {
        $validationSection = @"
<h3>Telemetry Validation Query</h3>
<pre><code class='kusto'>customEvents | where timestamp &gt; ago(1h) | where name == '$eventName' | project timestamp,name,customDimensions | order by timestamp desc</code></pre>
"@
    } else { $validationSection = '' }

    try {
        $logTail = Get-Content -Path $logPath -Tail 50 -ErrorAction SilentlyContinue
        $logTailText = if ($logTail) { $logTail -join "`n" } else { '(No log content)' }
    } catch { $logTailText = '(Failed to read log tail)' }

    $samplingConfigured = if ($samplingFlag -is [bool]) { "Configured isEnabled: $samplingFlag" } elseif ($samplingFlag -eq 'CodeManaged') { "Runtime override (code-managed)" } else { '' }
    $retentionQuery = "union requests, dependencies, pageViews, browserTimings, exceptions, traces | where timestamp > ago(${SamplingLookbackHours}h) | summarize RetainedPercentage = 100/avg(coalesce(itemCount,1)) by bin(timestamp, 1h), itemType"
    $appNameLine = if ($AppName) { "<p><strong>App Name:</strong> $AppName</p>" } else { '' }
    $logEscaped = ($logTailText -replace '&','&amp;') -replace '<','&lt;' -replace '>','&gt;'

                # Build worker runtime guidance HTML block (expanded details)
                $runtimeDisplayForHtml = if ($workerRuntime) { $workerRuntime } else { '(unset)' }
        if ($runtimeOverride) {
            $workerRuntimeGuidanceHtml = @"
<p><strong>Guidance:</strong> For this runtime (java / dotnet-isolated), sampling &amp; custom logs are configured in application code; host.json <code>samplingSettings</code> is ignored.</p>
<h3>.NET isolated example: disable adaptive sampling</h3>
<pre><code class='csharp'>// Program.cs (.NET isolated)
builder.Services.AddApplicationInsightsTelemetryWorkerService(options =&gt; {
    options.EnableAdaptiveSampling = false; // disables adaptive sampling
});
// Optionally configure TelemetryConfiguration for more processors:
// builder.Services.AddSingleton&lt;ITelemetryInitializer, MyInitializer&gt;();
</code></pre>
<p>After disabling, the RetainedPercentage in the Kusto query should remain close to 100 indicating full retention.</p>
<p>Reference: <a href="https://learn.microsoft.com/en-us/troubleshoot/azure/azure-functions/monitoring/functions-monitoring-appinsightslogs#custom-application-logs" target="_blank">Custom application logs guidance</a>.</p>
"@
                } else {
                        $workerRuntimeGuidanceHtml = @"
<p>Host.json samplingSettings apply for this runtime. To disable sampling add:</p>
<pre><code class='json'>{
    \"logging\": {
        \"applicationInsights\": {
            \"samplingSettings\": {
                \"isEnabled\": false
            }
        }
    }
}</code></pre>
<p>Restart the Function App after editing <code>host.json</code>. Use the retention query to confirm RetainedPercentage ~100 (no sampling).</p>
"@
                }

                $report = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <title>Application Insights Diagnostic Report</title>
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
        .badge-ok { background:#e6f9ee; color:#137333; padding:2px 6px; border-radius:4px; font-size:.75rem; }
        .badge-warn { background:#fff4e5; color:#8a5600; padding:2px 6px; border-radius:4px; font-size:.75rem; }
        .badge-err { background:#fdecea; color:#b3261e; padding:2px 6px; border-radius:4px; font-size:.75rem; }
    </style>
</head>
<body>
    <h1>Application Insights Diagnostic Report</h1>
    <p><strong>Generated (UTC):</strong> $generatedUtc</p>
    $appNameLine
    <div class="section">
        <h2>Summary</h2>
        <table>
            <tr><th>Category</th><th>Status</th></tr>
            <tr><td>Configuration</td><td>$summaryConfig</td></tr>
            <tr><td>Connectivity</td><td>$connectivityClassification</td></tr>
            <tr><td>Telemetry</td><td>$telemetryResult</td></tr>
            <tr><td>SamplingFlag</td><td>$(if ($samplingFlag -eq 'CodeManaged') { 'CodeManaged (not via host.json)' } else { $samplingFlag })</td></tr>
            <tr><td>Runtime</td><td>$(if ($runtimeOverride) { "$runtimeDisplayForHtml CodeManaged (not via host.json)" } else { $runtimeDisplayForHtml })</td></tr>
        </table>
    </div>
    <div class="section">
        <h2>Configuration</h2>
        <p>Status: $summaryConfig<br/>Present settings: $presentList</p>
    </div>
    <div class="section">
        <h2>Connectivity</h2>
        <p>Result: $connectivityClassification<br/>Endpoint: $endpoint</p>
    </div>
    <div class="section">
        <h2>Telemetry</h2>
        <p>Result: $telemetryResult</p>
        $validationSection
    </div>
    <div class="section">
        <h2>Sampling (Step 4)</h2>
        <p>Sampling flag: $samplingFlag<br/>$samplingConfigured</p>
        <h3>Retention query (24h window)</h3>
        <pre><code class='kusto'>$($retentionQuery -replace '<','&lt;' -replace '>','&gt;')</code></pre>
        <p><em>Interpretation:</em> RetainedPercentage ~100 =&gt; no/zero sampling; &lt;100 =&gt; sampling active; fluctuating =&gt; adaptive sampling adjustments.</p>
        $(if (-not $runtimeOverride) { '<h3>Disable Sampling Snippet</h3><pre><code class="json">{`n  "logging": {`n    "applicationInsights": {`n      "samplingSettings": {`n        "isEnabled": false`n      }`n    }`n  }`n}</code></pre>' } else { '<p><strong>Runtime override:</strong> sampling & logging must be configured in code for this worker runtime. See <a href="https://learn.microsoft.com/en-us/troubleshoot/azure/azure-functions/monitoring/functions-monitoring-appinsightslogs#custom-application-logs" target="_blank">documentation</a>.</p>' })
    </div>
    <div class="section">
        <h2>Worker Runtime (Step 5)</h2>
        <p>FUNCTIONS_WORKER_RUNTIME: $runtimeDisplayForHtml</p>
        $workerRuntimeGuidanceHtml
    </div>
    <div class="section">
        <h2>Redacted Log (tail)</h2>
        <pre><code class='text'>$logEscaped</code></pre>
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
"@

    try {
        Set-Content -Path $HtmlReportResolved -Value $report -Encoding UTF8
        Write-Output ("[Info] HTML report saved: {0}" -f $HtmlReportResolved)
    } catch {
        Write-Output ("[WARN] Failed to write HTML report: {0}" -f $_)
    }
}

exit 0
