#Requires -Version 5.1
# ============================================================
#  Dejavu Security Baseline Checker v2.0.0
#  PowerShell Edition — Windows 10/11 / PowerShell 5.1+
# ============================================================

# Handle parameter parsing for -- format
$argsParsed = @{}
for ($i = 0; $i -lt $args.Count; $i++) {
    $arg = $args[$i]
    if ($arg -match '^--(\w+)$') {
        $paramName = $matches[1]
        if ($i + 1 -lt $args.Count -and $args[$i + 1] -notmatch '^--') {
            $argsParsed[$paramName] = $args[$i + 1]
            $i++
        } else {
            $argsParsed[$paramName] = $true
        }
    }
}

# Set parameters from parsed arguments
$dir = if ($argsParsed.ContainsKey('dir')) { $argsParsed['dir'] } else { "" }
$checks = if ($argsParsed.ContainsKey('checks')) { $argsParsed['checks'] } else { "all" }
$output = if ($argsParsed.ContainsKey('output')) { $argsParsed['output'] } else { "json" }
$report = if ($argsParsed.ContainsKey('report')) { $argsParsed['report'] } else { "" }
$fix = $argsParsed.ContainsKey('fix')
$runtime = $argsParsed.ContainsKey('runtime')
$port = if ($argsParsed.ContainsKey('port')) { [int]$argsParsed['port'] } else { 18789 }
$showdetails = $argsParsed.ContainsKey('showdetails')
$help = $argsParsed.ContainsKey('help')

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ================================================================
#  Global Variables
# ================================================================
$Script:DEJAVU_VERSION  = "2.0.0"
$Script:TIMESTAMP      = Get-Date -Format "yyyyMMdd_HHmmss"
$Script:REPORT_DIR     = Join-Path $PSScriptRoot "output"
$Script:REPORT_FILE    = if ($report) { $report } else {
                           $ext = if ($output -eq 'json') { 'json' } else { 'md' }
                           Join-Path $Script:REPORT_DIR "dejavu_report_$($Script:TIMESTAMP).$ext"
                         }
$Script:OPENCLAW_DIR   = $dir
$Script:FIX_MODE       = $fix
$Script:VERBOSE_MODE   = $showdetails -or ($PSBoundParameters.ContainsKey('Verbose'))
$Script:RUNTIME_CHECK  = $runtime
$Script:GATEWAY_PORT   = $port
$Script:BROWSER_PORT   = 18791

$Script:TotalChecks  = 0
$Script:PassedChecks = 0
$Script:Findings     = [System.Collections.Generic.List[PSObject]]::new()
$Script:ModuleDeductions = @{
    config  = 0; skills  = 0; network = 0
    proxy   = 0; runtime = 0; auth    = 0; deps = 0
    hostaudit = 0; dlp = 0
}
$Script:CurrentModule = "unknown"

# ================================================================
#  Color Output Functions
# ================================================================
function Write-ColorLine {
    param([string]$Text, [string]$Color = "White", [switch]$NoNewline)
    $params = @{ ForegroundColor = $Color; Object = $Text }
    if ($NoNewline) { $params['NoNewline'] = $true }
    Write-Host @params
}

function Write-Finding {
    param(
        [ValidateSet('CRITICAL','HIGH','MEDIUM','LOW','PASS','SKIP','INFO')]
        [string]$Severity,
        [string]$CheckId,
        [string]$Description,
        [string]$Detail = ""
    )
    $icon = switch ($Severity) {
        'CRITICAL' { "[CRIT]" }
        'HIGH'     { "[HIGH]" }
        'MEDIUM'   { "[MEDI]" }
        'LOW'      { "[LOW] " }
        'PASS'     { "[PASS]" }
        'SKIP'     { "[SKIP]" }
        'INFO'     { "[INFO]" }
    }
    $color = switch ($Severity) {
        'CRITICAL' { "Red"     }
        'HIGH'     { "Red"     }
        'MEDIUM'   { "Yellow"  }
        'LOW'      { "Cyan"    }
        'PASS'     { "Green"   }
        'SKIP'     { "Gray"    }
        'INFO'     { "Cyan"    }
    }
    Write-ColorLine "$icon [$CheckId] $Description" $color
    if ($Detail -and $Script:VERBOSE_MODE) {
        Write-ColorLine "       $Detail" "Gray"
    }
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-ColorLine "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" "Cyan"
    Write-ColorLine "  $Title" "Cyan"
    Write-ColorLine "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" "Cyan"
}

function Write-FixHint {
    param([string]$Command)
    if ($Script:FIX_MODE) {
        Write-ColorLine "         FIX: $Command" "Green"
    }
}

# ================================================================
#  Scoring Functions
# ================================================================
function Add-Finding {
    param(
        [string]$CheckId,
        [string]$Severity,
        [string]$Description,
        [string]$Remediation = "N/A"
    )
    $Script:TotalChecks++
    $deductMap = @{CRITICAL=25; HIGH=15; MEDIUM=8; LOW=3; PASS=0; SKIP=0; INFO=0}
    $deduct = $deductMap[$Severity]
    if ($null -ne $deduct) {
        $Script:ModuleDeductions[$Script:CurrentModule] += $deduct
    }
    if ($Severity -eq "PASS") { $Script:PassedChecks++ }

    $finding = [PSCustomObject]@{
        CheckId     = $CheckId
        Severity    = $Severity
        Description = $Description
        Remediation = $Remediation
        Module      = $Script:CurrentModule
    }
    $Script:Findings.Add($finding)
}

function Get-ModuleScore {
    param([string]$Module)
    $deduction = $Script:ModuleDeductions[$Module]
    return [Math]::Max(0, 100 - ($deduction * 3))
}

function Get-OverallScore {
    # Bug Fix #30: Include hostaudit(3) and dlp(2) in weights to ensure these modules' deductions count toward total
    # Bug Fix #31: Fix comment - all 9 module weights sum to 100, divide by $weightSum for normalization
    $weights = @{ config=15; skills=20; network=20; proxy=15; runtime=10; auth=5; deps=10; hostaudit=3; dlp=2 }
    $total = 0
    $weightSum = 0
    foreach ($m in $weights.Keys) {
        $total += (Get-ModuleScore $m) * $weights[$m]
        $weightSum += $weights[$m]
    }
    return [Math]::Max(0, [int]($total / $weightSum))
}

function Get-ScoreBar {
    param([int]$Score, [int]$Width = 20)
    $filled = [int]($Score * $Width / 100)
    $bar  = [string]::new([char]9608, $filled)
    $bar += [string]::new([char]9617, ($Width - $filled))
    return $bar
}

function Get-RiskLevel {
    param([int]$Score)
    if ($Score -ge 90) { return "LOW RISK" }
    elseif ($Score -ge 70) { return "MEDIUM RISK" }
    elseif ($Score -ge 50) { return "HIGH RISK" }
    else { return "CRITICAL RISK" }
}

# ================================================================
#  openclaw.json Parsing
# ================================================================
function Get-OpenClawConfig {
    $candidates = @(
        (Join-Path $Script:OPENCLAW_DIR "openclaw.json"),
        (Join-Path $Script:OPENCLAW_DIR "config\openclaw.json")
    )
    foreach ($path in $candidates) {
        if (Test-Path $path) {
            $Script:OPENCLAW_CONFIG_PATH = $path
            try {
                $raw = Get-Content $path -Raw -Encoding UTF8
                # Bug Fix #1: Use negative lookbehind to avoid accidentally removing :// from URLs (e.g. http://localhost)
                $clean = $raw -replace '(?<![:/])//[^\n]*', ''
                $clean = $clean -replace '/\*[\s\S]*?\*/', ''
                $clean = $clean -replace ',(\s*[}\]])', '$1'
                return $clean | ConvertFrom-Json
            } catch {
                Write-Warning "Failed to parse ${path}: $_"
                return $null
            }
        }
    }
    return $null
}

function Get-ConfigValue {
    param($Config, [string]$Path)
    if ($null -eq $Config) { return $null }
    $parts = $Path -split '\.'
    $current = $Config
    foreach ($part in $parts) {
        if ($null -eq $current) { return $null }
        try { $current = $current.$part } catch { return $null }
    }
    return $current
}

# ================================================================
#  MODULE C: Configuration File Security (Windows)
# ================================================================

# Safe recursive file enumeration that skips large directories like node_modules/.git
function Get-SafeConfigFiles {
    param([string]$RootPath)
    $excludeDirs = @('node_modules', '.git', 'dist', 'build', '.next', 'coverage', '.pnpm')
    $includeExts = @('.md', '.json', '.yaml', '.yml', '.env')
    try {
        Get-ChildItem -Path $RootPath -File -ErrorAction SilentlyContinue |
            # Bug Fix #26: 同时匹配扩展名列表及 .env* 文件名（捕获 .env.local、.env.production 等）
            Where-Object { $includeExts -contains $_.Extension -or $_.Name -match '^\.env' }
        Get-ChildItem -Path $RootPath -Directory -ErrorAction SilentlyContinue |
            Where-Object { $excludeDirs -notcontains $_.Name } |
            ForEach-Object { Get-SafeConfigFiles $_.FullName }
    } catch { }
}

function Invoke-ConfigChecks {
    $Script:CurrentModule = "config"
    Write-Section "[config] Configuration File Security"

    $cfg = Get-OpenClawConfig

    # C1.1 Hardcoded API credentials
    $secretPatterns = @(
        'sk-[a-zA-Z0-9]{20,}',
        'sk-ant-[a-zA-Z0-9\-]{20,}',
        'sk-proj-[a-zA-Z0-9\-]{20,}',
        'AIza[0-9A-Za-z\-_]{35}',
        'ghp_[a-zA-Z0-9]{36}',
        'Bearer\s+[a-zA-Z0-9\-_\.]{40,}',
        'AKIA[0-9A-Z]{16}'
    )
    $configFiles = @(Get-SafeConfigFiles $Script:OPENCLAW_DIR)

    $secretFound = $false
    foreach ($file in $configFiles) {
        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $content) { continue }
        foreach ($pattern in $secretPatterns) {
            if ($content -match $pattern) {
                $secretFound = $true
                Write-Finding "CRITICAL" "C1.1" "Hardcoded secret in: $($file.Name)"
                Add-Finding "C1.1" "CRITICAL" "Hardcoded secret in $($file.Name)" `
                    "Move secrets to environment variables or Windows Credential Manager"
                break  # Report only one per file, continue checking other files
            }
        }
        # Bug Fix #21: Remove outer break to ensure every file containing secrets is detected
    }
    if (-not $secretFound) {
        Write-Finding "PASS" "C1.1" "No hardcoded API keys or secrets detected ✓"
        Add-Finding "C1.1" "PASS" "No hardcoded secrets" ""
    }

    # C1.2 SOUL.md prompt injection detection
    $soulFiles = @(Get-SafeConfigFiles $Script:OPENCLAW_DIR | Where-Object { $_.Name -eq 'SOUL.md' })
    if ($soulFiles) {
        $dangerPatterns = @(
            'ignore.*previous.*instruction','disregard.*safety',
            'you are now','jailbreak','DAN mode',
            'no restriction','sudo mode','bypass.*security',
            'admin.*privilege','unrestricted','forget.*guidelines'
        )
        $soulDanger = $false
        foreach ($soul in $soulFiles) {
            $soulContent = Get-Content $soul.FullName -Raw -ErrorAction SilentlyContinue
            if (-not $soulContent) { continue }
            foreach ($pat in $dangerPatterns) {
                if ($soulContent -imatch $pat) {
                    $soulDanger = $true
                    Write-Finding "HIGH" "C1.2" "Privilege escalation pattern in SOUL.md" `
                                  "Pattern: $pat"
                    Add-Finding "C1.2" "HIGH" "Prompt injection in SOUL.md" `
                        "Remove instructions attempting to bypass agent safety constraints"
                    break
                }
            }
            if ($soulDanger) { break }
        }
        if (-not $soulDanger) {
            Write-Finding "PASS" "C1.2" "SOUL.md has no privilege escalation patterns ✓"
            Add-Finding "C1.2" "PASS" "SOUL.md clean" ""
        }
    } else {
        Write-Finding "SKIP" "C1.2" "No SOUL.md found — skipping"
        Add-Finding "C1.2" "SKIP" "No SOUL.md in target directory" ""
    }

    # C1.3 openclaw.json JSON parseability check
    $cfgPath = Join-Path $Script:OPENCLAW_DIR "openclaw.json"
    if (-not (Test-Path $cfgPath)) {
        $cfgPath = Join-Path $Script:OPENCLAW_DIR "config\openclaw.json"
    }
    if (Test-Path $cfgPath) {
        try {
            $null = Get-Content $cfgPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            Write-Finding "PASS" "C1.3" "openclaw.json parses successfully ✓"
            Add-Finding "C1.3" "PASS" "Config parseable" ""
        } catch {
            $errMsg = $_.Exception.Message -replace "`r`n|`n", " "
            Write-Finding "HIGH" "C1.3" "openclaw.json has JSON parse error: $errMsg"
            Add-Finding "C1.3" "HIGH" "openclaw.json parse error" `
                "Fix JSON syntax errors (check for trailing commas, unquoted keys)"
        }
    } else {
        Write-Finding "HIGH" "C1.3" "openclaw.json not found in $Script:OPENCLAW_DIR"
        Add-Finding "C1.3" "HIGH" "openclaw.json missing" `
            "Run 'openclaw init' to create default config, or check --dir path"
    }

    # C1.4 File ACL check (not world-writable)
    $aclIssues = $false
    foreach ($file in $configFiles | Select-Object -First 50) {
        try {
            $acl = Get-Acl $file.FullName
            $everyoneAccess = $acl.Access | Where-Object {
                $entry = $_
                # Bug Fix #28: Use SID to identify Everyone(S-1-1-0) and BUILTIN\Users(S-1-5-32-545)
                # Avoid missing BUILTIN\Users due to localized names on non-English Windows
                $isPublic = $false
                try {
                    $sid = $entry.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                    $isPublic = ($sid -eq 'S-1-1-0' -or $sid -eq 'S-1-5-32-545')
                } catch {
                    $isPublic = ($entry.IdentityReference -match 'Everyone|BUILTIN\\Users')
                }
                $isPublic -and
                $entry.FileSystemRights -match "Write|FullControl" -and
                $entry.AccessControlType -eq "Allow"
            }
            if ($everyoneAccess) {
                $aclIssues = $true
                Write-Finding "MEDIUM" "C1.4" "World-writable config file: $($file.Name)"
                Add-Finding "C1.4" "MEDIUM" "World-writable config file: $($file.Name)" `
                    "Run: icacls `"$($file.FullName)`" /remove `"Everyone`""
                Write-FixHint "icacls `"$($file.FullName)`" /remove `"Everyone`""
            }
        } catch { }
    }
    if (-not $aclIssues) {
        Write-Finding "PASS" "C1.4" "No world-writable config files found ✓"
        Add-Finding "C1.4" "PASS" "File permissions OK" ""
    }

    # C1.5 openclaw.json NTFS 权限检查（仅限当前用户可读）
    $ocJsonPath = $cfgPath  # 复用 C1.3 解析出的路径
    if (Test-Path $ocJsonPath) {
        try {
            $acl = Get-Acl $ocJsonPath -ErrorAction Stop
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            $othersWritable = $acl.Access | Where-Object {
                $entry = $_
                $isOther = $false
                try {
                    $sid = $entry.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                    # Exclude current user and SYSTEM/Administrators
                    $isOwnerOrSystem = ($sid -eq 'S-1-5-18' -or $sid -match '^S-1-5-32-544')
                    $isOther = -not $isOwnerOrSystem
                } catch {
                    $isOther = ($entry.IdentityReference -notmatch [regex]::Escape($currentUser) -and
                                $entry.IdentityReference -notmatch 'SYSTEM|Administrators|CREATOR')
                }
                $isOther -and
                $entry.FileSystemRights -match 'Read|FullControl' -and
                $entry.AccessControlType -eq 'Allow'
            }
            if (@($othersWritable).Count -gt 0) {
                Write-Finding "MEDIUM" "C1.5" "openclaw.json is readable by other accounts — tokens may be exposed"
                Add-Finding "C1.5" "MEDIUM" "openclaw.json readable by others" `
                    "Restrict with: icacls `"$ocJsonPath`" /inheritance:r /grant `"${currentUser}:(R)`""
            } else {
                Write-Finding "PASS" "C1.5" "openclaw.json access restricted to owner/system ✓"
                Add-Finding "C1.5" "PASS" "Config file permissions OK" ""
            }
        } catch {
            Write-Finding "SKIP" "C1.5" "Cannot read ACL for openclaw.json — skipping permission check"
            Add-Finding "C1.5" "SKIP" "ACL check failed" ""
        }
    } else {
        Write-Finding "SKIP" "C1.5" "openclaw.json not found — skipping permission check"
        Add-Finding "C1.5" "SKIP" "Config not found" ""
    }

    # C1.6 Dangerous configuration flags
    if ($null -ne $cfg) {
        $dangerFlags = @('allowAll','disableSafety','skipVerification','bypassAuth','devMode','insecure')
        $flagFound = $false
        foreach ($flag in $dangerFlags) {
            $val = Get-ConfigValue $cfg $flag
            if ($val -eq $true) {
                Write-Finding "HIGH" "C1.6" "Dangerous flag: $flag=true"
                Add-Finding "C1.6" "HIGH" "Dangerous flag: $flag=true" `
                    "Set $flag to false or remove from config"
                $flagFound = $true
            }
        }
        if (-not $flagFound) {
            Write-Finding "PASS" "C1.6" "No dangerous configuration flags detected ✓"
            Add-Finding "C1.6" "PASS" "No dangerous flags" ""
        }
    } else {
        Write-Finding "SKIP" "C1.6" "Dangerous flag check skipped — no openclaw.json found"
        Add-Finding "C1.6" "SKIP" "Dangerous flag check skipped (no config)" ""
    }

    # C1.7 AGENTS.md high-risk instruction scan
    $agentsFiles = @(Get-SafeConfigFiles $Script:OPENCLAW_DIR | Where-Object { $_.Name -eq 'AGENTS.md' })
    if ($agentsFiles.Count -gt 0) {
        $agentRiskPatterns = @(
            'run.*as.*admin','runas.*administrator',
            'bypass.*uac','disable.*defender','disable.*antivirus',
            'curl.*\|\s*iex','iwr.*\|\s*iex','invoke-expression.*http',
            'rm\s+-rf\s+[/\\]','del\s+\/[sf]',
            'net\s+user.*\/add','net\s+localgroup.*administrators',
            'reg\s+add.*run','schtasks.*\/create'
        )
        $agentRisk = $false
        foreach ($af in $agentsFiles) {
            $ac = Get-Content $af.FullName -Raw -ErrorAction SilentlyContinue
            if (-not $ac) { continue }
            foreach ($pat in $agentRiskPatterns) {
                if ($ac -imatch $pat) {
                    Write-Finding "HIGH" "C1.7" "High-risk instruction in AGENTS.md: '$pat'"
                    Add-Finding "C1.7" "HIGH" "Dangerous agent instruction in AGENTS.md" `
                        "Review and remove high-risk shell commands from AGENTS.md"
                    $agentRisk = $true
                    break
                }
            }
            if ($agentRisk) { break }
        }
        if (-not $agentRisk) {
            Write-Finding "PASS" "C1.7" "AGENTS.md has no high-risk instructions ✓"
            Add-Finding "C1.7" "PASS" "AGENTS.md clean" ""
        }
    } else {
        Write-Finding "SKIP" "C1.7" "No AGENTS.md found — skipping"
        Add-Finding "C1.7" "SKIP" "No AGENTS.md in target directory" ""
    }
}

# ================================================================
#  MODULE N: Network Exposure Checks (Windows)
# ================================================================
function Invoke-NetworkChecks {
    $Script:CurrentModule = "network"
    Write-Section "[network] Network Exposure Analysis"

    # N3.1 Gateway port binding
    $gatewayListeners = Get-NetTCPConnection -LocalPort $Script:GATEWAY_PORT `
                        -State Listen -ErrorAction SilentlyContinue
    if ($gatewayListeners) {
        $publicBinding = $gatewayListeners | Where-Object {
            $_.LocalAddress -eq "0.0.0.0" -or $_.LocalAddress -eq "::"
        }
        if ($publicBinding) {
            Write-Finding "CRITICAL" "N3.1" `
                "Gateway port $($Script:GATEWAY_PORT) bound to ALL interfaces (0.0.0.0)"
            Add-Finding "N3.1" "CRITICAL" `
                "Gateway port exposed on all interfaces" `
                'Set "bind": "loopback" in openclaw.json gateway config'
            Write-FixHint 'openclaw.json: "gateway": {"bind": "loopback"}'
        } else {
            Write-Finding "PASS" "N3.1" "Gateway port $($Script:GATEWAY_PORT) on loopback only ✓"
            Add-Finding "N3.1" "PASS" "Gateway port loopback only" ""
        }
    } else {
        Write-Finding "PASS" "N3.1" "Gateway port $($Script:GATEWAY_PORT) not listening"
        Add-Finding "N3.1" "PASS" "Gateway port not active" ""
    }

    # N3.2 Browser control port
    $browserListeners = Get-NetTCPConnection -LocalPort $Script:BROWSER_PORT `
                        -State Listen -ErrorAction SilentlyContinue
    if ($browserListeners) {
        $publicBrowser = $browserListeners | Where-Object {
            $_.LocalAddress -eq "0.0.0.0" -or $_.LocalAddress -eq "::"
        }
        if ($publicBrowser) {
            Write-Finding "CRITICAL" "N3.2" `
                "Browser control port $($Script:BROWSER_PORT) exposed on all interfaces"
            Add-Finding "N3.2" "CRITICAL" `
                "Browser control port publicly exposed" `
                "Bind browser control port to 127.0.0.1 only"
        } else {
            Write-Finding "PASS" "N3.2" "Browser control port on loopback only ✓"
            Add-Finding "N3.2" "PASS" "Browser port loopback only" ""
        }
    } else {
        Write-Finding "PASS" "N3.2" "Browser control port $($Script:BROWSER_PORT) not listening"
        Add-Finding "N3.2" "PASS" "Browser port not active" ""
    }

    # N3.3 Check if other services are exposed on 0.0.0.0 (excluding openclaw checked ports and well-known ports)
    $ocPorts = @($Script:GATEWAY_PORT, $Script:BROWSER_PORT, 18792, 18793, 18794, 18795)
    $allListeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalAddress -eq '0.0.0.0' -or $_.LocalAddress -eq '::' })
    $extraExposed = @($allListeners | Where-Object {
        $p = $_.LocalPort
        $p -gt 1024 -and $ocPorts -notcontains $p
    } | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object)
    if ($extraExposed.Count -gt 0) {
        Write-Finding "MEDIUM" "N3.3" "Other services exposed on all interfaces: ports $($extraExposed -join ', ')"
        Add-Finding "N3.3" "MEDIUM" "Additional exposed ports: $($extraExposed -join ', ')" `
            "Bind unneeded services to loopback or firewall them; reduce attack surface"
    } else {
        Write-Finding "PASS" "N3.3" "No unexpected services exposed on all interfaces ✓"
        Add-Finding "N3.3" "PASS" "No additional exposed services" ""
    }

    # N3.4 TLS 配置检查
    $cfgN = Get-OpenClawConfig
    if ($null -ne $cfgN) {
        $tlsEnabled = Get-ConfigValue $cfgN "gateway.tls.enabled"
        $bindVal    = Get-ConfigValue $cfgN "gateway.bind"
        if ($tlsEnabled -eq $true) {
            Write-Finding "PASS" "N3.4" "TLS is enabled on gateway ✓"
            Add-Finding "N3.4" "PASS" "TLS enabled" ""
        } elseif ($bindVal -eq 'loopback' -or $bindVal -eq 'localhost' -or $bindVal -eq '127.0.0.1') {
            Write-Finding "LOW" "N3.4" "TLS not configured — acceptable for loopback-only deployment"
            Add-Finding "N3.4" "LOW" "No TLS (loopback only)" `
                "Consider TLS or HTTPS reverse proxy if exposing over LAN/WAN"
        } else {
            Write-Finding "MEDIUM" "N3.4" "TLS not enabled — gateway is HTTP only (acceptable if behind TLS-terminating proxy)"
            Add-Finding "N3.4" "MEDIUM" "No TLS on gateway" `
                "Enable gateway.tls or place behind an HTTPS reverse proxy"
        }
    } else {
        Write-Finding "SKIP" "N3.4" "TLS check skipped — openclaw.json not found"
        Add-Finding "N3.4" "SKIP" "TLS check skipped (no config)" ""
    }

    # N3.6 Windows Firewall rules
    # Bug Fix #51: Calling Get-NetFirewallPortFilter per rule is O(n) WMI calls, which can take several minutes when there are many rules.
    # Use Start-Job + 12 second timeout: timeout results in SKIP to prevent the entire scan from hanging.
    $gPort = "$($Script:GATEWAY_PORT)"; $bPort = "$($Script:BROWSER_PORT)"
    $fwJob = Start-Job -ScriptBlock {
        param($gPort, $bPort)
        $results = @()
        # Use -Enabled True parameter directly, skip Where-Object filtering
        $rules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True `
                     -ErrorAction SilentlyContinue
        foreach ($r in $rules) {
            try {
                $pf = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                # Bug Fix #32: LocalPort returns string, need to convert int port to string for comparison
                if ($pf -and ($pf.LocalPort -contains $gPort -or
                              $pf.LocalPort -contains $bPort)) {
                    $results += "$($pf.LocalPort) (Rule: $($r.DisplayName))"
                }
            } catch { }
        }
        return $results
    } -ArgumentList $gPort, $bPort

    $null = Wait-Job -Job $fwJob -Timeout 12
    $exposedPorts = @()
    if ($fwJob.State -eq "Completed") {
        $exposedPorts = @(Receive-Job -Job $fwJob -ErrorAction SilentlyContinue |
                          Where-Object { $_ })
        if ($exposedPorts.Count -gt 0) {
            Write-Finding "HIGH" "N3.6" `
                "Windows Firewall allows inbound on OpenClaw ports: $($exposedPorts -join ', ')"
            Add-Finding "N3.6" "HIGH" `
                "Firewall exposes OpenClaw ports" `
                "Remove or restrict the firewall rules for ports $Script:GATEWAY_PORT/$Script:BROWSER_PORT"
        } else {
            Write-Finding "PASS" "N3.6" "No inbound firewall rules expose OpenClaw ports ✓"
            Add-Finding "N3.6" "PASS" "Firewall rules OK" ""
        }
    } else {
        Stop-Job  -Job $fwJob -ErrorAction SilentlyContinue
        Write-Finding "SKIP" "N3.6" `
            "Firewall rule scan timed out (>12 s) — re-run with fewer active rules"
        Add-Finding "N3.6" "SKIP" "Firewall check timed out" ""
    }
    Remove-Job -Job $fwJob -Force -ErrorAction SilentlyContinue

    # N3.5 CORS check (read from config file)
    $cfg = Get-OpenClawConfig
    if ($null -ne $cfg) {
        $corsOrigins = Get-ConfigValue $cfg "gateway.cors.origins"
        if ($null -ne $corsOrigins) {
            # Bug Fix #17: Use exact matching instead of substring -match '\*|all' to avoid false positives for domains like wall.example.com
            $isWildcardCors = $false
            if ($corsOrigins -is [array]) {
                $isWildcardCors = ($corsOrigins -contains '*') -or ($corsOrigins -contains 'all')
            } else {
                $corsStr = "$corsOrigins".Trim()
                $isWildcardCors = ($corsStr -eq '*' -or $corsStr -eq 'all')
            }
            if ($isWildcardCors) {
                Write-Finding "HIGH" "N3.5" "CORS wildcard '*' — any website can make requests to gateway"
                Add-Finding "N3.5" "HIGH" "CORS wildcard" `
                    "Restrict CORS origins to specific trusted domains"
            } else {
                Write-Finding "PASS" "N3.5" "CORS configured with specific origins ✓"
                Add-Finding "N3.5" "PASS" "CORS config OK" ""
            }
        } else {
            # Bug Fix #4: config exists but CORS not configured, provide hint
            Write-Finding "INFO" "N3.5" "CORS not configured in openclaw.json (may be handled by reverse proxy)"
            Add-Finding "N3.5" "INFO" "CORS not configured in openclaw.json" ""
        }
    } else {
        # Bug Fix #4: When config file cannot be parsed, treat as SKIP
        Write-Finding "SKIP" "N3.5" "CORS check skipped — openclaw.json not found or parse error"
        Add-Finding "N3.5" "SKIP" "CORS check skipped (no config)" ""
    }
}

# ================================================================
#  MODULE A: Authentication Strength Check (Windows)
# ================================================================
function Invoke-AuthChecks {
    $Script:CurrentModule = "auth"
    Write-Section "[auth] Authentication Strength Analysis"

    $cfg = Get-OpenClawConfig
    if ($null -eq $cfg) {
        Write-Finding "HIGH" "A6.0" "Failed to parse openclaw.json — skipping auth checks"
        Add-Finding "A6.0" "HIGH" "openclaw.json not found or parse error" `
            "Create openclaw.json in the target directory or run: node openclaw.mjs init"
        return
    }

    # A6.1 Token length >= 40 hex chars
    $token = Get-ConfigValue $cfg "gateway.auth.token"
    if (-not $token) { $token = Get-ConfigValue $cfg "gateway.token" }

    if ($token -and $token -match '^[0-9a-fA-F]{40,}$') {
        Write-Finding "PASS" "A6.1" "Auth token meets entropy requirements (>=40 hex chars) ✓"
        Add-Finding "A6.1" "PASS" "Token entropy OK" ""
    } elseif ($token) {
        Write-Finding "CRITICAL" "A6.1" "Auth token too short or non-hex (len=$($token.Length))"
        Add-Finding "A6.1" "CRITICAL" "Weak auth token" "Run: node openclaw.mjs token reset"
        Write-FixHint "node openclaw.mjs token reset"
    } else {
        Write-Finding "HIGH" "A6.1" "No auth token configured — unauthenticated access possible"
        Add-Finding "A6.1" "HIGH" "No auth token" "Set auth.token in openclaw.json"
    }

    # A6.2 Weak token pattern detection
    if ($token) {
        $weakPatterns = @('0{10,}','1{10,}','f{10,}','deadbeef','cafebabe','test','demo','admin','password')
        $isWeak = $false
        foreach ($p in $weakPatterns) {
            if ($token -match $p) { $isWeak = $true; break }
        }
        if ($isWeak) {
            Write-Finding "CRITICAL" "A6.2" "Auth token matches known-weak pattern"
            Add-Finding "A6.2" "CRITICAL" "Weak token pattern" "Regenerate token immediately"
            Write-FixHint "node openclaw.mjs token reset"
        } else {
            Write-Finding "PASS" "A6.2" "Token passes weak-pattern check ✓"
            Add-Finding "A6.2" "PASS" "No weak token pattern" ""
        }
    } else {
        Write-Finding "SKIP" "A6.2" "Weak-pattern check skipped — no token configured"
        Add-Finding "A6.2" "SKIP" "Weak-pattern check skipped (no token)" ""
    }

    # A6.3 auth.mode check
    $authMode = Get-ConfigValue $cfg "gateway.auth.mode"
    if (-not $authMode) { $authMode = Get-ConfigValue $cfg "auth.mode" }
    if ($authMode -eq 'none' -or $authMode -eq 'open') {
        Write-Finding "CRITICAL" "A6.3" "auth.mode='$authMode' — no authentication required!"
        Add-Finding "A6.3" "CRITICAL" "Auth disabled" 'Set "mode": "token" in auth config'
    } elseif ($authMode -eq 'token') {
        Write-Finding "PASS" "A6.3" "auth.mode='token' ✓"
        Add-Finding "A6.3" "PASS" "Auth mode OK" ""
    } elseif ($null -eq $authMode -or $authMode -eq '') {
        # Bug Fix #22: When auth.mode is not configured, should be MEDIUM instead of falling into else INFO showing empty string
        Write-Finding "MEDIUM" "A6.3" "auth.mode not configured — authentication mode unset"
        Add-Finding "A6.3" "MEDIUM" "auth.mode not set" 'Add "mode": "token" to gateway.auth in openclaw.json'
    } else {
        Write-Finding "INFO" "A6.3" "auth.mode='$authMode' — verify this is intentional"
        Add-Finding "A6.3" "INFO" "Non-standard auth mode: $authMode" ""
    }

    # A6.4 Token rotation policy check
    $rotationFound = $false
    # Check if token rotation is configured in scheduled tasks or YAML/scripts
    $rotationTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.TaskName -imatch 'openclaw.*token|token.*rotate|rotate.*token' })
    if ($rotationTasks.Count -gt 0) { $rotationFound = $true }

    if (-not $rotationFound) {
        $yamlFiles = @(Get-ChildItem -Path $Script:OPENCLAW_DIR -Recurse -Include '*.yml','*.yaml' `
            -Depth 4 -ErrorAction SilentlyContinue)
        foreach ($yf in $yamlFiles) {
            $yc = Get-Content $yf.FullName -Raw -ErrorAction SilentlyContinue
            if ($yc -imatch 'rotate.*token|token.*rotate|token.*expir') {
                $rotationFound = $true; break
            }
        }
    }

    if ($rotationFound) {
        Write-Finding "PASS" "A6.4" "Token rotation policy detected ✓"
        Add-Finding "A6.4" "PASS" "Token rotation OK" ""
    } else {
        Write-Finding "LOW" "A6.4" "No token rotation policy detected — static tokens increase exposure window"
        Add-Finding "A6.4" "LOW" "No token rotation" `
            "Set up periodic token rotation (monthly recommended); use Task Scheduler or CI pipeline"
    }

    # A6.5 Rate limiting
    $rateLimit = Get-ConfigValue $cfg "gateway.rateLimit"
    if ($null -eq $rateLimit -or $rateLimit -eq $false) {
        Write-Finding "MEDIUM" "A6.5" "No rate limiting configured on gateway"
        Add-Finding "A6.5" "MEDIUM" "No rate limiting" `
            "Enable rateLimit in gateway config or use nginx rate limiting upstream"
    } else {
        Write-Finding "PASS" "A6.5" "Rate limiting is configured ✓"
        Add-Finding "A6.5" "PASS" "Rate limiting OK" ""
    }
}

# ================================================================
#  MODULE D: Dependency Vulnerability Scan (Windows)
# ================================================================
function Invoke-DepsChecks {
    $Script:CurrentModule = "deps"
    Write-Section "[deps] Dependency Vulnerability Scan"

    # D7.1 npm / pnpm audit
    $pkgJsonPath  = Join-Path $Script:OPENCLAW_DIR "package.json"
    $pnpmLockPath = Join-Path $Script:OPENCLAW_DIR "pnpm-lock.yaml"
    # Fallback: search openclaw global npm install location
    if (-not (Test-Path $pkgJsonPath)) {
        # 1. Priority: user manually specifies via $env:OPENCLAW_PKG_JSON
        if ($env:OPENCLAW_PKG_JSON -and (Test-Path $env:OPENCLAW_PKG_JSON)) {
            $pkgJsonPath  = $env:OPENCLAW_PKG_JSON
            $pnpmLockPath = Join-Path (Split-Path $pkgJsonPath) "pnpm-lock.yaml"
        } else {
            $npmRoot = $null
            try { $npmRoot = (& npm root -g 2>$null) } catch {}
            $fallbackPaths = @(
                if ($npmRoot) { "$npmRoot\openclaw" },
                "$env:APPDATA\npm\node_modules\openclaw",
                "$env:ProgramFiles\nodejs\node_modules\openclaw",
                "/usr/lib/node_modules/openclaw",
                "/usr/local/lib/node_modules/openclaw"
            )
            foreach ($loc in $fallbackPaths) {
                if ($loc -and (Test-Path (Join-Path $loc "package.json"))) {
                    $pkgJsonPath  = Join-Path $loc "package.json"
                    $pnpmLockPath = Join-Path $loc "pnpm-lock.yaml"
                    break
                }
            }
        }
    }
    if (Test-Path $pkgJsonPath) {
        # Priority: use pnpm audit (for pnpm projects)
        $usesPnpm  = Test-Path $pnpmLockPath
        $auditTool = if ($usesPnpm -and (Get-Command "pnpm" -ErrorAction SilentlyContinue)) { "pnpm" } else { "npm" }
        try {
            # Push-Location to target directory before running audit
            $auditJson = $null
            Push-Location $Script:OPENCLAW_DIR
            try { $auditJson = & $auditTool audit --json 2>$null }
            finally { Pop-Location }
            if ($auditJson) {
                $auditResult = $auditJson | ConvertFrom-Json -ErrorAction SilentlyContinue
                # 1) audit returns error object (e.g. network unavailable)
                if ($null -ne $auditResult -and
                    $null -ne $auditResult.PSObject.Properties['error']) {
                    $errCode = if ($auditResult.error.PSObject.Properties['code']) { $auditResult.error.code } else { "UNKNOWN" }
                    Write-Finding "SKIP" "D7.1" "${auditTool} audit skipped: $errCode (network unavailable or registry unreachable)"
                    Add-Finding "D7.1" "SKIP" "${auditTool} audit skipped: $errCode" "Ensure network access to npm registry and retry"
                # 2) audit v1 format: contains metadata.vulnerabilities
                } elseif ($null -ne $auditResult -and
                          $null -ne $auditResult.PSObject.Properties['metadata']) {
                    $vulnMeta = $auditResult.metadata.vulnerabilities
                    $critCount = if ($vulnMeta.PSObject.Properties['critical']) { [int]$vulnMeta.critical } else { 0 }
                    $highCount = if ($vulnMeta.PSObject.Properties['high'])     { [int]$vulnMeta.high     } else { 0 }
                    if ($critCount -gt 0) {
                        Write-Finding "CRITICAL" "D7.1" "${auditTool} audit: $critCount critical vulnerabilities"
                        Add-Finding "D7.1" "CRITICAL" "$critCount critical npm vulns" "Run: $auditTool audit fix"
                        Write-FixHint "$auditTool audit fix --force"
                    } elseif ($highCount -gt 0) {
                        Write-Finding "HIGH" "D7.1" "${auditTool} audit: $highCount high-severity vulnerabilities"
                        Add-Finding "D7.1" "HIGH" "$highCount high npm vulns" "Run: $auditTool audit fix"
                    } else {
                        Write-Finding "PASS" "D7.1" "${auditTool} audit: no high/critical vulnerabilities ✓"
                        Add-Finding "D7.1" "PASS" "No high/critical npm vulns" ""
                    }
                # 3) audit report v2 format (npm 7+): contains vulnerabilities object
                } elseif ($null -ne $auditResult -and
                          $null -ne $auditResult.PSObject.Properties['vulnerabilities']) {
                    $critCount = 0; $highCount = 0
                    $auditResult.vulnerabilities.PSObject.Properties | ForEach-Object {
                        $sev = $_.Value.severity
                        if ($sev -eq 'critical') { $critCount++ }
                        elseif ($sev -eq 'high')  { $highCount++ }
                    }
                    if ($critCount -gt 0) {
                        Write-Finding "CRITICAL" "D7.1" "${auditTool} audit: $critCount critical vulnerabilities"
                        Add-Finding "D7.1" "CRITICAL" "$critCount critical npm vulns" "Run: $auditTool audit fix"
                        Write-FixHint "$auditTool audit fix --force"
                    } elseif ($highCount -gt 0) {
                        Write-Finding "HIGH" "D7.1" "${auditTool} audit: $highCount high-severity vulnerabilities"
                        Add-Finding "D7.1" "HIGH" "$highCount high npm vulns" "Run: $auditTool audit fix"
                    } else {
                        Write-Finding "PASS" "D7.1" "${auditTool} audit: no high/critical vulnerabilities ✓"
                        Add-Finding "D7.1" "PASS" "No high/critical npm vulns" ""
                    }
                } else {
                    Write-Finding "SKIP" "D7.1" "${auditTool} audit returned unexpected format — skipping"
                    Add-Finding "D7.1" "SKIP" "${auditTool} audit: unexpected output format" ""
                }
            } else {
                Write-Finding "SKIP" "D7.1" "${auditTool} audit returned no output — ensure node_modules exist"
                Add-Finding "D7.1" "SKIP" "${auditTool} audit: no output (run npm install first)" "Run: npm install"
            }
        } catch {
            Write-Finding "SKIP" "D7.1" "$auditTool audit failed: $_"
            Add-Finding "D7.1" "SKIP" "${auditTool} audit failed" ""
        }
    } else {
        Write-Finding "SKIP" "D7.1" "No package.json found — skipping dependency audit"
        Write-ColorLine "         Searched paths:" "Gray"
        Write-ColorLine "           `$OPENCLAW_DIR         = $($Script:OPENCLAW_DIR)" "Gray"
        Write-ColorLine "           C:\Program Files\nodejs\node_modules\openclaw\package.json" "Gray"
        Write-ColorLine "           $env:APPDATA\npm\node_modules\openclaw\package.json" "Gray"
        Write-ColorLine "         If openclaw is installed elsewhere, set:" "Yellow"
        Write-ColorLine "           `$env:OPENCLAW_PKG_JSON = 'C:\your\path\to\openclaw\package.json'" "Yellow"
        Add-Finding "D7.1" "SKIP" "No package.json in target directory" "Set `$env:OPENCLAW_PKG_JSON to override"
    }

    # D7.2 Node.js EOL check
    $nodePath = Get-Command "node" -ErrorAction SilentlyContinue
    if ($nodePath) {
        $nodeVer = & node --version 2>$null
        if ($nodeVer -match 'v(\d+)\.') {
            $major = [int]$Matches[1]
            # Bug Fix #27: v19 and v21 are odd non-LTS versions, EOL since April 2024, need to list separately
            # Bug Fix #29: Fix indentation alignment
            if ($major -le 18 -or $major -eq 19 -or $major -eq 21) {
                Write-Finding "HIGH" "D7.2" "Node.js $nodeVer is END-OF-LIFE"
                Add-Finding "D7.2" "HIGH" "EOL Node.js: $nodeVer" "Upgrade to Node.js v22 LTS"
            } elseif ($major -eq 20) {
                Write-Finding "MEDIUM" "D7.2" "Node.js $nodeVer reaches EOL April 2026"
                Add-Finding "D7.2" "MEDIUM" "Node.js v20 near EOL" "Plan upgrade to v22"
            } else {
                Write-Finding "PASS" "D7.2" "Node.js $nodeVer is supported ✓"
                Add-Finding "D7.2" "PASS" "Node.js version OK" ""
            }
        } else {
            Write-Finding "SKIP" "D7.2" "Unable to parse Node.js version string: $nodeVer"
            Add-Finding "D7.2" "SKIP" "Node.js version string unparseable" ""
        }
    } else {
        Write-Finding "SKIP" "D7.2" "node not found in PATH — skipping Node.js version check"
        Add-Finding "D7.2" "SKIP" "node not found in PATH" "Install Node.js from https://nodejs.org"
    }

    # D7.3 Known high-risk package detection
    # Bug Fix #18: Use regex word boundary matching instead of .Contains() to avoid false positives like ansi-colors matching colors, @faker-js/faker matching faker, etc.
    $knownBadPkgs = @('event-stream', 'flatmap-stream', 'left-pad', 'ua-parser-js', 'colors', 'faker')
    $lockFile = Join-Path $Script:OPENCLAW_DIR "pnpm-lock.yaml"
    if (-not (Test-Path $lockFile)) { $lockFile = Join-Path $Script:OPENCLAW_DIR "package-lock.json" }
    if (Test-Path $lockFile) {
        $lockContent = Get-Content $lockFile -Raw -ErrorAction SilentlyContinue
        $badFound = $false
        foreach ($pkg in $knownBadPkgs) {
            $escaped = [regex]::Escape($pkg)
            # Bug Fix #25: Merge scoped fork exclusion into initial regex to avoid false negatives when lock file contains both standalone package and scoped fork
            # (?<!@[\w-]+/) excludes @faker-js/faker and other scoped forks; (?<![\w-]) excludes compound package names like ansi-colors
            if ($lockContent -and $lockContent -match "(?m)(?<!@[\w-]+/)(?<![\w-])$escaped(?![\w-])") {
                Write-Finding "HIGH" "D7.3" "Known-compromised package detected: $pkg"
                Add-Finding "D7.3" "HIGH" "Compromised package: $pkg" "Remove and audit supply chain"
                $badFound = $true
            }
        }
        if (-not $badFound) {
            Write-Finding "PASS" "D7.3" "No known-compromised packages found ✓"
            Add-Finding "D7.3" "PASS" "No compromised packages" ""
        }
    } else {
        Write-Finding "SKIP" "D7.3" "No lock file found — skipping compromised package check"
        Add-Finding "D7.3" "SKIP" "No pnpm-lock.yaml or package-lock.json found" ""
    }
}

# ================================================================
#  MODULE S: Skills Security Check (Windows)
# ================================================================
function Invoke-SkillsChecks {
    $Script:CurrentModule = "skills"
    Write-Section "[skills] Skills & Plugin Security"

    # Detect skills directory
    $skillsDir = $null
    foreach ($candidate in @(
        (Join-Path $Script:OPENCLAW_DIR "skills"),
        (Join-Path $Script:OPENCLAW_DIR "agents\skills"),
        (Join-Path $Script:OPENCLAW_DIR "plugins"),
        (Join-Path $env:USERPROFILE ".openclaw\skills")
    )) {
        if (Test-Path $candidate) { $skillsDir = $candidate; break }
    }

    if (-not $skillsDir) {
        Write-ColorLine "" "Gray"
        Write-ColorLine "  ┌─────────────────────────────────────────────────────────────┐" "Yellow"
        Write-ColorLine "  │  S2.0  Skills directory not found — skipping skills checks  │" "Yellow"
        Write-ColorLine "  │                                                             │" "Yellow"
        Write-ColorLine "  │  To enable skills scanning, set the directory before run:  │" "Yellow"
        Write-ColorLine "  │                                                             │" "Yellow"
        Write-ColorLine "  │    `$env:SKILLS_DIR = 'C:\path\to\your\skills'              │" "Cyan"
        Write-ColorLine "  │    .\dejavu.ps1 -Dir `"$env:USERPROFILE\.openclaw`"          │" "Cyan"
        Write-ColorLine "  │                                                             │" "Yellow"
        Write-ColorLine "  │  Common locations to check:                                │" "Yellow"
        Write-ColorLine "  │    $env:USERPROFILE\.openclaw\skills                        │" "Gray"
        Write-ColorLine "  │    $env:USERPROFILE\.openclaw\agents\skills                 │" "Gray"
        Write-ColorLine "  │    $env:USERPROFILE\.openclaw\plugins                       │" "Gray"
        Write-ColorLine "  └─────────────────────────────────────────────────────────────┘" "Yellow"
        Write-ColorLine "" "Gray"
        Write-Finding "SKIP" "S2.1" "No skills directory found — set `$env:SKILLS_DIR to enable scanning"
        Add-Finding "S2.1" "SKIP" "No skills directory found" "Set `$env:SKILLS_DIR = 'path\to\skills' before running"
        return
    }

    # S2.1 Inventory skills
    $skillDirs = @(Get-ChildItem -Path $skillsDir -Directory -ErrorAction SilentlyContinue)
    $skillCount = $skillDirs.Count
    if ($skillCount -eq 0) {
        Write-Finding "PASS" "S2.1" "No skills installed — minimal attack surface ✓"
        Add-Finding "S2.1" "PASS" "No skills installed" ""
    } else {
        Write-Finding "PASS" "S2.1" "$skillCount skill(s) found: $($skillDirs.Name -join ', ') ✓"
        Add-Finding "S2.1" "PASS" "$skillCount skills installed" ""
    }

    # S2.2 Permission minimization (detect dangerous tool combinations)
    $dangerousCombos = @(
        @('bash','file_write'), @('shell','network_fetch'),
        @('execute','read_file','write_file'), @('terminal','http_request')
    )
    $violations = @()
    foreach ($sd in $skillDirs) {
        $manifest = $null
        foreach ($mf in @('package.json','manifest.json','skill.json')) {
            $mpath = Join-Path $sd.FullName $mf
            if (Test-Path $mpath) {
                try { $manifest = Get-Content $mpath -Raw | ConvertFrom-Json } catch {}
                break
            }
        }
        if (-not $manifest) { continue }
        $tools = @($manifest.tools) + @($manifest.permissions) | Where-Object { $_ }
        $toolStr = ($tools | Out-String).ToLower()
        foreach ($combo in $dangerousCombos) {
            if (($combo | Where-Object { $toolStr -notmatch [regex]::Escape($_) }).Count -eq 0) {
                $violations += "$($sd.Name): has dangerous combo [$($combo -join ' + ')]"
            }
        }
    }
    if ($violations.Count -gt 0) {
        Write-Finding "HIGH" "S2.2" "Over-permissioned skill(s): $($violations.Count)"
        $violations | ForEach-Object { Write-ColorLine "         $_" "Red" }
        Add-Finding "S2.2" "HIGH" "Over-permissioned skills detected" "Remove unnecessary tool permissions from skill manifests"
    } else {
        Write-Finding "PASS" "S2.2" "No dangerous skill permission combinations ✓"
        Add-Finding "S2.2" "PASS" "Skill permissions OK" ""
    }

    # S2.3 SSRF risk (user-controllable URLs)
    $ssrfPatterns = @(
        'fetch\s*\(\s*\$\{.*user',
        'http(s)?\.get\s*\(\s*\$\{.*input',
        'axios\.(get|post)\s*\(\s*\$\{.*param',
        'url\s*[=:]\s*.*\$\{.*\}',
        'request\s*\(.*\$\{.*url'
    )
    $skillJsFiles = @(Get-ChildItem -Path $skillsDir -Recurse -Include '*.js','*.ts','*.mjs' -Depth 4 -ErrorAction SilentlyContinue)
    $ssrfFiles = @()
    foreach ($f in $skillJsFiles) {
        $c = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $c) { continue }
        foreach ($pat in $ssrfPatterns) {
            if ($c -match $pat) { $ssrfFiles += $f.Name; break }
        }
    }
    if ($ssrfFiles.Count -gt 0) {
        Write-Finding "HIGH" "S2.3" "Potential SSRF risk in $($ssrfFiles.Count) skill file(s): $($ssrfFiles -join ', ')"
        Add-Finding "S2.3" "HIGH" "SSRF risk in skills" "Validate & allowlist URLs before outbound requests"
    } else {
        Write-Finding "PASS" "S2.3" "No obvious SSRF patterns in skills ✓"
        Add-Finding "S2.3" "PASS" "Skills SSRF check OK" ""
    }

    # S2.4 Prompt injection surface
    $injectionPatterns = @(
        'systemPrompt.*\+.*user',
        'instructions.*\+.*input',
        '\$\{.*(userMessage|userInput|userText)',
        'prompt\s*=.*\+.*user',
        'message.*`.*\$\{.*\}'
    )
    $injectionFiles = @()
    foreach ($f in $skillJsFiles) {
        $c = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $c) { continue }
        foreach ($pat in $injectionPatterns) {
            if ($c -match $pat) { $injectionFiles += $f.Name; break }
        }
    }
    if ($injectionFiles.Count -gt 0) {
        Write-Finding "HIGH" "S2.4" "Prompt injection surface in $($injectionFiles.Count) skill file(s)"
        Add-Finding "S2.4" "HIGH" "Prompt injection risk" "Sanitize user input before including in LLM prompts"
    } else {
        Write-Finding "PASS" "S2.4" "No obvious prompt injection patterns ✓"
        Add-Finding "S2.4" "PASS" "Skills prompt injection OK" ""
    }

    # S2.5 Source legitimacy (toxic skills list)
    $toxicFile = Join-Path $PSScriptRoot "rules\toxic_skills.txt"
    if (Test-Path $toxicFile) {
        $toxicList = Get-Content $toxicFile -ErrorAction SilentlyContinue | Where-Object { $_ -notmatch '^#' -and $_ -ne '' }
        $toxicFound = @()
        foreach ($sd in $skillDirs) {
            if ($toxicList -contains $sd.Name.ToLower()) { $toxicFound += $sd.Name }
        }
        if ($toxicFound.Count -gt 0) {
            Write-Finding "CRITICAL" "S2.5" "Known toxic skill(s) detected: $($toxicFound -join ', ')"
            Add-Finding "S2.5" "CRITICAL" "Toxic skills: $($toxicFound -join ', ')" "Remove immediately: rm -rf skills/<name>"
        } else {
            Write-Finding "PASS" "S2.5" "No known toxic skills detected ✓"
            Add-Finding "S2.5" "PASS" "Toxic skills check OK" ""
        }
    } else {
        Write-Finding "SKIP" "S2.5" "toxic_skills.txt not found — skipping toxic skill check"
        Add-Finding "S2.5" "SKIP" "No toxic skills rule file" ""
    }

    # S2.6 Source metadata (skills without source information)
    $noSourceSkills = @()
    foreach ($sd in $skillDirs) {
        $hasSource = $false
        foreach ($mf in @('package.json','manifest.json')) {
            $mpath = Join-Path $sd.FullName $mf
            if (Test-Path $mpath) {
                $mc = Get-Content $mpath -Raw -ErrorAction SilentlyContinue
                if ($mc -match '"(source|repository|homepage|author)"') { $hasSource = $true; break }
            }
        }
        if (-not $hasSource) { $noSourceSkills += $sd.Name }
    }
    if ($noSourceSkills.Count -gt 0) {
        Write-Finding "MEDIUM" "S2.6" "$($noSourceSkills.Count) skill(s) missing source metadata: $($noSourceSkills -join ', ')"
        Add-Finding "S2.6" "MEDIUM" "Skills missing source metadata" "Verify skill origins manually"
    } else {
        Write-Finding "PASS" "S2.6" "All skills have source metadata ✓"
        Add-Finding "S2.6" "PASS" "Skill sources OK" ""
    }
}

# ================================================================
#  MODULE P: Reverse Proxy Configuration Check (Windows)
# ================================================================
function Invoke-ProxyChecks {
    $Script:CurrentModule = "proxy"
    Write-Section "[proxy] Reverse Proxy Configuration"

    $cfg = Get-OpenClawConfig

    # P4.1 trustedProxies configuration
    $proxies = Get-ConfigValue $cfg "gateway.trustedProxies"
    if ($null -eq $proxies -or ($proxies -is [array] -and $proxies.Count -eq 0)) {
        Write-Finding "LOW" "P4.1" "trustedProxies not configured — safe if NOT behind a reverse proxy"
        Add-Finding "P4.1" "LOW" "trustedProxies not set" "Set to reverse proxy IP(s) if applicable"
    } elseif ($proxies -match '"\*"' -or ($proxies | Where-Object { $_ -eq '*' -or $_ -eq '0.0.0.0' })) {
        Write-Finding "CRITICAL" "P4.1" "trustedProxies=* or 0.0.0.0 — ANY host can spoof X-Forwarded-For"
        Add-Finding "P4.1" "CRITICAL" "trustedProxies wildcard: IP spoofing possible" 'Restrict to specific proxy IPs: ["127.0.0.1"]'
    } else {
        Write-Finding "PASS" "P4.1" "trustedProxies configured with specific IPs ✓"
        Add-Finding "P4.1" "PASS" "trustedProxies OK" ""
    }

    # P4.2 X-Forwarded-For injection risk
    $authMode = Get-ConfigValue $cfg "gateway.auth.mode"
    if ($authMode -eq "trusted-proxy") {
        if ($null -eq $proxies -or ($proxies -is [array] -and $proxies.Count -eq 0)) {
            Write-Finding "CRITICAL" "P4.2" "auth.mode='trusted-proxy' but trustedProxies is empty — any client can forge X-Forwarded-For"
            Add-Finding "P4.2" "CRITICAL" "trusted-proxy auth without proxy whitelist" "Configure trustedProxies with specific proxy IPs immediately"
        } else {
            Write-Finding "PASS" "P4.2" "trusted-proxy mode with trustedProxies configured ✓"
            Add-Finding "P4.2" "PASS" "X-Forwarded-For auth OK" ""
        }
    } else {
        Write-Finding "PASS" "P4.2" "auth.mode='$authMode' does not rely on X-Forwarded-For ✓"
        Add-Finding "P4.2" "PASS" "Forwarded header not auth-critical" ""
    }

    # P4.3 Security response headers (detect if gateway is running)
    try {
        $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$Script:GATEWAY_PORT/" `
                    -TimeoutSec 3 -ErrorAction Stop -UseBasicParsing
        $missingHeaders = @()
        foreach ($h in @('X-Content-Type-Options','X-Frame-Options','Content-Security-Policy')) {
            if (-not $resp.Headers[$h]) { $missingHeaders += $h }
        }
        if ($missingHeaders.Count -gt 0) {
            Write-Finding "MEDIUM" "P4.3" "Missing security headers: $($missingHeaders -join ', ')"
            Add-Finding "P4.3" "MEDIUM" "Missing security response headers" "Configure reverse proxy (nginx/Caddy) to add these headers"
        } else {
            Write-Finding "PASS" "P4.3" "Required security headers present ✓"
            Add-Finding "P4.3" "PASS" "Security headers OK" ""
        }
    } catch {
        Write-Finding "SKIP" "P4.3" "Gateway not responding on port $Script:GATEWAY_PORT — skipping header check"
        Add-Finding "P4.3" "SKIP" "Gateway not active" ""
    }

    # P4.4 SSL termination configuration
    $tlsEnabled = Get-ConfigValue $cfg "gateway.tls.enabled"
    $tlsCert    = Get-ConfigValue $cfg "gateway.tls.cert"
    if ($null -ne $tlsEnabled -and $tlsEnabled -eq $true) {
        if ($tlsCert) {
            Write-Finding "PASS" "P4.4" "TLS configured with certificate ✓"
            Add-Finding "P4.4" "PASS" "TLS configured" ""
        } else {
            Write-Finding "MEDIUM" "P4.4" "TLS enabled but no certificate path configured"
            Add-Finding "P4.4" "MEDIUM" "TLS cert missing" "Set gateway.tls.cert in openclaw.json"
        }
    } else {
        Write-Finding "MEDIUM" "P4.4" "TLS not enabled — gateway is HTTP only (acceptable if behind TLS-terminating proxy)"
        Add-Finding "P4.4" "MEDIUM" "TLS not configured" "Enable TLS or ensure reverse proxy handles HTTPS"
    }

    # P4.5 Authentication bypass flags check
    $bypassFlags = @('skipAuth','disableAuth','noAuth')
    $bypassFound = $false
    foreach ($flag in $bypassFlags) {
        $val = Get-ConfigValue $cfg "gateway.$flag"
        if ($val -eq $true) {
            Write-Finding "CRITICAL" "P4.5" "Auth bypass flag detected: gateway.$flag=true"
            Add-Finding "P4.5" "CRITICAL" "gateway.$flag=true disables auth" "Remove this flag from openclaw.json immediately"
            $bypassFound = $true
        }
    }
    if (-not $bypassFound) {
        Write-Finding "PASS" "P4.5" "No auth bypass flags detected ✓"
        Add-Finding "P4.5" "PASS" "No auth bypass flags" ""
    }

    # P4.6 Timeout configuration
    $timeout = Get-ConfigValue $cfg "gateway.timeout"
    if ($null -eq $timeout -or $timeout -eq 0) {
        Write-Finding "LOW" "P4.6" "No gateway timeout configured — connections may hang indefinitely"
        Add-Finding "P4.6" "LOW" "No gateway timeout" "Set gateway.timeout (e.g., 30000ms) in openclaw.json"
    } else {
        Write-Finding "PASS" "P4.6" "Gateway timeout configured: ${timeout}ms ✓"
        Add-Finding "P4.6" "PASS" "Gateway timeout OK" ""
    }
}

# ================================================================
#  MODULE R: Runtime Instance Checks (Windows)
# ================================================================
function Invoke-RuntimeChecks {
    $Script:CurrentModule = "runtime"
    Write-Section "[runtime] Runtime Instance Checks"

    $cfg = Get-OpenClawConfig
    if ($null -eq $cfg) {
        Write-Finding "SKIP" "R5.0" "openclaw.json not found — skipping runtime checks"
        Add-Finding "R5.0" "SKIP" "No openclaw.json" ""
        return
    }

    # R5.1 auth.mode
    $authMode = Get-ConfigValue $cfg "gateway.auth.mode"
    switch ($authMode) {
        { $_ -eq $null -or $_ -eq '' -or $_ -eq 'none' } {
            Write-Finding "CRITICAL" "R5.1" "gateway.auth.mode='$authMode' — instance has NO authentication"
            Add-Finding "R5.1" "CRITICAL" "Auth mode=none" 'Set "auth": {"mode": "token"} in openclaw.json'
            Write-FixHint 'openclaw.json: "gateway": {"auth": {"mode": "token"}}'
        }
        { $_ -in @('token','password','trusted-proxy') } {
            Write-Finding "PASS" "R5.1" "gateway.auth.mode='$authMode' ✓"
            Add-Finding "R5.1" "PASS" "Auth mode configured" ""
        }
        default {
            Write-Finding "HIGH" "R5.1" "Unrecognized auth.mode: '$authMode'"
            Add-Finding "R5.1" "HIGH" "Unknown auth mode" "Use: token / password / trusted-proxy"
        }
    }

    # R5.2 Bind interface
    $bind = Get-ConfigValue $cfg "gateway.bind"
    switch ($bind) {
        { $_ -in @('loopback','localhost','127.0.0.1') } {
            Write-Finding "PASS" "R5.2" "gateway.bind='$bind' — loopback only ✓"
            Add-Finding "R5.2" "PASS" "Bind=loopback" ""
        }
        { $_ -in @('lan','all','0.0.0.0') -or $_ -eq $null } {
            Write-Finding "CRITICAL" "R5.2" "gateway.bind='$bind' — EXPOSED TO NETWORK"
            Add-Finding "R5.2" "CRITICAL" "Gateway bound to all interfaces" 'Set "bind": "loopback" in openclaw.json'
            Write-FixHint 'openclaw.json: "gateway": {"bind": "loopback"}'
        }
        default {
            Write-Finding "MEDIUM" "R5.2" "gateway.bind='$bind' — non-standard, verify manually"
            Add-Finding "R5.2" "MEDIUM" "Non-standard bind value" "Set to 'loopback' unless LAN access is intentional"
        }
    }

    # R5.3 denyCommands
    $denyCmds = Get-ConfigValue $cfg "gateway.nodes.denyCommands"
    $criticalCmds = @('rm','del','dd','format','fdisk','shutdown','rmdir')
    if ($null -eq $denyCmds -or ($denyCmds -is [array] -and $denyCmds.Count -eq 0)) {
        Write-Finding "MEDIUM" "R5.3" "denyCommands is empty — no shell commands are blocked"
        Add-Finding "R5.3" "MEDIUM" "denyCommands not configured" "Add high-risk commands: del, format, shutdown, rmdir"
    } else {
        $missingCmds = $criticalCmds | Where-Object { $denyCmds -notcontains $_ }
        if ($missingCmds) {
            Write-Finding "MEDIUM" "R5.3" "High-risk commands missing from denyCommands: $($missingCmds -join ', ')"
            Add-Finding "R5.3" "MEDIUM" "Missing commands in denyCommands" "Add: $($missingCmds -join ', ')"
        } else {
            Write-Finding "PASS" "R5.3" "Core high-risk commands present in denyCommands ✓"
            Add-Finding "R5.3" "PASS" "denyCommands OK" ""
        }
    }

    # R5.4 trustedProxies consistency with auth.mode (reused)
    $proxies = Get-ConfigValue $cfg "gateway.trustedProxies"
    if ($null -ne $proxies -and ($proxies | Where-Object { $_ -eq '*' -or $_ -eq '0.0.0.0' })) {
        Write-Finding "HIGH" "R5.4" "trustedProxies wildcard — X-Forwarded-For can be spoofed"
        Add-Finding "R5.4" "HIGH" "trustedProxies wildcard" 'Change to specific proxy IPs: ["127.0.0.1"]'
    } else {
        Write-Finding "PASS" "R5.4" "trustedProxies OK ✓"
        Add-Finding "R5.4" "PASS" "trustedProxies OK" ""
    }

    # R5.5 auth-profiles.json
    $authProfilePaths = @(
        (Join-Path $Script:OPENCLAW_DIR "agents\main\agent\auth-profiles.json"),
        (Join-Path $Script:OPENCLAW_DIR "auth-profiles.json"),
        (Join-Path $env:USERPROFILE ".openclaw\auth-profiles.json")
    )
    $authProfilePath = $authProfilePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($authProfilePath) {
        $profileContent = Get-Content $authProfilePath -Raw -ErrorAction SilentlyContinue
        if ($profileContent -imatch '"(admin|superuser|root)"' -and $profileContent -notmatch '"allowedIP') {
            Write-Finding "HIGH" "R5.5" "Admin auth-profile without IP restriction in auth-profiles.json"
            Add-Finding "R5.5" "HIGH" "Admin profile without IP allowlist" "Add 'allowedIPs' to admin auth profiles"
        } else {
            Write-Finding "PASS" "R5.5" "Auth profiles check OK ✓"
            Add-Finding "R5.5" "PASS" "Auth profiles OK" ""
        }
    } else {
        Write-Finding "SKIP" "R5.5" "auth-profiles.json not found — skipping"
        Add-Finding "R5.5" "SKIP" "auth-profiles.json not found" ""
    }

    # R5.6 Paired device audit
    $pairedPaths = @(
        (Join-Path $Script:OPENCLAW_DIR "devices\paired.json"),
        (Join-Path $env:USERPROFILE ".openclaw\devices\paired.json")
    )
    $pairedPath = $pairedPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($pairedPath) {
        $pairedContent = Get-Content $pairedPath -Raw -ErrorAction SilentlyContinue
        $deviceCount = ([regex]::Matches($pairedContent, '"id"')).Count
        Write-Finding "LOW" "R5.6" "Found $deviceCount paired device(s) — review manually"
        Add-Finding "R5.6" "LOW" "Paired devices require review" "Remove unrecognized devices from paired.json"
    } else {
        Write-Finding "SKIP" "R5.6" "No paired devices file found"
        Add-Finding "R5.6" "SKIP" "No paired.json" ""
    }

    # R5.7 session TTL
    $ttl = Get-ConfigValue $cfg "gateway.auth.sessionTtl"
    if ($null -eq $ttl -or $ttl -eq 0) {
        Write-Finding "LOW" "R5.7" "session TTL not configured — sessions never expire"
        Add-Finding "R5.7" "LOW" "No session TTL" "Set gateway.auth.sessionTtl (e.g. 3600 seconds)"
    } else {
        Write-Finding "PASS" "R5.7" "Session TTL configured: ${ttl}s ✓"
        Add-Finding "R5.7" "PASS" "Session TTL OK" ""
    }

    # R5.8 openclaw process running status
    $gwProcess = Get-Process -Name "*openclaw*" -ErrorAction SilentlyContinue
    if ($gwProcess) {
        Write-Finding "PASS" "R5.8" "OpenClaw process running (PID: $($gwProcess[0].Id)) ✓"
        Add-Finding "R5.8" "PASS" "OpenClaw process active" ""
    } else {
        Write-Finding "SKIP" "R5.8" "No OpenClaw process detected — runtime state checks skipped"
        Add-Finding "R5.8" "SKIP" "OpenClaw not running" "Start OpenClaw and re-run with -Runtime for live checks"
    }
}

# ================================================================
#  MODULE H: Host Runtime Audit (Windows)
# ================================================================
function Invoke-HostAuditChecks {
    $Script:CurrentModule = "hostaudit"
    Write-Section "[hostaudit] Host Runtime Audit"

    # H8.1 Sensitive directory file changes in last 24h
    $sensitivePaths = @(
        $Script:OPENCLAW_DIR,
        "$env:USERPROFILE\.openclaw",
        "$env:USERPROFILE\.ssh"
    )
    $modCount = 0
    foreach ($p in $sensitivePaths) {
        if (Test-Path $p) {
            $modCount += @(Get-ChildItem -Path $p -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-24) }).Count
        }
    }
    if ($modCount -gt 50) {
        Write-Finding "HIGH" "H8.1" "Large number of sensitive directory changes in last 24h: $modCount files"
        Add-Finding "H8.1" "HIGH" "Sensitive dir changes: $modCount files in 24h" "Review with: Get-ChildItem -Recurse | Where LastWriteTime -gt (Get-Date).AddHours(-24)"
    } elseif ($modCount -gt 10) {
        Write-Finding "MEDIUM" "H8.1" "Sensitive directory had $modCount file change(s) in last 24h"
        Add-Finding "H8.1" "MEDIUM" "Sensitive dir changes: $modCount files" "Review recently modified files"
    } else {
        Write-Finding "PASS" "H8.1" "Sensitive directory change count normal: $modCount ✓"
        Add-Finding "H8.1" "PASS" "Sensitive dir changes normal" ""
    }

    # H8.2 Scheduled task audit (Windows equivalent of cron)
    try {
        $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue |
            Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notmatch '\\Microsoft\\' })
        if ($tasks.Count -gt 0) {
            Write-Finding "MEDIUM" "H8.2" "Found $($tasks.Count) non-Microsoft scheduled task(s) — please review"
            if ($Script:VERBOSE_MODE) {
                $tasks | Select-Object -First 10 | ForEach-Object {
                    Write-ColorLine "         Task: $($_.TaskName) [$($_.State)]" "Gray"
                }
            }
            Add-Finding "H8.2" "MEDIUM" "$($tasks.Count) non-Microsoft scheduled tasks" "Audit: Get-ScheduledTask | Where TaskPath -notmatch Microsoft"
        } else {
            Write-Finding "PASS" "H8.2" "No suspicious scheduled tasks found ✓"
            Add-Finding "H8.2" "PASS" "Scheduled tasks OK" ""
        }
    } catch {
        Write-Finding "SKIP" "H8.2" "Scheduled task enumeration failed — re-run as Administrator"
        Add-Finding "H8.2" "SKIP" "Scheduled task check requires Administrator" ""
    }

    # H8.3 Login failures in last 24h (Windows Security log)
    try {
        $failedLogins = @(Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4625
            StartTime = (Get-Date).AddHours(-24)
        } -ErrorAction Stop)
        if ($failedLogins.Count -gt 20) {
            Write-Finding "HIGH" "H8.3" "High login failure count last 24h: $($failedLogins.Count)"
            Add-Finding "H8.3" "HIGH" "Login failures: $($failedLogins.Count) in 24h" "Investigate with: Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625}"
        } elseif ($failedLogins.Count -gt 5) {
            Write-Finding "MEDIUM" "H8.3" "Login failures in last 24h: $($failedLogins.Count)"
            Add-Finding "H8.3" "MEDIUM" "Login failures: $($failedLogins.Count)" "Review Security event log ID 4625"
        } else {
            Write-Finding "PASS" "H8.3" "Login failure count normal: $($failedLogins.Count) in 24h ✓"
            Add-Finding "H8.3" "PASS" "Login failures normal" ""
        }
    } catch {
        Write-Finding "SKIP" "H8.3" "Security event log not accessible — re-run as Administrator"
        Add-Finding "H8.3" "SKIP" "Security event log requires Administrator" ""
    }

    # H8.4 Suspicious outbound connections (non-standard ports)
    $suspiciousPorts = @(4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337)
    $suspConn = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Where-Object { $suspiciousPorts -contains $_.RemotePort -and $_.RemoteAddress -ne '127.0.0.1' })
    if ($suspConn.Count -gt 0) {
        Write-Finding "HIGH" "H8.4" "Suspicious outbound connection(s) detected: $($suspConn.Count)"
        $suspConn | ForEach-Object {
            Write-ColorLine "         Port $($_.RemotePort) → $($_.RemoteAddress)" "Red"
        }
        Add-Finding "H8.4" "HIGH" "Suspicious outbound connections on common backdoor ports" "Investigate with: Get-NetTCPConnection -State Established"
    } else {
        Write-Finding "PASS" "H8.4" "No outbound connections on suspicious ports ✓"
        Add-Finding "H8.4" "PASS" "Outbound connections OK" ""
    }

    # H8.5 User privilege audit (count of local Administrators group members)
    try {
        $admins = @(net localgroup Administrators 2>$null | Where-Object { $_ -notmatch '^--|^$|^Members|^The command|Administrators' } | Where-Object { $_.Trim() -ne '' })
        if ($admins.Count -gt 3) {
            Write-Finding "MEDIUM" "H8.5" "Local Administrators group has $($admins.Count) members — review for least-privilege"
            Add-Finding "H8.5" "MEDIUM" "Too many local admins: $($admins.Count)" "Remove unnecessary accounts from Administrators group"
        } else {
            Write-Finding "PASS" "H8.5" "Local Administrators group member count OK: $($admins.Count) ✓"
            Add-Finding "H8.5" "PASS" "Admin group OK" ""
        }
    } catch {
        Write-Finding "SKIP" "H8.5" "Admin group enumeration failed"
        Add-Finding "H8.5" "SKIP" "Admin group check failed" ""
    }

    # H8.6 Startup items audit (registry Run keys)
    $runKeys = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
    )
    $runItems = @()
    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            $props = Get-ItemProperty $key -ErrorAction SilentlyContinue
            if ($props) {
                $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } |
                    ForEach-Object { $runItems += "$($_.Name): $($_.Value)" }
            }
        }
    }
    if ($runItems.Count -gt 0) {
        Write-Finding "LOW" "H8.6" "Found $($runItems.Count) startup entry(ies) in registry Run keys"
        if ($Script:VERBOSE_MODE) {
            $runItems | ForEach-Object { Write-ColorLine "         $_" "Gray" }
        }
        Add-Finding "H8.6" "LOW" "Startup entries: $($runItems.Count)" "Review: HKCU/HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
    } else {
        Write-Finding "PASS" "H8.6" "No unexpected startup entries found ✓"
        Add-Finding "H8.6" "PASS" "Startup entries OK" ""
    }
}

# ================================================================
#  MODULE I: DLP / Integrity Baseline (Windows)
# ================================================================
function Invoke-DlpChecks {
    $Script:CurrentModule = "dlp"
    Write-Section "[dlp] DLP / Integrity Baseline"

    $ocDir = if (Test-Path (Join-Path $Script:OPENCLAW_DIR "openclaw.json")) {
        $Script:OPENCLAW_DIR
    } elseif (Test-Path "$env:USERPROFILE\.openclaw") {
        "$env:USERPROFILE\.openclaw"
    } else {
        $Script:OPENCLAW_DIR
    }

    # I9.1 Process environment variable scan (current session)
    $envSensitive = [System.Environment]::GetEnvironmentVariables() |
        ForEach-Object { $_.Keys } |
        Where-Object { $_ -imatch 'SECRET|TOKEN|PASSWORD|KEY|PRIVATE|CREDENTIAL|API' } |
        Where-Object { $_ -ne 'Path' }
    if ($null -ne $envSensitive -and @($envSensitive).Count -gt 0) {
        Write-Finding "HIGH" "I9.1" "Sensitive env variable name(s) detected in current session: $(@($envSensitive) -join ', ') (values sanitized)"
        Add-Finding "I9.1" "HIGH" "Sensitive env vars in session" "Verify these variables are intentionally set and scoped correctly"
    } else {
        Write-Finding "PASS" "I9.1" "No sensitive env variable names in current session ✓"
        Add-Finding "I9.1" "PASS" "Env vars clean" ""
    }

    # I9.2 Plaintext private key / mnemonic DLP scan
    $scanRoot = if (Test-Path (Join-Path $ocDir "workspace")) { Join-Path $ocDir "workspace" } else { $ocDir }
    $dlpPatterns = @{
        'ETH Private Key'  = '(?i)\b0x[a-fA-F0-9]{64}\b'
        'BTC WIF Key'      = '\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b'
        'PEM Private Key'  = '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'
        'Mnemonic Phrase'  = '(?i)\b([a-z]{3,12}\s+){11}[a-z]{3,12}\b'
    }
    $dlpFiles = @(Get-ChildItem -Path $scanRoot -Recurse -Include '*.txt','*.md','*.json','*.log','*.pem','*.key' `
        -Depth 6 -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\node_modules\\|\\\.git\\' })
    $dlpHits    = @{}   # pattern -> hit count
    $dlpHitFiles = @{}   # pattern -> list of file paths
    foreach ($f in $dlpFiles) {
        $content = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $content) { continue }
        foreach ($kv in $dlpPatterns.GetEnumerator()) {
            if ($content -match $kv.Value) {
                if (-not $dlpHits[$kv.Key]) {
                    $dlpHits[$kv.Key]     = 0
                    $dlpHitFiles[$kv.Key] = [System.Collections.Generic.List[string]]::new()
                }
                $dlpHits[$kv.Key]++
                $dlpHitFiles[$kv.Key].Add($f.FullName)
            }
        }
    }
    if ($dlpHits.Count -gt 0) {
        $summary = ($dlpHits.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', '
        Write-Finding "CRITICAL" "I9.2" "DLP: Potential plaintext private key/mnemonic detected! $summary"
        # Output file paths by type
        foreach ($kv in $dlpHitFiles.GetEnumerator()) {
            Write-ColorLine "         [$($kv.Key)]" "Red"
            foreach ($path in $kv.Value) {
                Write-ColorLine "           -> $path" "Yellow"
            }
        }
        Add-Finding "I9.2" "CRITICAL" "Plaintext private keys detected: $summary" "Immediately review and remove private keys from workspace files"
    } else {
        Write-Finding "PASS" "I9.2" "DLP scan: no private key or mnemonic patterns found ✓"
        Add-Finding "I9.2" "PASS" "DLP scan passed" ""
    }

    # I9.3 Critical configuration file hash baseline
    $baselineDir  = Join-Path $ocDir "security-baselines"
    $baselineFile = Join-Path $baselineDir "config-baseline.sha256"
    $keyFiles = @(@('openclaw.json','SOUL.md','AGENTS.md') |
        ForEach-Object { Join-Path $ocDir $_ } |
        Where-Object { Test-Path $_ })

    if ($keyFiles.Count -eq 0) {
        Write-Finding "SKIP" "I9.3" "No key config files found for hash baseline"
        Add-Finding "I9.3" "SKIP" "No files to baseline" ""
    } elseif (-not (Test-Path $baselineFile)) {
        # First run, establish baseline
        $null = New-Item -ItemType Directory -Force -Path $baselineDir
        $keyFiles | ForEach-Object {
            $hash = (Get-FileHash $_ -Algorithm SHA256).Hash
            "$hash  $_"
        } | Set-Content $baselineFile -Encoding UTF8
        Write-Finding "PASS" "I9.3" "Hash baseline created for $($keyFiles.Count) file(s) ✓"
        Add-Finding "I9.3" "PASS" "Baseline created" ""
    } else {
        $baseline = Get-Content $baselineFile | Where-Object { $_ -match '^\w{64}' }
        $changed = @()
        foreach ($entry in $baseline) {
            $parts = $entry -split '\s+', 2
            if ($parts.Count -eq 2 -and (Test-Path $parts[1])) {
                $current = (Get-FileHash $parts[1] -Algorithm SHA256).Hash
                if ($current -ne $parts[0]) { $changed += (Split-Path $parts[1] -Leaf) }
            }
        }
        if ($changed.Count -gt 0) {
            Write-Finding "HIGH" "I9.3" "Hash baseline mismatch — files modified since last scan: $($changed -join ', ')"
            Add-Finding "I9.3" "HIGH" "Config files modified: $($changed -join ', ')" "Review changes; re-run to update baseline"
        } else {
            Write-Finding "PASS" "I9.3" "All config files match hash baseline ✓"
            Add-Finding "I9.3" "PASS" "Hash baseline OK" ""
        }
    }

    # I9.4 Brain/Memory backup validation
    $brainPaths = @(@(
        (Join-Path $ocDir "memory"),
        (Join-Path $ocDir "brain"),
        (Join-Path $ocDir "agents\main\agent\memory")
    ) | Where-Object { Test-Path $_ })
    if ($brainPaths.Count -gt 0) {
        $brainFiles = @(Get-ChildItem -Path ($brainPaths | Select-Object -First 1) -File -ErrorAction SilentlyContinue)
        if ($brainFiles.Count -gt 0) {
            $newest = ($brainFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime
            $daysSince = ((Get-Date) - $newest).Days
            if ($daysSince -gt 7) {
                Write-Finding "MEDIUM" "I9.4" "Brain/Memory last modified $daysSince days ago — verify backup is current"
                Add-Finding "I9.4" "MEDIUM" "Stale brain backup ($daysSince days)" "Ensure brain/memory data is backed up regularly"
            } else {
                Write-Finding "PASS" "I9.4" "Brain/Memory data is recent (${daysSince}d ago) ✓"
                Add-Finding "I9.4" "PASS" "Brain backup current" ""
            }
        } else {
            Write-Finding "LOW" "I9.4" "Brain directory exists but is empty"
            Add-Finding "I9.4" "LOW" "Empty brain directory" ""
        }
    } else {
        Write-Finding "SKIP" "I9.4" "No brain/memory directory found"
        Add-Finding "I9.4" "SKIP" "No brain directory" ""
    }
}

# ================================================================
#  Scoring Summary and Report Generation
# ================================================================
function Write-Summary {
    $finalScore = Get-OverallScore
    $riskLevel = Get-RiskLevel $finalScore
    $bar = Get-ScoreBar $finalScore

    Write-Host ""
    Write-ColorLine "══════════════════════════════════════════════════" "Cyan"
    Write-ColorLine "  dejavu v$Script:DEJAVU_VERSION  Security Baseline Summary" "Cyan"
    Write-ColorLine "══════════════════════════════════════════════════" "Cyan"
    Write-ColorLine "  Target:     $Script:OPENCLAW_DIR" "White"
    Write-ColorLine "  Scan Time:  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "White"
    Write-Host ""

    $riskColor = switch ($riskLevel) {
        'LOW RISK'      { 'Green'  }
        'MEDIUM RISK'   { 'Yellow' }
        'HIGH RISK'     { 'Red'    }
        'CRITICAL RISK' { 'Red'    }
        default         { 'White'  }
    }

    Write-ColorLine "  Overall Score: $finalScore/100  [$bar]" $riskColor
    Write-ColorLine "  Risk Level:    $riskLevel" $riskColor
    Write-Host ""

    Write-ColorLine "  Module Scores:" "White"
    Write-ColorLine "  ─────────────────────────────────────────────" "Gray"
    # Bug Fix #33: Include hostaudit and dlp to ensure these modules' deductions count toward total score, consistent with Get-OverallScore's 9 module weights
    foreach ($module in @('config','skills','network','proxy','runtime','auth','deps','hostaudit','dlp')) {
        $ms = Get-ModuleScore $module
        $mbar = Get-ScoreBar $ms 15
        $mcolor = if ($ms -ge 90) { 'Green' } elseif ($ms -ge 70) { 'Yellow' } else { 'Red' }
        $modName = $module.Substring(0,1).ToUpper() + $module.Substring(1)
        Write-Host -NoNewline "  $($modName.PadRight(10))"
        Write-ColorLine " $ms/100  [$mbar]" $mcolor
    }
    Write-Host ""

    $criticals = @($Script:Findings | Where-Object { $_.Severity -eq 'CRITICAL' })
    $highs     = @($Script:Findings | Where-Object { $_.Severity -eq 'HIGH' })
    $mediums   = @($Script:Findings | Where-Object { $_.Severity -eq 'MEDIUM' })

    Write-ColorLine "  CRITICAL: $($criticals.Count)" $(if ($criticals.Count -gt 0) {'Red'} else {'Green'})
    Write-ColorLine "  HIGH:     $($highs.Count)"     $(if ($highs.Count -gt 0)     {'Red'} else {'Green'})
    Write-ColorLine "  MEDIUM:   $($mediums.Count)"   $(if ($mediums.Count -gt 0)   {'Yellow'} else {'Green'})
    Write-ColorLine "══════════════════════════════════════════════════" "Cyan"

    # Save report (only create when parent directory is not empty to avoid empty string in relative path)
    $reportParentDir = Split-Path $Script:REPORT_FILE
    if ($reportParentDir) { $null = New-Item -ItemType Directory -Force -Path $reportParentDir }

    if ($Output -eq 'json') {
        # JSON format report
        $moduleScores = [ordered]@{}
        foreach ($module in @('config','skills','network','proxy','runtime','auth','deps','hostaudit','dlp')) {
            $moduleScores[$module] = Get-ModuleScore $module
        }
        $sortOrder = @{CRITICAL=0;HIGH=1;MEDIUM=2;LOW=3;PASS=4;SKIP=5;INFO=6}
        $jsonReport = [ordered]@{
            generated    = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            target       = $Script:OPENCLAW_DIR
            score        = $finalScore
            riskLevel    = $riskLevel
            totalChecks  = $Script:TotalChecks
            passedChecks = $Script:PassedChecks
            moduleScores = $moduleScores
            findings     = @(
                $Script:Findings | Sort-Object { $sortOrder[$_.Severity] } | ForEach-Object {
                    [ordered]@{
                        checkId     = $_.CheckId
                        severity    = $_.Severity
                        module      = $_.Module
                        description = $_.Description
                        remediation = $_.Remediation
                    }
                }
            )
        }
        $jsonReport | ConvertTo-Json -Depth 5 | Set-Content $Script:REPORT_FILE -Encoding UTF8
    } else {
        # Markdown format report (default)
        $sortOrder = @{CRITICAL=0;HIGH=1;MEDIUM=2;LOW=3;PASS=4;SKIP=5;INFO=6}
        $lines = @(
            "# dejavu Report — $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
            "",
            "| Field | Value |",
            "|-------|-------|",
            "| **Target** | ``$Script:OPENCLAW_DIR`` |",
            "| **Score** | $finalScore/100 |",
            "| **Risk Level** | $riskLevel |",
            "| **Total Checks** | $Script:TotalChecks |",
            "| **Passed** | $Script:PassedChecks |",
            "",
            "## Module Scores",
            "",
            "| Module | Score |",
            "|--------|-------|"
        )
        foreach ($module in @('config','skills','network','proxy','runtime','auth','deps','hostaudit','dlp')) {
            $ms = Get-ModuleScore $module
            $lines += "| $($module.Substring(0,1).ToUpper() + $module.Substring(1)) | $ms/100 |"
        }
        $lines += @("", "## Findings", "", "| ID | Severity | Module | Description | Remediation |",
                    "|---|---|---|---|---|")
        foreach ($f in $Script:Findings | Sort-Object { $sortOrder[$_.Severity] }) {
            $lines += "| $($f.CheckId) | $($f.Severity) | $($f.Module) | $($f.Description) | $($f.Remediation) |"
        }
        $lines | Set-Content $Script:REPORT_FILE -Encoding UTF8
    }
    Write-ColorLine "  Report saved: $Script:REPORT_FILE" "Green"

    # Exit codes
    if ($criticals.Count -gt 0) { exit 3 }
    if ($highs.Count -gt 0)     { exit 2 }
    if ($mediums.Count -gt 0)   { exit 1 }
    exit 0
}

# ================================================================
#  Main Entry Point
# ================================================================
function Main {
    if ($help) {
        Write-Host @"
Dejavu Security Baseline Checker v$Script:DEJAVU_VERSION (PowerShell)

Usage: .\dejavu.ps1 --dir <openclaw-dir> [options]

Options:
  --dir <path>           OpenClaw install directory (required)
  --checks <modules>     Check modules, comma-separated, default all
                        Options: config,skills,network,proxy,runtime,auth,deps,hostaudit,dlp
  --output <format>      Output format: json|markdown (default json)
  --report <path>        Report output path
  --fix                  Auto-fix low-risk issues
  --runtime              Enable live instance runtime checks
  --port <n>             Gateway port number, default 18789
  --showdetails          Show detailed fix suggestions (or use -Verbose for PowerShell verbose output)
  --help                 Show this help

Exit Codes:
  0 = No MEDIUM/HIGH/CRITICAL findings
  1 = MEDIUM findings present
  2 = HIGH findings present
  3 = CRITICAL findings present

Examples:
  .\dejavu.ps1 --dir 'C:\Users\you\.openclaw'
  .\dejavu.ps1 --dir 'C:\openclaw' --checks 'network,auth' --output markdown --report report.md
  .\dejavu.ps1 --dir 'C:\openclaw' --fix --showdetails
"@
        return
    }

    if (-not $Script:OPENCLAW_DIR) {
        Write-ColorLine "[ERROR] --dir is required. Use --help for usage." "Red"
        exit 1
    }

    if (-not (Test-Path $Script:OPENCLAW_DIR)) {
        Write-ColorLine "[ERROR] Directory not found: $Script:OPENCLAW_DIR" "Red"
        exit 1
    }

    Write-ColorLine @"
 ██████╗ ███████╗     ██╗ █████╗ ██╗   ██╗██╗   ██╗
 ██╔══██╗██╔════╝     ██║██╔══██╗██║   ██║██║   ██║
 ██║  ██║█████╗       ██║███████║██║   ██║██║   ██║
 ██║  ██║██╔══╝  ██   ██║██╔══██║╚██╗ ██╔╝██║   ██║
 ██████╔╝███████╗╚█████╔╝██║  ██║ ╚████╔╝ ╚██████╔╝
 ╚═════╝ ╚══════╝ ╚════╝ ╚═╝  ╚═╝  ╚═══╝   ╚═════╝ 
  Dejavu Security Baseline Checker v$Script:DEJAVU_VERSION [PowerShell Edition]
"@ "Cyan"
    Write-ColorLine "[INFO] Target:  $Script:OPENCLAW_DIR" "Cyan"
    Write-ColorLine "[INFO] Checks:  $checks" "Cyan"
    Write-ColorLine "[INFO] Output:  $output" "Cyan"
    Write-Host ""

    # Bug Fix #43: 'all' mode includes hostaudit and dlp to ensure these modules' deductions count toward total score, consistent with $validModules' 9 module definition
    # Original code @('config',...,'deps') was missing the last two modules, causing hostaudit/dlp to be silently skipped during full scan
    $checkList = if ($checks -eq 'all') {
        @('config','skills','network','proxy','runtime','auth','deps','hostaudit','dlp')
    } else {
        $checks.Split(',') | ForEach-Object { $_.Trim().ToLower() }
    }

    # Bug Fix #19: Validate module names, give warning for unknown names instead of silently skipping
    $validModules = @('config','skills','network','proxy','runtime','auth','deps','hostaudit','dlp')
    foreach ($check in $checkList) {
        if ($validModules -notcontains $check) {
            Write-ColorLine "[WARN] Unknown check module: '$check' — skipping (valid: $($validModules -join ', '))" "Yellow"
            continue
        }
        switch ($check) {
            'config'    { Invoke-ConfigChecks    }
            'network'   { Invoke-NetworkChecks   }
            'auth'      { Invoke-AuthChecks      }
            'deps'      { Invoke-DepsChecks      }
            'skills'    { Invoke-SkillsChecks    }
            'proxy'     { Invoke-ProxyChecks     }
            'runtime'   { Invoke-RuntimeChecks   }
            'hostaudit' { Invoke-HostAuditChecks }
            'dlp'       { Invoke-DlpChecks       }
        }
    }

    Write-Summary
}

Main
