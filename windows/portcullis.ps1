<#
  portcullis.ps1 — personal system security self-audit (Windows / PowerShell)

  Audits the "top 5 easiest ways in", prints + saves a report, then
  interactively offers fixes: SAFE fixes apply on your yes; RISKY ones
  (firewall / RDP / BitLocker / service changes) only PRINT the command
  + a warning — you run those yourself.

  Run in an elevated PowerShell for full checks:
      Right-click PowerShell -> Run as Administrator
      Set-ExecutionPolicy -Scope Process Bypass -Force
      .\portcullis.ps1
#>

$ErrorActionPreference = 'SilentlyContinue'
$report = Join-Path $env:USERPROFILE ("security_audit_{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$findings = New-Object System.Collections.Generic.List[object]
function Add-Finding($Sev,$Title,$Detail,$FixType='NONE',$FixCmd='',$Warn='') {
  $findings.Add([pscustomobject]@{Sev=$Sev;Title=$Title;Detail=$Detail;FixType=$FixType;FixCmd=$FixCmd;Warn=$Warn})
}
function SevColor($s){ switch($s){'CRIT'{'Red'}'HIGH'{'Red'}'WARN'{'Yellow'}'OK'{'Green'}default{'Cyan'}} }

Write-Host "=== Personal System Security Audit ===" -ForegroundColor Cyan
Write-Host ("OS: Windows   Admin: {0}   {1}" -f $isAdmin,(Get-Date))
if(-not $isAdmin){ Write-Host "Tip: run as Administrator for the full set of checks." -ForegroundColor Yellow }
Write-Host ("-"*60)

# --- 1. Firewall profiles ---
try {
  $off = Get-NetFirewallProfile | Where-Object { -not $_.Enabled }
  if($off){
    Add-Finding HIGH "Firewall OFF for: $($off.Name -join ', ')" `
      "A disabled profile means services are reachable on that network type." `
      SHOW "Set-NetFirewallProfile -Profile $($off.Name -join ',') -Enabled True" `
      "Enabling Public firewall is safe on personal machines; verify no inbound app breaks."
  } else {
    Add-Finding OK "Firewall ON (all profiles)" "Domain/Private/Public firewalls enabled."
  }
} catch { Add-Finding INFO "Firewall state unknown" "Could not query firewall (need admin?)." }

# --- 2. Exposed listening ports ---
$risky = @{22='SSH';23='Telnet';135='RPC';139='NetBIOS';445='SMB';3389='RDP';5900='VNC';3306='MySQL';5432='Postgres';27017='Mongo';6379='Redis'}
try {
  $listen = Get-NetTCPConnection -State Listen |
    Where-Object { $risky.ContainsKey([int]$_.LocalPort) -and $_.LocalAddress -notin '127.0.0.1','::1' }
  if($listen){
    $ports = ($listen | ForEach-Object { "$($_.LocalPort)=$($risky[[int]$_.LocalPort])" } | Sort-Object -Unique) -join ', '
    Add-Finding HIGH "Sensitive ports listening beyond localhost" `
      "Exposed: $ports. Bots scan for these constantly." `
      SHOW "# Identify owner: Get-Process -Id (Get-NetTCPConnection -LocalPort <PORT>).OwningProcess`n# Disable the service/feature if unused; put remote access behind a VPN." `
      "Verify each port before disabling anything you rely on."
  } else { Add-Finding OK "No sensitive ports exposed" "No high-risk ports listening on non-loopback." }
} catch { Add-Finding INFO "Port scan skipped" "Could not enumerate listening ports." }

# --- 3. BitLocker (system drive) ---
try {
  $sys = $env:SystemDrive
  $bl = Get-BitLockerVolume -MountPoint $sys
  if($bl -and $bl.ProtectionStatus -eq 'On' -and $bl.VolumeStatus -eq 'FullyEncrypted'){
    Add-Finding OK "BitLocker ON ($sys)" "System drive is encrypted."
  } else {
    Add-Finding HIGH "System drive not encrypted" `
      "If the laptop is lost/stolen, the disk can be read directly." `
      SHOW "Enable-BitLocker -MountPoint $sys -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector" `
      "Save the recovery key it generates (also back it up to your Microsoft account)."
  }
} catch { Add-Finding INFO "BitLocker status unknown" "Run as admin to check BitLocker (Home edition may not support it)." }

# --- 4. Microsoft Defender ---
try {
  $mp = Get-MpComputerStatus
  if($mp){
    if(-not $mp.RealTimeProtectionEnabled){
      Add-Finding HIGH "Defender real-time protection is OFF" `
        "Malware/infostealers run unchecked." `
        AUTO "Set-MpPreference -DisableRealtimeMonitoring `$false" `
        ""
    } else { Add-Finding OK "Defender real-time ON" "Antivirus active." }
    if($mp.AntivirusSignatureAge -gt 3){
      Add-Finding WARN "Defender signatures are $($mp.AntivirusSignatureAge) days old" `
        "Outdated definitions miss new threats." AUTO "Update-MpSignature" ""
    }
  }
} catch { Add-Finding INFO "Defender status unknown" "Get-MpComputerStatus unavailable (3rd-party AV?)." }

# --- 5. RDP enabled ---
try {
  $deny = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections
  if($deny -eq 0){
    Add-Finding HIGH "Remote Desktop (RDP) is enabled" `
      "Exposed RDP is a top ransomware entry point." `
      SHOW "Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1" `
      "Only disable if you don't use RDP; otherwise keep it behind a VPN with MFA."
  } else { Add-Finding OK "RDP disabled" "Remote Desktop is off." }
} catch {}

# --- 6. Auto-login ---
try {
  $al = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon).AutoAdminLogon
  if($al -eq '1'){
    Add-Finding WARN "Automatic login is ON" "Anyone who powers on the PC is logged in as you." `
      SHOW "Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 0" ""
  }
} catch {}

# --- 7. Pending updates (best-effort via winget) ---
try {
  if(Get-Command winget -ErrorAction SilentlyContinue){
    $up = (winget upgrade 2>$null | Select-String -Pattern 'upgrades available')
    if($up){ Add-Finding WARN "App updates available (winget)" "Unpatched apps are an easy door." SHOW "winget upgrade --all" "" }
  }
  Add-Finding INFO "Check Windows Update" "Also run: Settings > Windows Update > Check for updates."
} catch {}

# --- 8. Startup items (review only) ---
try {
  $items = Get-CimInstance Win32_StartupCommand | Select-Object -Expand Name
  if($items){ Add-Finding INFO "Review your startup items" ("Auto-start entries (infostealers hide here): " + ($items -join ', ')) }
} catch {}

# ===== Report =====
"Personal System Security Audit","OS: Windows   $(Get-Date)",("-"*60) | Out-File $report
foreach($f in $findings){ "[$($f.Sev)] $($f.Title)","      $($f.Detail)" | Out-File $report -Append }

Write-Host "`nFindings" -ForegroundColor White; Write-Host ("-"*60)
$high=0;$warn=0;$ok=0
foreach($f in $findings){
  Write-Host ("[{0}] " -f $f.Sev) -ForegroundColor (SevColor $f.Sev) -NoNewline
  Write-Host $f.Title
  Write-Host ("      " + $f.Detail) -ForegroundColor DarkGray
  switch($f.Sev){'HIGH'{$high++}'CRIT'{$high++}'WARN'{$warn++}'OK'{$ok++}}
}
Write-Host ("-"*60)
Write-Host ("Summary: {0} high, {1} warn, {2} ok" -f $high,$warn,$ok)
Write-Host ("Report saved to: {0}" -f $report)

# ===== Remediation =====
$fixables = $findings | Where-Object { $_.FixType -ne 'NONE' }
if(-not $fixables){ Write-Host "`nNothing to fix. Nice." -ForegroundColor Green; return }

$go = Read-Host "`nGo through the $($fixables.Count) fixable item(s) now? [y/N]"
if($go -notmatch '^[Yy]'){ Write-Host "Skipped. Review $report anytime."; return }

foreach($f in $fixables){
  Write-Host "`n$('-'*60)"
  Write-Host ("[{0}] {1}" -f $f.Sev,$f.Title) -ForegroundColor (SevColor $f.Sev)
  if($f.Warn){ Write-Host ("! " + $f.Warn) -ForegroundColor Yellow }
  Write-Host "Fix:" -ForegroundColor White
  Write-Host $f.FixCmd
  if($f.FixType -eq 'AUTO'){
    $a = Read-Host "This is safe to apply automatically. Apply now? [y/N]"
    if($a -match '^[Yy]'){
      try { Invoke-Expression $f.FixCmd; Write-Host "Applied." -ForegroundColor Green }
      catch { Write-Host "Failed — apply manually." -ForegroundColor Red }
    } else { Write-Host "Left unchanged." }
  } else {
    Write-Host "(Not auto-run — copy/paste the command above once you've reviewed it.)" -ForegroundColor DarkGray
  }
}
Write-Host "`nDone. Full report: $report" -ForegroundColor Green
