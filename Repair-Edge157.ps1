<#
.SYNOPSIS
    Detects and repairs Microsoft Edge / WebView2 Runtime installs that fail with
    "The application was unable to start correctly (0xc000007b)".

.DESCRIPTION
    In November 2026 some Windows PCs received Edge and/or WebView2 Runtime 157.0.4341.42
    with most of the program files in the new version folder built for 32-bit (x86) while the
    product is registered and launched as 64-bit (x64). The 64-bit launcher loads a 32-bit
    msedge.dll and Windows stops it with 0xc000007b. Broken WebView2 also breaks apps built on it
    (new Outlook, Teams, Microsoft 365 Copilot, Acrobat, ChatGPT desktop, Widgets and others).

    What this script does, per product (Edge, WebView2):
      1. Reads the PE header of every .dll/.exe in the newest version folder and counts x86 files.
         A healthy x64 install has about 2 (an IE-mode helper and an x86 WebView loader).
         More than 5, or an x86 msedge.dll, means the install is broken.
      2. If broken (and -CheckOnly was not given): downloads the current x64 installer from Microsoft,
         verifies its Authenticode signature is valid and signed by Microsoft Corporation,
         stops the processes holding the folder, RENAMES the bad version folder to
         <version>.x86bad (nothing is deleted, so you can roll back), then installs fresh.
         Renaming first matters: an in-place MSI repair skips files whose version already
         matches, which leaves the 32-bit files in place.
      3. Also broken: the registered version has no folder (Edge: the launcher's version; WebView2: the
         version registered with EdgeUpdate). This happens when an earlier repair was interrupted after
         the rename. WebView2 then gets a fresh install with its EdgeUpdate registration exported to a
         .reg file first and restored if the install does not take.
      4. Re-checks both products and test-launches Edge headless.

    v5 (2026-11-09): WebView2 registered-version check and fresh-install fallback; never renames an
    older healthy WebView2 folder.
    v6 (2026-11-09): downloads fall back from Invoke-WebRequest to BITS to curl.exe, two tries each.

    Run as Administrator or SYSTEM (RMM). Windows PowerShell 5.1 or later. x64 Windows only.
    Running it will close Edge and any app using WebView2 (Teams, Outlook...) on the PC
    if a repair is needed. Healthy installs are never touched.

    No data is sent anywhere except downloads from Microsoft (edgeupdates.microsoft.com, go.microsoft.com).
    Log: %windir%\Temp\Repair-Edge157\

.PARAMETER CheckOnly
    Report only. Change nothing.

.PARAMETER FromBootTask
    Internal. Used by the one-time startup task the script registers when a folder is locked
    by a running app and can't be renamed; the task finishes the repair before anyone signs in
    and then removes itself.

.EXAMPLE
    .\Repair-Edge157.ps1 -CheckOnly
    .\Repair-Edge157.ps1

.NOTES
    Published by Boston Managed IT (bostonmit.com) and SWFIT (swfit.io). MIT License.
    Provided as is, without warranty. Test on one PC before deploying widely.
    Exit codes: 0 = healthy or fixed, 1 = still broken after repair (or broken with -CheckOnly), 2 = not run as admin / unsupported.
#>
[CmdletBinding()]
param([switch]$CheckOnly, [switch]$FromBootTask)
$script:needBoot = $false

$ErrorActionPreference = 'Continue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = 'SilentlyContinue'

if (-not [Environment]::Is64BitOperatingSystem) { Write-Output 'Not a 64-bit OS; this issue does not apply.'; exit 2 }
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin -and -not $CheckOnly) { Write-Output 'Run this script as Administrator (or SYSTEM). -CheckOnly works without admin.'; exit 2 }

$work = if ($admin) { Join-Path $env:windir 'Temp\Repair-Edge157' } else { Join-Path $env:TEMP 'Repair-Edge157' }
New-Item $work -ItemType Directory -Force | Out-Null
Start-Transcript -Path (Join-Path $work ("run-{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))) -Append | Out-Null

$pf86 = ${env:ProgramFiles(x86)}
$Products = @(
    @{ Name = 'Edge';     Root = "$pf86\Microsoft\Edge\Application";        Main = 'msedge.dll' },
    @{ Name = 'WebView2'; Root = "$pf86\Microsoft\EdgeWebView\Application"; Main = 'msedge.dll' }
)

function Get-Machine([string]$Path) {
    # Returns the PE machine type: 8664 = x64, 14C = x86, AA64 = ARM64.
    try {
        $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
        try {
            $br = New-Object IO.BinaryReader($fs)
            $null = $fs.Seek(0x3C, 'Begin'); $off = $br.ReadInt32()
            $null = $fs.Seek($off + 4, 'Begin')
            '{0:X}' -f $br.ReadUInt16()
        } finally { $fs.Close() }
    } catch { '?' }
}

$WV2Guid = '{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
$WV2Keys = @("HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\$WV2Guid",
             "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientState\$WV2Guid")

function Get-WebView2Registered {
    # Machine-wide WebView2 Runtime version as registered with EdgeUpdate.
    (Get-ItemProperty $WV2Keys[0] -Name pv -ErrorAction SilentlyContinue).pv
}

function Get-InstallState($Product) {
    $ver = Get-ChildItem $Product.Root -Directory -ErrorAction SilentlyContinue |
        Where-Object Name -match '^\d+\.\d+\.\d+\.\d+$' |
        Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
    # The launcher (Application\msedge.exe) loads the folder matching its own version.
    # If that folder is missing, Windows reports "side-by-side configuration is incorrect".
    # WebView2 has no launcher: apps find it through the version registered with EdgeUpdate (pv).
    # If that folder is missing, apps report "can't find a required component... Get Edge WebView2"
    # and the WebView2 installer says it is already installed.
    if ($Product.Name -eq 'WebView2') {
        $want = Get-WebView2Registered
        $from = 'registered'
    } else {
        $launcher = Join-Path $Product.Root 'msedge.exe'
        $want = if (Test-Path $launcher) { (Get-Item $launcher).VersionInfo.ProductVersion } else { $null }
        $from = 'launcher'
    }
    $orphan = [bool]($want -and -not (Test-Path (Join-Path $Product.Root "$want\$($Product.Main)")))
    if (-not $ver) { return [pscustomobject]@{ Folder = $null; Bad = $orphan; X86Bad = $false; Orphan = $orphan; Want = $want; Summary = "no version folder ($from v$want)" } }
    $files = Get-ChildItem $ver.FullName -Recurse -Include *.dll, *.exe -File -ErrorAction SilentlyContinue
    $x86 = @($files | Where-Object { (Get-Machine $_.FullName) -eq '14C' }).Count
    $main = Get-Machine (Join-Path $ver.FullName $Product.Main)
    $s = "v$($ver.Name) x86 files=$x86/$($files.Count) $($Product.Main)=$main"
    if ($orphan) { $s += " | $from v$want has no folder" }
    [pscustomobject]@{
        Folder  = $ver
        Want    = $want
        Orphan  = $orphan
        X86Bad  = ($x86 -gt 5 -or $main -eq '14C')
        Bad     = ($x86 -gt 5 -or $main -eq '14C' -or $orphan)
        Summary = $s
    }
}

function Save-SignedFile([string]$Url, [string]$OutFile) {
    # Three downloaders, two tries each: some networks break one client (TLS "decryption operation
    # failed", connection reset mid-download) but not another. BITS also resumes large files.
    $ok = $false
    $tries = @(
        @{ n = 'Invoke-WebRequest'; s = { Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -ErrorAction Stop } },
        @{ n = 'BITS';              s = { Start-BitsTransfer -Source $Url -Destination $OutFile -Priority Foreground -ErrorAction Stop } },
        @{ n = 'curl.exe';          s = { & "$env:windir\System32\curl.exe" -sSfL --retry 3 --retry-delay 5 -o $OutFile $Url 2>&1 | Out-Null
                                          if ($LASTEXITCODE -ne 0) { throw "curl exit $LASTEXITCODE" } } }
    )
    foreach ($t in $tries) {
        for ($a = 1; $a -le 2 -and -not $ok; $a++) {
            Remove-Item $OutFile -Force -ErrorAction SilentlyContinue
            try {
                & $t.s
                if ((Test-Path $OutFile) -and (Get-Item $OutFile).Length -gt 1MB) { $ok = $true }
                else { throw 'download came back empty' }
            } catch {
                Write-Output "  download via $($t.n) failed (try $a): $($_.Exception.Message)"
                Start-Sleep -Seconds 5
            }
        }
        if ($ok) { if ($t.n -ne 'Invoke-WebRequest') { Write-Output "  downloaded via $($t.n)" }; break }
    }
    if (-not $ok) { throw "Could not download $Url (Invoke-WebRequest, BITS and curl.exe all failed)" }
    $sig = Get-AuthenticodeSignature $OutFile
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        Remove-Item $OutFile -Force -ErrorAction SilentlyContinue
        throw "Signature check failed for $OutFile ($($sig.Status))"
    }
}

function Stop-Holders([string]$Dir) {
    # Processes with a module loaded from the folder (Edge, WebView2 hosts such as Teams or Outlook).
    for ($i = 0; $i -lt 3; $i++) {
        $h = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
            try { $_.Path -like "$Dir*" -or ($_.Modules | Where-Object FileName -like "$Dir*" | Select-Object -First 1) } catch { $false }
        })
        if (-not $h) { return }
        Write-Output ("  stopping: " + (($h | Select-Object -ExpandProperty Name -Unique) -join ', '))
        $h | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
    }
}

$EdgeServices = 'edgeupdate', 'edgeupdatem', 'MicrosoftEdgeElevationService'
$HostNames = 'msedge', 'msedgewebview2', 'msedge_proxy', 'identity_helper', 'ms-teams', 'olk', 'OUTLOOK',
             'M365Copilot', 'Copilot', 'Widgets', 'WidgetService', 'Acrobat', 'AcroCEF', 'ChatGPT', 'SearchHost'

function Stop-EdgeServices {
    foreach ($s in $EdgeServices) { Stop-Service $s -Force -ErrorAction SilentlyContinue }
    Get-Process MicrosoftEdgeUpdate -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

function Move-BadFolder($State) {
    $src = $State.Folder.FullName
    $target = "$src.x86bad"
    if (Test-Path $target) { $target = "$target-$(Get-Date -Format yyyyMMddHHmmss)" }
    for ($i = 1; $i -le 6; $i++) {
        try {
            Rename-Item $src (Split-Path $target -Leaf) -ErrorAction Stop
            Write-Output "  renamed bad folder to $(Split-Path $target -Leaf)"
            return $true
        } catch {
            Write-Output "  rename attempt $i failed (folder in use), closing apps and retrying"
            Stop-EdgeServices
            Stop-Holders $src
            Get-Process -Name $HostNames -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds (3 * $i)
        }
    }
    return $false
}

function Register-BootRepair {
    # Folder stays locked: finish the repair at next startup, before anyone signs in. Runs once.
    $dst = Join-Path $env:ProgramData 'Repair-Edge157\Repair-Edge157.ps1'
    New-Item (Split-Path $dst) -ItemType Directory -Force | Out-Null
    Copy-Item $PSCommandPath $dst -Force
    $cmd = "-NoProfile -ExecutionPolicy Bypass -File `"$dst`" -FromBootTask"
    $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $cmd
    $trg = New-ScheduledTaskTrigger -AtStartup
    $pr  = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName 'Repair-Edge157' -Action $act -Trigger $trg -Principal $pr -Force | Out-Null
    Write-Output '  folder still locked: repair scheduled for next restart (task Repair-Edge157)'
}

function Repair-Edge($Product, $State) {
    # Windows PowerShell 5.1 passes the whole JSON array down the pipeline as one object,
    # so unroll it with ForEach-Object before filtering to the Stable channel.
    $feed = @(Invoke-RestMethod 'https://edgeupdates.microsoft.com/api/products' -UseBasicParsing)
    $rel = ($feed | ForEach-Object { $_ } | Where-Object { $_.Product -eq 'Stable' }).Releases |
        Where-Object { $_.Platform -eq 'Windows' -and $_.Architecture -eq 'x64' } |
        Sort-Object { [version]$_.ProductVersion } -Descending | Select-Object -First 1
    $url = ($rel.Artifacts | Where-Object ArtifactName -eq 'msi' | Select-Object -First 1).Location
    if (-not $url) { throw 'Could not find the Edge Stable x64 MSI on edgeupdates.microsoft.com' }
    # This file name matches the registered Edge MSI product, so Windows Installer accepts it.
    $msi = Join-Path $work 'MicrosoftEdgeEnterpriseX64.msi'
    Write-Output "  downloading Edge Stable x64 $($rel.ProductVersion)"
    Save-SignedFile $url $msi
    Stop-EdgeServices
    Stop-Holders $Product.Root
    # Only rename a folder that actually holds the broken files (not an older healthy one).
    if ($State.Folder -and $State.X86Bad -and -not (Move-BadFolder $State)) { $script:needBoot = $true; return }
    $log = Join-Path $work 'edge-msi.log'
    # REINSTALLMODE=amus: "a" rewrites every file even when the version already matches.
    $p = Start-Process msiexec.exe -ArgumentList "/i `"$msi`" REINSTALL=ALL REINSTALLMODE=amus /qn /norestart /l*v `"$log`"" -Wait -PassThru
    Write-Output "  msiexec forced reinstall exit $($p.ExitCode)"
    $target = Join-Path $Product.Root "$($rel.ProductVersion)\$($Product.Main)"
    if (-not (Test-Path $target)) {
        $p = Start-Process msiexec.exe -ArgumentList "/i `"$msi`" ALLOWDOWNGRADE=1 REINSTALL=ALL REINSTALLMODE=amus /qn /norestart /l*v `"$log.2`"" -Wait -PassThru
        Write-Output "  msiexec second attempt exit $($p.ExitCode)"
    }
    Write-Output "  $($rel.ProductVersion) folder present: $(Test-Path $target)"
}

function Repair-WebView2($Product, $State) {
    $exe = Join-Path $work 'MicrosoftEdgeWebView2RuntimeInstallerX64.exe'
    Write-Output '  downloading WebView2 Runtime Evergreen standalone x64'
    Save-SignedFile 'https://go.microsoft.com/fwlink/?linkid=2124701' $exe
    Stop-EdgeServices
    Stop-Holders $Product.Root
    Get-Process -Name $HostNames -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    # Only rename a folder that actually holds the broken files (not an older healthy one).
    if ($State.Folder -and $State.X86Bad -and -not (Move-BadFolder $State)) { $script:needBoot = $true; return }
    $p = Start-Process $exe -ArgumentList '/silent /install' -Wait -PassThru
    Write-Output ("  installer exit 0x{0:X}" -f $p.ExitCode)
    if (-not (Get-InstallState $Product).Orphan) { return }
    # Still registered to a version with no folder: the installer saw "already installed" and did nothing.
    # Export the EdgeUpdate registration, remove it, install fresh. Put it back if that fails too.
    Write-Output '  registered version still has no folder: fresh install'
    $saved = @()
    $i = 0
    foreach ($k in $WV2Keys) {
        if (-not (Test-Path $k)) { continue }
        $i++
        $reg = Join-Path $work ("webview2-reg-{0}-{1:yyyyMMddHHmmss}.reg" -f $i, (Get-Date))
        & reg.exe export ($k -replace '^HKLM:', 'HKLM') $reg /y | Out-Null
        if (-not (Test-Path $reg)) { Write-Output "  could not export $k; not removing it"; return }
        Remove-Item $k -Recurse -Force -ErrorAction SilentlyContinue
        $saved += $reg
    }
    Write-Output "  registration exported to $work and removed ($($saved.Count) keys)"
    Stop-EdgeServices
    $p = Start-Process $exe -ArgumentList '/silent /install' -Wait -PassThru
    Write-Output ("  fresh install exit 0x{0:X}" -f $p.ExitCode)
    $after = Get-InstallState $Product
    if (-not (Get-WebView2Registered) -or $after.Orphan) {
        foreach ($reg in $saved) { & reg.exe import $reg 2>&1 | Out-Null }
        Write-Output '  fresh install did not register a working version: registration restored'
    }
}

Write-Output "Repair-Edge157 on $env:COMPUTERNAME $(if ($CheckOnly) {'(check only)'})"
$anyBad = $false
foreach ($prod in $Products) {
    $s = Get-InstallState $prod
    Write-Output ("{0,-9} {1,-7} {2}" -f $prod.Name, $(if ($s.Bad) {'BROKEN'} else {'ok'}), $s.Summary)
    if (-not $s.Bad) { continue }
    $anyBad = $true
    if ($CheckOnly) { continue }
    try {
        if ($prod.Name -eq 'Edge') { Repair-Edge $prod $s } else { Repair-WebView2 $prod $s }
    } catch { Write-Output "  repair failed: $($_.Exception.Message)" }
}

if ($CheckOnly) {
    Stop-Transcript | Out-Null
    if ($anyBad) { Write-Output 'RESULT: BROKEN (run without -CheckOnly to repair)'; exit 1 }
    Write-Output 'RESULT: OK'; exit 0
}

$stillBad = $false
foreach ($prod in $Products) {
    $s = Get-InstallState $prod
    if ($s.Bad) { $stillBad = $true }
    Write-Output ("after: {0,-9} {1,-7} {2}" -f $prod.Name, $(if ($s.Bad) {'BROKEN'} else {'ok'}), $s.Summary)
}

# Headless launch test with a throwaway profile (does not touch user profiles).
$edgeExe = "$pf86\Microsoft\Edge\Application\msedge.exe"
if (Test-Path $edgeExe) {
    $prof = Join-Path $work 'launch-test'
    try {
        $p = Start-Process $edgeExe -ArgumentList '--headless', '--disable-gpu', '--no-first-run', "--user-data-dir=$prof", 'about:blank' -PassThru
        if (-not $p.WaitForExit(20000)) {
            Write-Output 'launch test: Edge started and kept running (OK)'
            Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" | Where-Object CommandLine -like "*$prof*" |
                ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        } elseif ($p.ExitCode -eq 0) { Write-Output 'launch test: exit 0 (OK)' }
        else { Write-Output ('launch test: exit 0x{0:X8}' -f $p.ExitCode); if (('{0:X8}' -f $p.ExitCode) -eq 'C000007B') { $stillBad = $true } }
    } catch { Write-Output "launch test failed: $($_.Exception.Message)" }
    Start-Sleep -Seconds 2
    Remove-Item $prof -Recurse -Force -ErrorAction SilentlyContinue
}

if ($FromBootTask) { Unregister-ScheduledTask -TaskName 'Repair-Edge157' -Confirm:$false -ErrorAction SilentlyContinue }
elseif ($stillBad -and $script:needBoot) { Register-BootRepair }
foreach ($s in $EdgeServices) { Start-Service $s -ErrorAction SilentlyContinue }

Stop-Transcript | Out-Null
if ($stillBad -and $script:needBoot -and -not $FromBootTask) { Write-Output 'RESULT: PENDING RESTART (repair finishes automatically at next startup)'; exit 1 }
if ($stillBad) { Write-Output 'RESULT: STILL BROKEN (see log in %windir%\Temp\Repair-Edge157)'; exit 1 }
Write-Output 'RESULT: FIXED or healthy'
exit 0
