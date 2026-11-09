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
      3. Re-checks both products and test-launches Edge headless.

    Run as Administrator or SYSTEM (RMM). Windows PowerShell 5.1 or later. x64 Windows only.
    Running it will close Edge and any app using WebView2 (Teams, Outlook...) on the PC
    if a repair is needed. Healthy installs are never touched.

    No data is sent anywhere except downloads from Microsoft (edgeupdates.microsoft.com, go.microsoft.com).
    Log: %windir%\Temp\Repair-Edge157\

.PARAMETER CheckOnly
    Report only. Change nothing.

.EXAMPLE
    .\Repair-Edge157.ps1 -CheckOnly
    .\Repair-Edge157.ps1

.NOTES
    Published by Boston Managed IT (bostonmit.com) and SWFIT (swfit.io). MIT License.
    Provided as is, without warranty. Test on one PC before deploying widely.
    Exit codes: 0 = healthy or fixed, 1 = still broken after repair (or broken with -CheckOnly), 2 = not run as admin / unsupported.
#>
[CmdletBinding()]
param([switch]$CheckOnly)

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

function Get-InstallState($Product) {
    $ver = Get-ChildItem $Product.Root -Directory -ErrorAction SilentlyContinue |
        Where-Object Name -match '^\d+\.\d+\.\d+\.\d+$' |
        Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
    if (-not $ver) { return [pscustomobject]@{ Folder = $null; Bad = $false; Summary = 'not installed' } }
    $files = Get-ChildItem $ver.FullName -Recurse -Include *.dll, *.exe -File -ErrorAction SilentlyContinue
    $x86 = @($files | Where-Object { (Get-Machine $_.FullName) -eq '14C' }).Count
    $main = Get-Machine (Join-Path $ver.FullName $Product.Main)
    [pscustomobject]@{
        Folder  = $ver
        Bad     = ($x86 -gt 5 -or $main -eq '14C')
        Summary = "v$($ver.Name) x86 files=$x86/$($files.Count) $($Product.Main)=$main"
    }
}

function Save-SignedFile([string]$Url, [string]$OutFile) {
    Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
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

function Move-BadFolder($State) {
    $target = "$($State.Folder.FullName).x86bad"
    if (Test-Path $target) { $target = "$target-$(Get-Date -Format yyyyMMddHHmmss)" }
    Rename-Item $State.Folder.FullName (Split-Path $target -Leaf) -ErrorAction Stop
    Write-Output "  renamed bad folder to $(Split-Path $target -Leaf)"
}

function Repair-Edge($Product, $State) {
    $rel = (Invoke-RestMethod 'https://edgeupdates.microsoft.com/api/products' -UseBasicParsing |
        Where-Object Product -eq 'Stable').Releases |
        Where-Object { $_.Platform -eq 'Windows' -and $_.Architecture -eq 'x64' } |
        Sort-Object { [version]$_.ProductVersion } -Descending | Select-Object -First 1
    $url = ($rel.Artifacts | Where-Object ArtifactName -eq 'msi' | Select-Object -First 1).Location
    if (-not $url) { throw 'Could not find the Edge Stable x64 MSI on edgeupdates.microsoft.com' }
    # This file name matches the registered Edge MSI product, so Windows Installer accepts it.
    $msi = Join-Path $work 'MicrosoftEdgeEnterpriseX64.msi'
    Write-Output "  downloading Edge Stable x64 $($rel.ProductVersion)"
    Save-SignedFile $url $msi
    Stop-Holders $Product.Root
    Move-BadFolder $State
    $log = Join-Path $work 'edge-msi.log'
    $p = Start-Process msiexec.exe -ArgumentList "/i `"$msi`" REINSTALL=ALL REINSTALLMODE=vamus /qn /norestart /l*v `"$log`"" -Wait -PassThru
    Write-Output "  msiexec reinstall exit $($p.ExitCode)"
    $after = Get-InstallState $Product
    if (-not $after.Folder -or $after.Bad) {
        $p = Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart /l*v `"$log.2`"" -Wait -PassThru
        Write-Output "  msiexec install exit $($p.ExitCode)"
    }
}

function Repair-WebView2($Product, $State) {
    $exe = Join-Path $work 'MicrosoftEdgeWebView2RuntimeInstallerX64.exe'
    Write-Output '  downloading WebView2 Runtime Evergreen standalone x64'
    Save-SignedFile 'https://go.microsoft.com/fwlink/?linkid=2124701' $exe
    Stop-Holders $State.Folder.FullName
    Move-BadFolder $State
    $p = Start-Process $exe -ArgumentList '/silent /install' -Wait -PassThru
    Write-Output ("  installer exit 0x{0:X}" -f $p.ExitCode)
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

Stop-Transcript | Out-Null
if ($stillBad) { Write-Output 'RESULT: STILL BROKEN (see log in %windir%\Temp\Repair-Edge157)'; exit 1 }
Write-Output 'RESULT: FIXED or healthy'
exit 0
