[CmdletBinding()]
param(
    [Parameter(Mandatory)] [switch] $IsolatedTestMachine,
    [string] $Package = ''
)

# This test changes the current user's installation. Run ONLY on a disposable
# Windows desktop/CI runner. It deliberately refuses an existing installation.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (!$IsolatedTestMachine) { throw 'An isolated Windows test machine is required.' }
if (!$Package) {
    $candidates = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot '..\release') -Filter '*_amd64.msi')
    if ($candidates.Count -ne 1) { throw 'Specify one amd64 MSI with -Package.' }
    $Package = $candidates[0].FullName
}
$packageFile = Get-Item -LiteralPath $Package
$installDirectory = Join-Path $env:LOCALAPPDATA 'Programs\WinSSH-Pageant'
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$appKey = 'HKCU:\Software\WinSSH-Pageant'
$shortcut = Join-Path ([Environment]::GetFolderPath('Programs')) 'WinSSH-Pageant.lnk'
$startupShortcut = Join-Path ([Environment]::GetFolderPath('Startup')) 'WinSSH-Pageant.lnk'
if ((Test-Path -LiteralPath $installDirectory) -or (Test-Path -LiteralPath $appKey) -or
    (Test-Path -LiteralPath $shortcut) -or (Test-Path -LiteralPath $startupShortcut) -or
    (Get-Process -Name winssh-pageant -ErrorAction SilentlyContinue)) {
    throw 'Refusing to alter an existing WinSSH-Pageant installation or process.'
}
$existingStartup = Get-ItemPropertyValue -LiteralPath $runKey -Name 'WinSSH-Pageant' -ErrorAction SilentlyContinue
if ($existingStartup) { throw 'An existing startup registration must not be overwritten by this test.' }

function Assert-Install([bool] $Condition, [string] $Message) { if (!$Condition) { throw $Message } }
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class InstallerSmokeSecurity {
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetTokenInformation(IntPtr token, int infoClass, out uint data, uint size, out uint returned);
    public static bool IsElevated(int pid) {
        IntPtr process = OpenProcess(0x1000, false, pid), token = IntPtr.Zero;
        if (process == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            if (!OpenProcessToken(process, 8, out token)) throw new Win32Exception(Marshal.GetLastWin32Error());
            uint elevated, returned;
            if (!GetTokenInformation(token, 20, out elevated, 4, out returned)) throw new Win32Exception(Marshal.GetLastWin32Error());
            return elevated != 0;
        } finally { if (token != IntPtr.Zero) CloseHandle(token); CloseHandle(process); }
    }
}
'@
function Invoke-Msi([string[]] $Arguments) {
    $process = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList $Arguments -WindowStyle Hidden -PassThru
    if (!$process.WaitForExit(120000)) { throw 'Windows Installer did not finish within two minutes.' }
    Assert-Install ($process.ExitCode -eq 0) "Windows Installer exited with $($process.ExitCode). Inspect the saved MSI log."
}

$logDirectory = Join-Path $PSScriptRoot '..\build\installer-smoke'
New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null
$logDirectory = [IO.Path]::GetFullPath($logDirectory)
$msi = New-Object -ComObject WindowsInstaller.Installer
try {
    $database = $msi.OpenDatabase($packageFile.FullName, 0)
    $view = $database.OpenView("SELECT Value FROM Property WHERE Property='ProductCode'")
    [void]$view.Execute()
    $record = $view.Fetch()
    $productCode = $record.GetType().InvokeMember('StringData', [Reflection.BindingFlags]::GetProperty, $null, $record, @(1))
    [void]$view.Close()
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record)
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database)
} finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($msi) }

# Notification-area testing needs a desktop shell. A headless CI runner can start
# its own shell; inability to create one is a test-environment failure, not a pass.
if (!(Get-Process -Name explorer -ErrorAction SilentlyContinue)) {
    Start-Process -FilePath (Join-Path $env:SystemRoot 'explorer.exe') -WindowStyle Hidden | Out-Null
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while (!(Get-Process -Name explorer -ErrorAction SilentlyContinue) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 250 }
}
Assert-Install ($null -ne (Get-Process -Name explorer -ErrorAction SilentlyContinue)) 'An interactive Explorer shell is required for the tray/launch smoke test.'

$installed = $false
try {
    Invoke-Msi @('/i', ('"' + $packageFile.FullName + '"'), '/qn', '/norestart', '/L*v', ('"' + (Join-Path $logDirectory 'install.log') + '"'))
    $installed = $true
    $exe = Join-Path $installDirectory 'winssh-pageant.exe'
    Assert-Install (Test-Path -LiteralPath $exe) 'The executable was not installed.'
    Assert-Install ((Get-ItemPropertyValue -LiteralPath $runKey -Name 'WinSSH-Pageant') -eq ('"' + $exe + '"')) 'Startup registration is missing or unquoted.'
    Assert-Install (Test-Path -LiteralPath $shortcut) 'Start Menu shortcut was not installed.'
    $shell = New-Object -ComObject WScript.Shell
    try {
        $link = $shell.CreateShortcut($shortcut)
        Assert-Install ($link.TargetPath -eq $exe) 'Start Menu shortcut has the wrong target.'
        Assert-Install (![string]::IsNullOrWhiteSpace($link.IconLocation)) 'Start Menu shortcut lacks an icon.'
    } finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell) }
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        $running = @(Get-Process -Name winssh-pageant -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $exe })
        if ($running.Count -eq 0) { Start-Sleep -Milliseconds 250 }
    } while ($running.Count -eq 0 -and [DateTime]::UtcNow -lt $deadline)
    Assert-Install ($running.Count -eq 1) 'Installation did not automatically start exactly one application instance.'
    Assert-Install (![InstallerSmokeSecurity]::IsElevated($running[0].Id)) 'Post-install application launch was elevated.'
    # Repair must stop/restart the same installation without a duplicate process.
    Invoke-Msi @('/fa', $productCode, '/qn', '/norestart', '/L*v', ('"' + (Join-Path $logDirectory 'repair.log') + '"'))
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        $running = @(Get-Process -Name winssh-pageant -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $exe })
        if ($running.Count -eq 0) { Start-Sleep -Milliseconds 250 }
    } while ($running.Count -eq 0 -and [DateTime]::UtcNow -lt $deadline)
    Assert-Install ($running.Count -eq 1) 'Repair did not restart exactly one application instance.'
    Assert-Install (![InstallerSmokeSecurity]::IsElevated($running[0].Id)) 'Post-repair application launch was elevated.'
} finally {
    if ($installed) {
        Invoke-Msi @('/x', $productCode, '/qn', '/norestart', '/L*v', ('"' + (Join-Path $logDirectory 'uninstall.log') + '"'))
    }
}
Assert-Install (!(Test-Path -LiteralPath (Join-Path $installDirectory 'winssh-pageant.exe'))) 'Uninstall left the executable behind.'
Assert-Install (!(Test-Path -LiteralPath $shortcut)) 'Uninstall left the Start Menu shortcut behind.'
$remainingStartup = Get-ItemPropertyValue -LiteralPath $runKey -Name 'WinSSH-Pageant' -ErrorAction SilentlyContinue
Assert-Install ($null -eq $remainingStartup) 'Uninstall left startup registration behind.'
Assert-Install (!(Get-Process -Name winssh-pageant -ErrorAction SilentlyContinue)) 'Uninstall left the application running.'
Write-Host 'PASS actual MSI install, registration, Start Menu/icon, automatic launch, repair/relaunch, uninstall/process exit, and cleanup.'
