[CmdletBinding()]
param([string] $ReleaseDirectory = (Join-Path $PSScriptRoot '..\release'))

# Read-only artifact verification. Does not install, launch, or register anything.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$installer = New-Object -ComObject WindowsInstaller.Installer

function Assert-Package([bool] $Condition, [string] $Message) {
    if (!$Condition) { throw $Message }
}
function Read-MsiTable($Database, [string] $Table, [string[]] $Columns) {
    $query = 'SELECT `' + ($Columns -join '`,`') + '` FROM `' + $Table + '`'
    $view = $Database.OpenView($query)
    try {
        [void]$view.Execute()
        while ($null -ne ($record = $view.Fetch())) {
            $row = [ordered]@{}
            for ($i = 0; $i -lt $Columns.Count; $i++) {
                $row[$Columns[$i]] = $record.GetType().InvokeMember('StringData', [Reflection.BindingFlags]::GetProperty, $null, $record, @($i + 1))
            }
            [pscustomobject]$row
            [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record)
        }
    } finally {
        [void]$view.Close()
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
    }
}

try {
    $packages = @(Get-ChildItem -LiteralPath $ReleaseDirectory -Filter '*.msi')
    Assert-Package ($packages.Count -gt 0) 'No MSI packages found.'
    foreach ($package in $packages) {
        $db = $installer.OpenDatabase($package.FullName, 0)
        try {
            $properties = @{}
            Read-MsiTable $db 'Property' @('Property', 'Value') | ForEach-Object { $properties[$_.Property] = $_.Value }
            Assert-Package ($properties.ProductName -eq 'WinSSH-Pageant') 'Incorrect product name.'
            Assert-Package (!$properties.ContainsKey('ALLUSERS')) 'The MSI must be strictly per-user.'
            Assert-Package ($properties.UpgradeCode -eq '{307F134F-BAE2-4610-9F8F-6A7C7DDB3980}') 'Upgrade family changed.'
            Assert-Package ($properties.LAUNCHAPP -eq '1') 'Launch after installation must be enabled by default.'
            Assert-Package ($properties.REBOOT -eq 'ReallySuppress') 'Installer must not reboot the desktop.'

            $directories = @(Read-MsiTable $db 'Directory' @('Directory', 'Directory_Parent', 'DefaultDir'))
            Assert-Package (@($directories | Where-Object { $_.Directory -eq 'ProgramsFolder' -and $_.Directory_Parent -eq 'LocalAppDataFolder' }).Count -eq 1) 'Install root must be per-user LocalAppData.'
            Assert-Package (@($directories | Where-Object { $_.Directory -eq 'INSTALLDIR' -and $_.Directory_Parent -eq 'ProgramsFolder' }).Count -eq 1) 'Incorrect application directory.'

            $registry = @(Read-MsiTable $db 'Registry' @('Registry', 'Root', 'Key', 'Name', 'Value', 'Component_'))
            Assert-Package (@($registry | Where-Object { $_.Root -ne '1' }).Count -eq 0) 'Package may only write HKCU.'
            Assert-Package (@($registry | Where-Object { $_.Key -like '*StartupApproved*' }).Count -eq 0) 'Do not override the user startup preference.'
            Assert-Package (@($registry | Where-Object {
                $_.Key -eq 'Software\Microsoft\Windows\CurrentVersion\Run' -and $_.Name -eq 'WinSSH-Pageant' -and $_.Value -eq '"[#ApplicationExe]"'
            }).Count -eq 1) 'Missing quoted Task Manager startup registration.'

            $shortcuts = @(Read-MsiTable $db 'Shortcut' @('Shortcut', 'Directory_', 'Name', 'Target', 'Icon_'))
            Assert-Package (@($shortcuts | Where-Object { $_.Directory_ -eq 'ProgramMenuFolder' -and $_.Target -eq '[#ApplicationExe]' -and $_.Icon_ -eq $properties.ARPPRODUCTICON }).Count -eq 1) 'Missing Start Menu shortcut with the application icon.'
            $icons = @(Read-MsiTable $db 'Icon' @('Name'))
            Assert-Package ($icons.Name -contains $properties.ARPPRODUCTICON) 'Missing embedded installer icon.'

            $actions = @(Read-MsiTable $db 'CustomAction' @('Action', 'Type', 'Source', 'Target'))
            Assert-Package (@($actions | Where-Object { $_.Action -eq 'StopApplication' -and $_.Source -eq 'ApplicationExe' -and $_.Target -eq '--exit' -and $_.Type -eq '18' }).Count -eq 1) 'Shutdown must use the installed executable and check its exit status.'
            Assert-Package (@($actions | Where-Object { $_.Action -eq 'LaunchApplication' -and $_.Target -eq 'WixUnelevatedShellExec' }).Count -eq 1) 'Launch must use the unelevated shell custom action.'
            Assert-Package (@($actions | Where-Object { $_.Target -match '(?i)taskkill|powershell|cmd\.exe' }).Count -eq 0) 'Unexpected shell/process-kill custom action.'

            $sequence = @{}
            Read-MsiTable $db 'InstallExecuteSequence' @('Action', 'Condition', 'Sequence') | ForEach-Object { $sequence[$_.Action] = $_ }
            Assert-Package ([int]$sequence.StopApplication.Sequence -lt [int]$sequence.InstallValidate.Sequence) 'Stop must precede file-in-use validation.'
            Assert-Package ([int]$sequence.LaunchApplication.Sequence -gt [int]$sequence.InstallFinalize.Sequence) 'Launch must follow the committed install.'
            Assert-Package ([int]$sequence.RemoveExistingProducts.Sequence -gt [int]$sequence.InstallInitialize.Sequence) 'Upgrade removal must be rollback protected.'

            $files = @(Read-MsiTable $db 'File' @('File', 'FileName', 'FileSize', 'Version'))
            Assert-Package ($files.Count -eq 5) 'MSI must contain the app, README, review, license, and third-party notices.'
            $exe = $files | Where-Object { $_.File -eq 'ApplicationExe' }
            Assert-Package ($exe.Version -eq ($properties.ProductVersion + '.0')) 'Embedded application version disagrees with MSI version.'
            $zipPath = [IO.Path]::ChangeExtension($package.FullName, '.zip')
            $archive = [IO.Compression.ZipFile]::OpenRead($zipPath)
            try {
                Assert-Package ($archive.Entries.Count -eq 5) 'Portable ZIP has unexpected entries.'
                foreach ($name in @('winssh-pageant.exe', 'README.md', 'REVIEW.md', 'LICENSE', 'THIRD_PARTY_NOTICES.txt')) {
                    Assert-Package ($null -ne $archive.GetEntry($name)) "ZIP is missing $name."
                }
                $entry = $archive.GetEntry('winssh-pageant.exe')
                Assert-Package ($entry.Length -eq [int64]$exe.FileSize) 'MSI and ZIP executable sizes disagree.'
                $stream = $entry.Open()
                $memory = [IO.MemoryStream]::new()
                try { $stream.CopyTo($memory); $bytes = $memory.ToArray() } finally { $stream.Dispose(); $memory.Dispose() }
                $pe = [BitConverter]::ToInt32($bytes, 0x3c)
                $machine = [BitConverter]::ToUInt16($bytes, $pe + 4)
                $subsystem = [BitConverter]::ToUInt16($bytes, $pe + 24 + 68)
                $expectedMachine = if ($package.BaseName.EndsWith('_amd64')) { 0x8664 } elseif ($package.BaseName.EndsWith('_arm64')) { 0xAA64 } else { 0x14c }
                Assert-Package ($machine -eq $expectedMachine) 'Executable architecture disagrees with package name.'
                Assert-Package ($subsystem -eq 2) 'Release executable must use the Windows GUI subsystem.'
                $binaryText = [Text.Encoding]::UTF8.GetString($bytes)
                foreach ($marker in @('requestedExecutionLevel level="asInvoker"', 'PerMonitorV2,PerMonitor',
                    'Microsoft.Windows.Common-Controls', '8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a')) {
                    Assert-Package ($binaryText.Contains($marker)) "Missing embedded manifest setting: $marker"
                }
            } finally { $archive.Dispose() }
            Write-Host "PASS $($package.Name): per-user registration, startup, Start Menu, icon, upgrades, shutdown, launch, version, architecture, ZIP."
        } finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($db) }
    }
} finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer) }
