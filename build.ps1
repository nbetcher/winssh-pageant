[CmdletBinding()]
param (
    [string] $BuildPath = "build",
    [ValidateSet('amd64', 'arm64', '386')]
    [string[]] $Architectures = @('amd64', 'arm64'),
    [switch] $Release,
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string] $ReleasePath = 'winssh-pageant',
    [Alias('Version')]
    [string] $ver = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = $PSScriptRoot
$wixVersion = '6.0.2'
$resourceVersion = 'v1.7.0'

function Invoke-Checked([string] $Command, [string[]] $Arguments) {
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Command failed with exit code $LASTEXITCODE" }
}

# Only write within the checkout, preserving unrelated artifacts. Never recursively
# delete a caller-supplied directory.
$outRoot = [IO.Path]::GetFullPath((Join-Path $repo $BuildPath))
if (!$outRoot.StartsWith($repo.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'BuildPath must be a child directory of this checkout.'
}
if (!$ver) { $ver = (Get-Content -LiteralPath (Join-Path $repo 'VERSION') -Raw).Trim() }
$ver = $ver.TrimStart('v')
if ($ver -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') {
    throw 'Version must contain exactly three numeric components, for example 2.4.1.'
}
$parts = $ver.Split('.')
if ([int]$parts[0] -gt 255 -or [int]$parts[1] -gt 255 -or [int]$parts[2] -gt 65535) {
    throw 'Version exceeds Windows Installer limits (255.255.65535).'
}

$toolsDir = Join-Path $repo '.tools'
$resourceTool = Join-Path $toolsDir 'go\goversioninfo.exe'
$wixTool = Join-Path $toolsDir 'wix\wix.exe'
$releaseDir = Join-Path $repo 'release'
$oldEnvironment = @{}
foreach ($name in @('GOOS', 'GOARCH', 'GOBIN', 'CGO_ENABLED')) {
    $oldEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
$generatedResources = @()
Push-Location $repo
try {
    New-Item -ItemType Directory -Force -Path $toolsDir, $outRoot | Out-Null
    if (!(Test-Path -LiteralPath $resourceTool)) {
        $env:GOBIN = Join-Path $toolsDir 'go'
        Invoke-Checked 'go' @('install', "github.com/josephspurrier/goversioninfo/cmd/goversioninfo@$resourceVersion")
    }
    $resourceBuildInfo = & go version -m $resourceTool
    if ($LASTEXITCODE -ne 0 -or !($resourceBuildInfo -match "\smod\s+github.com/josephspurrier/goversioninfo\s+$([regex]::Escape($resourceVersion))\s")) {
        throw "Expected goversioninfo $resourceVersion; remove .tools\go\goversioninfo.exe and rebuild to restore it."
    }
    if ($Release) {
        New-Item -ItemType Directory -Force -Path $releaseDir | Out-Null
        if (!(Test-Path -LiteralPath $wixTool)) {
            Invoke-Checked 'dotnet' @('tool', 'install', 'wix', '--tool-path', (Join-Path $toolsDir 'wix'), '--version', $wixVersion)
        }
        $installedWixVersion = & $wixTool --version
        if ($LASTEXITCODE -ne 0 -or $installedWixVersion -notlike "$wixVersion+*") {
            throw "Expected local WiX $wixVersion; remove .tools\wix and rebuild to restore it."
        }
        Push-Location $toolsDir
        try {
            foreach ($extension in @('WixToolset.UI.wixext', 'WixToolset.Util.wixext')) {
                $extensionFile = Join-Path $toolsDir ".wix\extensions\$extension\$wixVersion\wixext6\$extension.dll"
                if (!(Test-Path -LiteralPath $extensionFile)) {
                    Invoke-Checked $wixTool @('extension', 'add', "$extension/$wixVersion")
                }
            }
        } finally { Pop-Location }
    }
    $env:GOOS = 'windows'
    $env:CGO_ENABLED = '0'
    $checksums = [Collections.Generic.List[string]]::new()
    foreach ($arch in ($Architectures | Select-Object -Unique)) {
        $env:GOARCH = $arch
        $archDir = Join-Path $outRoot "$ver\$arch"
        New-Item -ItemType Directory -Force -Path $archDir | Out-Null
        $resourceFile = Join-Path $repo "release_resource_windows_$arch.syso"
        if (Test-Path -LiteralPath $resourceFile) { throw "Build resource already exists: $resourceFile" }
        $generatedResources += $resourceFile
        $resourceArgs = @('-o', $resourceFile, '-icon', (Join-Path $repo 'resources\icon\icon.ico'),
            '-manifest', (Join-Path $repo 'resources\app.manifest'),
            '-file-version', $ver, '-product-version', $ver, '-propagate-ver-strings')
        if ($arch -eq '386') { $resourceArgs += '-64=false' }
        if ($arch -eq 'arm64') { $resourceArgs += '-arm' }
        $resourceArgs += (Join-Path $repo 'resources\versioninfo.json')
        Invoke-Checked $resourceTool $resourceArgs
        $binary = Join-Path $archDir 'winssh-pageant.exe'
        $buildArgs = @('build', '-mod=readonly', '-trimpath', '-o', $binary)
        $linkFlags = "-X main.version=$ver"
        if ($Release) { $linkFlags += ' -w -s -H=windowsgui' }
        $buildArgs += @('-ldflags', $linkFlags)
        $buildArgs += '.'
        Invoke-Checked 'go' $buildArgs
        Copy-Item -LiteralPath (Join-Path $repo 'README.md'), (Join-Path $repo 'REVIEW.md'), (Join-Path $repo 'LICENSE') -Destination $archDir -Force
        $notice = [Collections.Generic.List[string]]::new()
        $notice.Add('Third-party software notices for this build')
        $notice.Add('')
        foreach ($dependency in @('github.com/Microsoft/go-winio', 'golang.org/x/sys')) {
            $moduleJson = & go list -m -json $dependency
            if ($LASTEXITCODE -ne 0) { throw "Cannot inspect dependency license: $dependency" }
            $module = $moduleJson | ConvertFrom-Json
            $notice.Add("$($module.Path) $($module.Version)")
            $notice.Add((Get-Content -LiteralPath (Join-Path $module.Dir 'LICENSE') -Raw))
        }
        $goRoot = & go env GOROOT
        if ($LASTEXITCODE -ne 0) { throw 'Cannot locate the Go runtime license.' }
        $goVersion = & go env GOVERSION
        if ($LASTEXITCODE -ne 0) { throw 'Cannot read the Go toolchain version.' }
        $notice.Add("Go standard library and runtime $goVersion (https://go.dev/)")
        $notice.Add((Get-Content -LiteralPath (Join-Path $goRoot 'LICENSE') -Raw))
        $notice.Add("WiX Toolset $wixVersion (MSI installer components only; https://github.com/wixtoolset/wix/tree/v$wixVersion)")
        $notice.Add((Get-Content -LiteralPath (Join-Path $repo 'packaging\wix-license.txt') -Raw))
        $notice | Set-Content -LiteralPath (Join-Path $archDir 'THIRD_PARTY_NOTICES.txt') -Encoding utf8
        if ($Release) {
            $stem = "$ReleasePath-${ver}_$arch"
            $zip = Join-Path $releaseDir "$stem.zip"
            Compress-Archive -LiteralPath $binary, (Join-Path $archDir 'README.md'), (Join-Path $archDir 'REVIEW.md'),
                (Join-Path $archDir 'LICENSE'), (Join-Path $archDir 'THIRD_PARTY_NOTICES.txt') -DestinationPath $zip -Force
            $msi = Join-Path $releaseDir "$stem.msi"
            $wixArch = @{ amd64 = 'x64'; arm64 = 'arm64'; '386' = 'x86' }[$arch]
            $extensions = @('WixToolset.UI.wixext', 'WixToolset.Util.wixext') | ForEach-Object {
                Join-Path $toolsDir ".wix\extensions\$_\$wixVersion\wixext6\$_.dll"
            }
            Invoke-Checked $wixTool @('build', (Join-Path $repo 'packaging\Package.wxs'),
                '-arch', $wixArch, '-d', "ProductVersion=$ver", '-d', "SourceDir=$archDir", '-d', "RepoDir=$repo",
                '-ext', $extensions[0], '-ext', $extensions[1], '-intermediateFolder', (Join-Path $archDir 'wix'), '-out', $msi)
            foreach ($file in @($zip, $msi)) {
                $checksums.Add("$((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant())  $([IO.Path]::GetFileName($file))")
            }
        }
    }
    if ($Release) {
        $checksums | Set-Content -LiteralPath (Join-Path $releaseDir 'SHA256SUMS.txt') -Encoding ascii
        Write-Host "Release packages: $releaseDir"
    }
} finally {
    foreach ($file in $generatedResources) { Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue }
    foreach ($name in $oldEnvironment.Keys) { [Environment]::SetEnvironmentVariable($name, $oldEnvironment[$name], 'Process') }
    Pop-Location
}
