[CmdletBinding()]
param(
    [string] $Version = '',
    [string] $Tag = '',
    [string] $ExpectedCommit = '',
    [string] $OutputFile = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$recordedVersion = (Get-Content -LiteralPath (Join-Path $repo 'VERSION') -Raw).Trim()
if ($Tag) {
    if ($Tag -notmatch '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') {
        throw 'Release tags must use vMAJOR.MINOR.PATCH without prerelease suffixes.'
    }
    $tagVersion = $Tag.Substring(1)
    if ($Version -and $Version -ne $tagVersion) { throw 'Dispatch version and tag disagree.' }
    $Version = $tagVersion
}
if (!$Version) { $Version = $recordedVersion }
if ($Version -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') {
    throw 'Release version must use MAJOR.MINOR.PATCH.'
}
$parts = $Version.Split('.')
if ([decimal]$parts[0] -gt 255 -or [decimal]$parts[1] -gt 255 -or [decimal]$parts[2] -gt 65535) {
    throw 'Release version exceeds MSI limits (255.255.65535).'
}
if ($Version -ne $recordedVersion) { throw "Release version must match VERSION ($recordedVersion)." }
$Tag = "v$Version"
$commit = git -C $repo rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve the checked-out commit.' }
if ($ExpectedCommit -and $commit -ne $ExpectedCommit) { throw 'Checkout does not match the requested release commit.' }
$existing = git -C $repo for-each-ref '--format=%(objectname)' "refs/tags/$Tag"
if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect release tags.' }
if ($existing) {
    $tagCommit = git -C $repo rev-parse "refs/tags/$Tag^{}"
    if ($LASTEXITCODE -ne 0 -or $tagCommit -ne $commit) { throw "Tag $Tag already points at another commit." }
}
if (!(Test-Path -LiteralPath (Join-Path $repo "packaging\release-notes\$Version.md"))) {
    throw "Missing reviewed release notes for $Version."
}
if ($OutputFile) {
    @("version=$Version", "tag=$Tag", "commit=$commit") | Add-Content -LiteralPath $OutputFile -Encoding utf8
}
[pscustomobject]@{ Version = $Version; Tag = $Tag; Commit = $commit }
