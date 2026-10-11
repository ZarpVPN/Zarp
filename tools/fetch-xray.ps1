# Downloads the pinned Xray-core release (the engine for VLESS over XHTTP, which sing-box cannot speak), checks its SHA-256
# and packs xray.exe into vendor\xray.zip, which is embedded into Zarp.exe.
# The version is pinned on purpose: Zarp generates Xray configuration for exactly this release, and the settings
# names change between releases (v26.3.27 dropped allowInsecure, v26.5 renamed clients and accounts to users, later
# releases block private addresses in the freedom outbound by default). To update, change $Version and $Sha256 together
# (the digest is shown on the release page: https://github.com/XTLS/Xray-core/releases).
# 26.7.28 is flagged as a pre-release on GitHub, like every Xray release since April 2026 (v26.3.27 is the last one that
# GitHub calls "latest"). Happ ships the byte-identical xray.exe, so servers that work with Happ work with this one.
# Only xray.exe is kept: geoip.dat, geosite.dat and wintun.dll from the same archive are not needed (Zarp uses Xray as a
# local SOCKS5 bridge and sing-box does the routing and the TUN adapter).
param(
    [string]$Out = (Join-Path $PSScriptRoot '..\vendor\xray.zip'),
    [string]$Version = '26.7.28',
    [string]$Sha256 = 'c7172078fca4711bcd92a4774dcd1822544579c58816197575c47533317fd8d1'
)
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem

$tag = "v$Version"
$name = 'Xray-windows-64'
$assetUrl = "https://github.com/XTLS/Xray-core/releases/download/$tag/$name.zip"

if (Test-Path $Out) {
    $z = [IO.Compression.ZipFile]::OpenRead((Resolve-Path $Out))
    $v = $z.GetEntry('version.txt')
    $have = if ($v) { (New-Object IO.StreamReader($v.Open())).ReadToEnd().Trim() } else { '' }
    $hasExe = $null -ne $z.GetEntry('xray.exe')
    $z.Dispose()
    if ($have -eq $tag -and $hasExe) { Write-Output "Xray $tag already in $Out"; return }
}

Write-Output "Downloading Xray $tag ..."
$wc = New-Object Net.WebClient
$wc.Headers['User-Agent'] = 'Zarp-build'
$bytes = $wc.DownloadData($assetUrl)
$sha = [Security.Cryptography.SHA256]::Create()
$actual = ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
if ($actual -ne $Sha256.ToLowerInvariant()) { throw "SHA-256 of $name.zip is $actual, expected $Sha256" }

$src = New-Object IO.Compression.ZipArchive((New-Object IO.MemoryStream(, $bytes)), [IO.Compression.ZipArchiveMode]::Read)
$ms = New-Object IO.MemoryStream
$dst = New-Object IO.Compression.ZipArchive($ms, [IO.Compression.ZipArchiveMode]::Create, $true)
$entry = $src.Entries | Where-Object { $_.Name -eq 'xray.exe' } | Select-Object -First 1
if (-not $entry) { throw "xray.exe not found in $name.zip" }
$e = $dst.CreateEntry('xray.exe', [IO.Compression.CompressionLevel]::Optimal)
$w = $e.Open(); $r = $entry.Open(); $r.CopyTo($w); $r.Close(); $w.Close()
$ve = $dst.CreateEntry('version.txt')
$w = New-Object IO.StreamWriter($ve.Open()); $w.Write($tag); $w.Close()
$dst.Dispose(); $src.Dispose()

New-Item -ItemType Directory -Force (Split-Path $Out) | Out-Null
[IO.File]::WriteAllBytes([IO.Path]::GetFullPath($Out), $ms.ToArray())
Write-Output ("Xray {0} -> {1} ({2:N0} KB)" -f $tag, $Out, ($ms.Length / 1KB))
