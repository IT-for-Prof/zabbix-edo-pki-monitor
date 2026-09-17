# itforprof.com by Konstantin Tyutyunnik
# Test fixtures for agent/edo-pki.ps1: an in-memory CA, CRLs, OCSP and TSP answers, a loopback HTTP server.
# Nothing is written to certificate stores; no real certificate or personal data is involved.
# DER is built with the collector's own writers, so the module dot-sources the collector.

Set-StrictMode -Version 2.0
Add-Type -AssemblyName System.Security
. (Join-Path $PSScriptRoot '..\..\agent\edo-pki.ps1')

$script:X509 = 'System.Security.Cryptography.X509Certificates'
$script:FakeCsptestBuild = $null

function New-TestAiaExtension {
    param([string[]]$Ocsp = @(), [string[]]$CaIssuers = @())
    $items = @()
    foreach ($u in $Ocsp) { $items += , (New-PkiTlv 0x30 ((New-PkiOid '1.3.6.1.5.5.7.48.1') + (New-PkiTlv 0x86 ([Text.Encoding]::ASCII.GetBytes($u))))) }
    foreach ($u in $CaIssuers) { $items += , (New-PkiTlv 0x30 ((New-PkiOid '1.3.6.1.5.5.7.48.2') + (New-PkiTlv 0x86 ([Text.Encoding]::ASCII.GetBytes($u))))) }
    $body = [byte[]]@(); foreach ($i in $items) { $body += $i }
    New-Object "$script:X509.X509Extension" '1.3.6.1.5.5.7.1.1', (New-PkiTlv 0x30 $body), $false
}

function New-TestCdpExtension {
    param([string[]]$Urls)
    $names = [byte[]]@(); foreach ($u in $Urls) { $names += New-PkiTlv 0x86 ([Text.Encoding]::ASCII.GetBytes($u)) }
    $dp = New-PkiTlv 0x30 (New-PkiTlv 0xA0 (New-PkiTlv 0xA0 $names))
    New-Object "$script:X509.X509Extension" '2.5.29.31', (New-PkiTlv 0x30 $dp), $false
}

# Returns a certificate that carries its private key. -Issuer $null makes a self-signed root.
function New-TestCert {
    param(
        [Parameter(Mandatory)] [string] $Subject,
        $Issuer = $null,
        [switch] $Ca,
        [string[]] $Cdp = @(),
        [string[]] $Ocsp = @(),
        [string[]] $CaIssuers = @(),
        [DateTimeOffset] $NotBefore = [DateTimeOffset]::UtcNow.AddDays(-3650),
        [DateTimeOffset] $NotAfter = [DateTimeOffset]::UtcNow.AddDays(365),
        $PkupNotAfter = $null,
        [switch] $NoAki,
        [byte[]] $CdpRaw = $null
    )
    $key = [Security.Cryptography.RSA]::Create(2048)
    $req = New-Object "$script:X509.CertificateRequest" $Subject, $key, ([Security.Cryptography.HashAlgorithmName]::SHA256), ([Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $req.CertificateExtensions.Add((New-Object "$script:X509.X509BasicConstraintsExtension" ([bool]$Ca), $false, 0, $true))
    $req.CertificateExtensions.Add((New-Object "$script:X509.X509SubjectKeyIdentifierExtension" $req.PublicKey, $false))
    if ($null -ne $Issuer -and -not $NoAki) {
        $keyId = ConvertFrom-TestHex (Get-PkiSki $Issuer)
        $req.CertificateExtensions.Add((New-Object "$script:X509.X509Extension" '2.5.29.35', (New-PkiTlv 0x30 (New-PkiTlv 0x80 $keyId)), $false))
    }
    if ($Cdp.Count) { $req.CertificateExtensions.Add((New-TestCdpExtension $Cdp)) }
    if ($null -ne $CdpRaw) { $req.CertificateExtensions.Add((New-Object "$script:X509.X509Extension" '2.5.29.31', $CdpRaw, $false)) }
    if ($Ocsp.Count -or $CaIssuers.Count) { $req.CertificateExtensions.Add((New-TestAiaExtension -Ocsp $Ocsp -CaIssuers $CaIssuers)) }
    if ($null -ne $PkupNotAfter) {
        $t = New-PkiTlv 0x81 ([Text.Encoding]::ASCII.GetBytes(([datetime]$PkupNotAfter).ToUniversalTime().ToString('yyyyMMddHHmmss') + 'Z'))
        $req.CertificateExtensions.Add((New-Object "$script:X509.X509Extension" '2.5.29.16', (New-PkiTlv 0x30 $t), $false))
    }
    if ($null -eq $Issuer) { return $req.CreateSelfSigned($NotBefore, $NotAfter) }
    $serial = [byte[]]::new(8); [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($serial); $serial[0] = $serial[0] -band 0x7F -bor 0x01
    if ($NotAfter -gt [DateTimeOffset]$Issuer.NotAfter) { $NotAfter = [DateTimeOffset]$Issuer.NotAfter }
    if ($NotBefore -lt [DateTimeOffset]$Issuer.NotBefore) { $NotBefore = [DateTimeOffset]$Issuer.NotBefore }
    $cert = $req.Create($Issuer, $NotBefore, $NotAfter, $serial)
    [Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($cert, $key)
}

function ConvertTo-TestDerTime {
    param([datetime]$Time, [switch]$Utc)
    $t = $Time.ToUniversalTime()
    if ($Utc) { return New-PkiTlv 0x17 ([Text.Encoding]::ASCII.GetBytes($t.ToString('yyMMddHHmmss') + 'Z')) }
    New-PkiTlv 0x18 ([Text.Encoding]::ASCII.GetBytes($t.ToString('yyyyMMddHHmmss') + 'Z'))
}

# A CRL with a dummy signature: the collector never checks signatures. -PadEntries grows the revoked list
# so the extensions (AKI) land in the tail, as with real lists.
function New-TestCrl {
    param(
        [Parameter(Mandatory)] $IssuerCert,
        [datetime] $ThisUpdate = [datetime]::UtcNow.AddHours(-1),
        $NextUpdate = [datetime]::UtcNow.AddHours(65),
        [int] $PadEntries = 0,
        [string] $AkiHex = $null,
        [switch] $NoAki,
        [switch] $UtcTime
    )
    $alg = New-PkiTlv 0x30 ((New-PkiOid '1.2.840.113549.1.1.11') + [byte[]](0x05, 0x00))
    $tbs = [byte[]](New-PkiInteger ([byte[]]1)) + $alg + $IssuerCert.SubjectName.RawData + (ConvertTo-TestDerTime $ThisUpdate -Utc:$UtcTime)
    if ($null -ne $NextUpdate) { $tbs += ConvertTo-TestDerTime ([datetime]$NextUpdate) -Utc:$UtcTime }
    if ($PadEntries -gt 0) {
        $entry = New-PkiTlv 0x30 ((New-PkiInteger ([byte[]](0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0x01))) + (ConvertTo-TestDerTime ([datetime]::UtcNow.AddDays(-3)) -Utc))
        $ms = New-Object IO.MemoryStream
        for ($i = 0; $i -lt $PadEntries; $i++) { $ms.Write($entry, 0, $entry.Length) }
        $tbs += New-PkiTlv 0x30 $ms.ToArray()
    }
    if (-not $NoAki) {
        if (-not $AkiHex) { $AkiHex = Get-PkiSki $IssuerCert }
        $keyId = ConvertFrom-TestHex $AkiHex
        $akiExt = New-PkiTlv 0x30 ((New-PkiOid '2.5.29.35') + (New-PkiTlv 0x04 (New-PkiTlv 0x30 (New-PkiTlv 0x80 $keyId))))
        $numExt = New-PkiTlv 0x30 ((New-PkiOid '2.5.29.20') + (New-PkiTlv 0x04 (New-PkiInteger ([byte[]]7))))
        $tbs += New-PkiTlv 0xA0 (New-PkiTlv 0x30 ($akiExt + $numExt))
    }
    New-PkiTlv 0x30 ((New-PkiTlv 0x30 $tbs) + $alg + (New-PkiTlv 0x03 ([byte[]](0, 1, 2, 3))))
}

function ConvertFrom-TestHex {
    param([string]$Hex)
    $b = [byte[]]::new($Hex.Length / 2)
    for ($i = 0; $i -lt $b.Length; $i++) { $b[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16) }
    , $b
}

# OCSP response with a dummy signature. -ResponseStatus other than 0 returns only the status.
function New-TestOcspResponse {
    param([string]$SerialHex, [ValidateSet('good', 'revoked', 'unknown')] [string]$Status = 'good', [int]$ResponseStatus = 0)
    $statusTlv = New-PkiTlv 0x0A ([byte[]]$ResponseStatus)
    if ($ResponseStatus -ne 0) { return New-PkiTlv 0x30 $statusTlv }
    $sha1 = New-PkiTlv 0x30 ((New-PkiOid '1.3.14.3.2.26') + [byte[]](0x05, 0x00))
    $certId = New-PkiTlv 0x30 ($sha1 + (New-PkiTlv 0x04 ([byte[]]::new(20))) + (New-PkiTlv 0x04 ([byte[]]::new(20))) + (New-PkiInteger (ConvertFrom-TestHex $SerialHex)))
    $now = ConvertTo-TestDerTime ([datetime]::UtcNow)
    $cs = switch ($Status) {
        'good' { [byte[]](0x80, 0x00) }
        'revoked' { New-PkiTlv 0xA1 $now }
        'unknown' { [byte[]](0x82, 0x00) }
    }
    $single = New-PkiTlv 0x30 ($certId + $cs + $now)
    $tbs = New-PkiTlv 0x30 ((New-PkiTlv 0xA1 (New-PkiTlv 0x30 ([byte[]]@()))) + $now + (New-PkiTlv 0x30 $single))
    $basic = New-PkiTlv 0x30 ($tbs + (New-PkiTlv 0x30 ((New-PkiOid '1.2.840.113549.1.1.11') + [byte[]](0x05, 0x00))) + (New-PkiTlv 0x03 ([byte[]](0, 1))))
    $rb = New-PkiTlv 0x30 ((New-PkiOid '1.3.6.1.5.5.7.48.1.1') + (New-PkiTlv 0x04 $basic))
    New-PkiTlv 0x30 ($statusTlv + (New-PkiTlv 0xA0 $rb))
}

# TimeStampResp. Status 0 or 1 carries a token for -Signer, built by hand as DER with a dummy signature, the way
# the real services encode it. (SignedCms of .NET Framework wraps non-data content in an extra OCTET STRING, which
# no measured service does.) -GostOids uses GOST R 34.11/34.10-2012 identifiers: without CryptoPro
# SignedCms.Decode refuses such tokens ("Unknown cryptographic algorithm"), as measured with the real services on a host without CryptoPro.
function New-TestTspResponse {
    param([int]$Status = 0, [byte[]]$Imprint, [byte[]]$Nonce, [datetime]$GenTime = [datetime]::UtcNow, $Signer, [switch]$GostOids)
    $statusInfo = New-PkiTlv 0x30 (New-PkiInteger ([byte[]]$Status))
    if ($Status -gt 1) { return New-PkiTlv 0x30 $statusInfo }
    $alg = New-PkiTlv 0x30 (New-PkiOid '1.2.643.7.1.1.2.2')
    $tst = (New-PkiInteger ([byte[]]1)) + (New-PkiOid '1.2.643.3.22.1') + (New-PkiTlv 0x30 ($alg + (New-PkiTlv 0x04 $Imprint))) +
        (New-PkiInteger ([byte[]](0x05, 0x06))) + (ConvertTo-TestDerTime $GenTime)
    if ($Nonce) { $tst += New-PkiInteger $Nonce }
    if ($GostOids) { $digestOid = '1.2.643.7.1.1.2.2'; $signOid = '1.2.643.7.1.1.1.1' } else { $digestOid = '2.16.840.1.101.3.4.2.1'; $signOid = '1.2.840.113549.1.1.1' }
    $digest = New-PkiTlv 0x30 (New-PkiOid $digestOid)
    $serial = $Signer.GetSerialNumber(); [Array]::Reverse($serial)
    $signerInfo = New-PkiTlv 0x30 ((New-PkiInteger ([byte[]]1)) + (New-PkiTlv 0x30 ($Signer.IssuerName.RawData + (New-PkiInteger $serial))) +
        $digest + (New-PkiTlv 0x30 (New-PkiOid $signOid)) + (New-PkiTlv 0x04 ([byte[]]::new(64))))
    $encap = New-PkiTlv 0x30 ((New-PkiOid '1.2.840.113549.1.9.16.1.4') + (New-PkiTlv 0xA0 (New-PkiTlv 0x04 (New-PkiTlv 0x30 $tst))))
    $signedData = New-PkiTlv 0x30 ((New-PkiInteger ([byte[]]3)) + (New-PkiTlv 0x31 $digest) + $encap + (New-PkiTlv 0xA0 $Signer.RawData) + (New-PkiTlv 0x31 $signerInfo))
    $token = New-PkiTlv 0x30 ((New-PkiOid '1.2.840.113549.1.7.2') + (New-PkiTlv 0xA0 $signedData))
    New-PkiTlv 0x30 ($statusInfo + $token)
}

# Answer of a time-stamping service to a real request: echoes its imprint and nonce (or breaks them).
function New-TestTspEcho {
    param([byte[]]$Request, $Signer, [int]$Status = 0, [double]$SkewSeconds = 0, [switch]$BreakNonce)
    $top = Read-PkiTlv $Request 0
    $parts = @(Get-PkiChildren $Request $top)
    $imprint = Get-PkiValue $Request (@(Get-PkiChildren $Request $parts[1])[1])
    $nonce = Get-PkiValue $Request $parts[2]
    if ($BreakNonce) { $nonce = [byte[]](0x01, 0x02, 0x03) }
    New-TestTspResponse -Status $Status -Imprint $imprint -Nonce $nonce -GenTime ([datetime]::UtcNow.AddSeconds(-$SkewSeconds)) -Signer $Signer
}

$script:MemoryStoreType = @'
using System; using System.Runtime.InteropServices;
namespace EdoPkiTests {
    public static class MemoryCrlStore {
        [DllImport("crypt32.dll", SetLastError = true)] static extern IntPtr CertOpenStore(IntPtr prov, uint enc, IntPtr hp, uint flags, IntPtr para);
        [DllImport("crypt32.dll", SetLastError = true)] static extern bool CertAddEncodedCRLToStore(IntPtr store, uint enc, byte[] data, uint len, uint disposition, IntPtr ctx);
        [DllImport("crypt32.dll")] public static extern bool CertCloseStore(IntPtr store, uint flags);
        public static IntPtr Open() {
            IntPtr s = CertOpenStore((IntPtr)2, 0, IntPtr.Zero, 0, IntPtr.Zero);
            if (s == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            return s;
        }
        public static void Add(IntPtr store, byte[] crl) {
            if (!CertAddEncodedCRLToStore(store, 0x10001, crl, (uint)crl.Length, 4, IntPtr.Zero)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }
    }
}
'@

# An in-memory CryptoAPI store holding the given CRLs; the collector reads it through the same crypt32 calls
# it uses for the machine CA store. Close with [EdoPkiTests.MemoryCrlStore]::CertCloseStore($h, 0).
function New-TestCrlStore {
    param([object[]]$Crls)
    if (-not ('EdoPkiTests.MemoryCrlStore' -as [type])) { Add-Type -TypeDefinition $script:MemoryStoreType }
    $h = [EdoPkiTests.MemoryCrlStore]::Open()
    # @($oneCrl) unrolls a single byte[] into bytes: treat that shape as one list.
    if ($Crls.Count -gt 0 -and $Crls[0] -is [byte]) { $Crls = @(, [byte[]]$Crls) }
    foreach ($c in $Crls) { [EdoPkiTests.MemoryCrlStore]::Add($h, [byte[]]$c) }
    $h
}

function Close-TestCrlStore {
    param([IntPtr]$Handle)
    [void][EdoPkiTests.MemoryCrlStore]::CertCloseStore($Handle, 0)
}

# ---------------- loopback HTTP server ----------------
# $Handler runs in a separate runspace for every request: param($req, $data) and returns a hashtable
# @{ Status; Headers (hashtable); Body (byte[]); DelayMs; DripMs; Silent }. $req has Method, Path, Headers, Body.
# $Data is shared with the test (a synchronized hashtable); $Data.Requests counts requests.
function Start-FakeHttp {
    param([Parameter(Mandatory)] [scriptblock] $Handler, [hashtable] $Data = @{}, [switch] $ImportFixtures)
    $shared = [hashtable]::Synchronized(@{ Requests = 0 })
    foreach ($k in $Data.Keys) { $shared[$k] = $Data[$k] }
    $listener = New-Object System.Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $ps = [powershell]::Create()
    [void]$ps.AddScript({
        param($listener, $handlerText, $shared, $rangeText, $fixturesPath)
        # With -ImportFixtures the server runspace loads its own copy of this module: calling back into the
        # test runspace would deadlock while the test thread waits for the HTTP answer.
        if ($fixturesPath) { Import-Module $fixturesPath } else { ${function:New-TestRangeResponse} = [scriptblock]::Create($rangeText) }
        $handler = [scriptblock]::Create($handlerText)
        while ($true) {
            try { $client = $listener.AcceptTcpClient() } catch { break }
            try {
                $ns = $client.GetStream(); $ns.ReadTimeout = 5000
                $buf = New-Object byte[] 65536; $ms = New-Object IO.MemoryStream; $headEnd = -1
                while ($headEnd -lt 0) {
                    $n = $ns.Read($buf, 0, $buf.Length); if ($n -le 0) { break }
                    $ms.Write($buf, 0, $n)
                    $headEnd = [Text.Encoding]::ASCII.GetString($ms.ToArray()).IndexOf("`r`n`r`n")
                }
                if ($headEnd -lt 0) { continue }
                $all = $ms.ToArray(); $lines = [Text.Encoding]::ASCII.GetString($all, 0, $headEnd) -split "`r`n"
                $first = $lines[0] -split ' '
                $headers = @{}; foreach ($l in $lines[1..($lines.Count - 1)]) { $i = $l.IndexOf(':'); if ($i -gt 0) { $headers[$l.Substring(0, $i).Trim().ToLowerInvariant()] = $l.Substring($i + 1).Trim() } }
                $len = 0; if ($headers.ContainsKey('content-length')) { $len = [int]$headers['content-length'] }
                $body = New-Object IO.MemoryStream; $body.Write($all, $headEnd + 4, $all.Length - $headEnd - 4)
                while ($body.Length -lt $len) { $n = $ns.Read($buf, 0, $buf.Length); if ($n -le 0) { break }; $body.Write($buf, 0, $n) }
                $shared.Requests++
                $req = @{ Method = $first[0]; Path = $first[1]; Headers = $headers; Body = $body.ToArray() }
                $resp = & $handler $req $shared
                if ($resp.ContainsKey('DelayMs')) { Start-Sleep -Milliseconds $resp.DelayMs }
                if ($resp.ContainsKey('Silent') -and $resp.Silent) { Start-Sleep -Seconds 30; continue }
                $b = [byte[]]@(); if ($resp.ContainsKey('Body') -and $null -ne $resp.Body) { $b = [byte[]]$resp.Body }
                $status = 200; if ($resp.ContainsKey('Status')) { $status = $resp.Status }
                $head = "HTTP/1.1 $status X`r`nContent-Length: $($b.Length)`r`nConnection: close`r`n"
                if ($resp.ContainsKey('Headers')) { foreach ($k in $resp.Headers.Keys) { $head += "${k}: $($resp.Headers[$k])`r`n" } }
                $hb = [Text.Encoding]::ASCII.GetBytes($head + "`r`n")
                $ns.Write($hb, 0, $hb.Length)
                if ($resp.ContainsKey('DripMs')) { foreach ($x in $b) { $ns.WriteByte($x); $ns.Flush(); Start-Sleep -Milliseconds $resp.DripMs } }
                elseif ($b.Length) { $ns.Write($b, 0, $b.Length) }
                $ns.Flush()
            } catch { } finally { $client.Close() }
        }
    }).AddArgument($listener).AddArgument($Handler.ToString()).AddArgument($shared).AddArgument(${function:New-TestRangeResponse}.ToString()).AddArgument($(if ($ImportFixtures) { $PSCommandPath } else { $null }))
    $handle = $ps.BeginInvoke()
    [pscustomobject]@{ Port = $listener.LocalEndpoint.Port; Url = "http://127.0.0.1:$($listener.LocalEndpoint.Port)"; Data = $shared; PowerShell = $ps; Listener = $listener; Handle = $handle }
}

function Stop-FakeHttp {
    param([Parameter(Mandatory)] $Server)
    try { $Server.Listener.Stop() } catch { }
    try { $Server.PowerShell.Stop() } catch { }
    $Server.PowerShell.Dispose()
}

# Serves $Bytes honoring (or ignoring) a Range header the way the CRL servers measured on 16.09.2026 do.
function New-TestRangeResponse {
    param([byte[]]$Bytes, [hashtable]$Req, [switch]$IgnoreRange)
    $range = $null; if ($Req.Headers.ContainsKey('range')) { $range = $Req.Headers['range'] }
    if ($IgnoreRange -or -not $range) { return @{ Status = 200; Body = $Bytes } }
    $total = $Bytes.Length
    if ($range -match '^bytes=(\d+)-(\d*)$') { $from = [int]$Matches[1]; $to = $total - 1; if ($Matches[2]) { $to = [Math]::Min([int]$Matches[2], $total - 1) } }
    elseif ($range -match '^bytes=-(\d+)$') { $from = [Math]::Max(0, $total - [int]$Matches[1]); $to = $total - 1 }
    else { return @{ Status = 416 } }
    $part = [byte[]]::new($to - $from + 1); [Array]::Copy($Bytes, $from, $part, 0, $part.Length)
    @{ Status = 206; Body = $part; Headers = @{ 'Content-Range' = "bytes $from-$to/$total" } }
}

# ---------------- fake csptest ----------------
# A console exe (argv is parsed by the process runtime, as for the real csptest). In its directory:
# names.txt (UTF-8, printed by -enum_cont in cp866), enum-exit.txt (exit code of -enum_cont, 0 without it), behaviors.txt (UTF-8 lines "name|ok|fail|hang"),
# certs\<sha256 of name>.cer or certs\default.cer (copied to -expcert), argv.log (one line per launch,
# arguments joined by the character with code 1).
function New-FakeCsptest {
    param([Parameter(Mandatory)] [string] $Dir)
    [void](New-Item -ItemType Directory -Force -Path (Join-Path $Dir 'certs'))
    $exe = Join-Path $Dir 'csptest.exe'
    if ($script:FakeCsptestBuild -and [IO.File]::Exists($script:FakeCsptestBuild)) { [IO.File]::Copy($script:FakeCsptestBuild, $exe); return $exe }
    $src = @"
using System; using System.IO; using System.Text; using System.Threading; using System.Security.Cryptography;
public static class FakeCsptest {
    static string Hex(byte[] b) { return BitConverter.ToString(b).Replace("-", ""); }
    public static int Main(string[] a) {
        string dir = AppDomain.CurrentDomain.BaseDirectory;
        File.AppendAllText(Path.Combine(dir, "argv.log"), string.Join(((char)1).ToString(), a) + "\n", new UTF8Encoding(false));
        if (Array.IndexOf(a, "-enum_cont") >= 0) {
            Stream o = Console.OpenStandardOutput(); Encoding enc = Encoding.GetEncoding(866);
            string names = Path.Combine(dir, "names.txt");
            if (File.Exists(names)) foreach (string n in File.ReadAllLines(names, Encoding.UTF8)) { byte[] b = enc.GetBytes(n + "\r\n"); o.Write(b, 0, b.Length); }
            byte[] t = enc.GetBytes("OK.\r\n[ErrorCode: 0x00000000]\r\n"); o.Write(t, 0, t.Length); o.Flush();
            string exit = Path.Combine(dir, "enum-exit.txt");
            return File.Exists(exit) ? int.Parse(File.ReadAllText(exit).Trim()) : 0;
        }
        int ci = Array.IndexOf(a, "-container"), ei = Array.IndexOf(a, "-expcert");
        if (ci < 0 || ei < 0 || ci + 1 >= a.Length || ei + 1 >= a.Length) return 2;
        string name = a[ci + 1], behavior = "ok";
        string bf = Path.Combine(dir, "behaviors.txt");
        if (File.Exists(bf)) foreach (string l in File.ReadAllLines(bf, Encoding.UTF8)) { int i = l.LastIndexOf('|'); if (i > 0 && l.Substring(0, i) == name) behavior = l.Substring(i + 1); }
        if (behavior == "hang") { Thread.Sleep(60000); return 1; }
        if (behavior == "fail") return 1;
        string key = Hex(SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(name)));
        string cer = Path.Combine(dir, "certs", key + ".cer");
        if (!File.Exists(cer)) cer = Path.Combine(dir, "certs", "default.cer");
        if (!File.Exists(cer)) return 3;
        File.Copy(cer, a[ei + 1], true);
        return 0;
    }
}
"@
    # Built once into Pester's TestDrive (removed with the test container), copied into every test directory.
    $script:FakeCsptestBuild = Join-Path (Get-Variable TestDrive -ValueOnly) ('fake-csptest-build-' + [guid]::NewGuid().ToString('N') + '.exe')
    Add-Type -TypeDefinition $src -OutputAssembly $script:FakeCsptestBuild -OutputType ConsoleApplication
    [IO.File]::Copy($script:FakeCsptestBuild, $exe)
    $exe
}

function Set-FakeContainer {
    param([Parameter(Mandatory)] [string] $Dir, [Parameter(Mandatory)] [string] $Name, $Cert = $null, [string] $Behavior = 'ok')
    if ($null -ne $Cert) {
        [IO.File]::WriteAllBytes((Join-Path $Dir "certs\$(Get-PkiNameKey $Name).cer"), $Cert.RawData)
    }
    $names = Join-Path $Dir 'names.txt'
    $existing = @(); if (Test-Path -LiteralPath $names) { $existing = @([IO.File]::ReadAllLines($names, [Text.Encoding]::UTF8)) }
    if ($existing -notcontains $Name) { [IO.File]::WriteAllLines($names, [string[]]($existing + $Name), (New-Object Text.UTF8Encoding $false)) }
    [IO.File]::AppendAllText((Join-Path $Dir 'behaviors.txt'), "$Name|$Behavior`r`n", (New-Object Text.UTF8Encoding $false))
}

function Remove-FakeContainer {
    param([Parameter(Mandatory)] [string] $Dir, [Parameter(Mandatory)] [string] $Name)
    $names = Join-Path $Dir 'names.txt'
    [IO.File]::WriteAllLines($names, [string[]]@([IO.File]::ReadAllLines($names, [Text.Encoding]::UTF8) | Where-Object { $_ -ne $Name }), (New-Object Text.UTF8Encoding $false))
}

function Get-FakeCsptestLaunches {
    param([Parameter(Mandatory)] [string] $Dir)
    $log = Join-Path $Dir 'argv.log'
    if (-not (Test-Path -LiteralPath $log)) { return @() }
    foreach ($line in [IO.File]::ReadAllLines($log, [Text.Encoding]::UTF8)) { if ($line) { , ($line -split [char]1) } }
}

function Get-ClosedPort {
    $l = New-Object System.Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
    $l.Start(); $port = $l.LocalEndpoint.Port; $l.Stop()
    $port
}

# Runs the collector the way agent2 does and returns exit code, stdout, stderr, duration.
function Invoke-CollectorProcess {
    param([Parameter(Mandatory)] [string] $ScriptPath, [string[]] $ArgumentList = @())
    $quoted = @($ArgumentList | ForEach-Object { '"' + $_ + '"' }) -join ' '
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'powershell.exe'
    $psi.Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$ScriptPath`" $quoted"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [Text.Encoding]::UTF8
    $psi.CreateNoWindow = $true
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $p = [Diagnostics.Process]::Start($psi)
    $errTask = $p.StandardError.ReadToEndAsync()
    $out = $p.StandardOutput.ReadToEnd()
    $p.WaitForExit()
    [pscustomobject]@{ ExitCode = $p.ExitCode; StdOut = $out.Trim(); StdErr = $errTask.Result.Trim(); Ms = $sw.ElapsedMilliseconds }
}

Export-ModuleMember -Function New-TestCert, New-TestCrl, New-TestOcspResponse, New-TestTspResponse,
    Start-FakeHttp, Stop-FakeHttp, New-TestRangeResponse, Get-ClosedPort, Invoke-CollectorProcess,
    New-FakeCsptest, Set-FakeContainer, Remove-FakeContainer, Get-FakeCsptestLaunches, New-TestTspEcho, New-TestCrlStore, Close-TestCrlStore
