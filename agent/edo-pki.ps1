<#
.SYNOPSIS
    EDO PKI Monitor collector: CRL, OCSP, CA certificates by AIA, time-stamping services and local CRLs
    for the certificates of this host, one ASCII JSON object on stdout.

.DESCRIPTION
    Run by Zabbix agent2 through UserParameter edo.pki[network,local,stores,containers,crl_urls,tsp_urls].
    Always prints exactly one JSON object and exits with code 0; nothing is ever written to stderr:
    agent2 glues stderr into the item value.

.NOTES
    itforprof.com by Konstantin Tyutyunnik — https://github.com/IT-for-Prof/zabbix-edo-pki-monitor

    Arguments are positional ($args, not a param block): an argument starting with "-" must not turn into
    a parameter binding error on stderr.
#>

Set-StrictMode -Version 2.0

# ---------------------------------------------------------------- DER

function ConvertTo-PkiHex {
    param([byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return '' }
    [BitConverter]::ToString($Bytes).Replace('-', '')
}


function New-PkiTlv {
    param([int]$Tag, [byte[]]$Value)
    if ($null -eq $Value) { $Value = [byte[]]@() }
    $n = $Value.Length
    if ($n -lt 0x80) { $len = [byte[]]@($n) }
    elseif ($n -lt 0x100) { $len = [byte[]](0x81, $n) }
    elseif ($n -lt 0x10000) { $len = [byte[]](0x82, ($n -shr 8), ($n -band 0xFF)) }
    else { $len = [byte[]](0x83, ($n -shr 16), (($n -shr 8) -band 0xFF), ($n -band 0xFF)) }
    $out = [byte[]]::new(1 + $len.Length + $n)
    $out[0] = [byte]$Tag
    [Array]::Copy($len, 0, $out, 1, $len.Length)
    [Array]::Copy($Value, 0, $out, 1 + $len.Length, $n)
    , $out
}

function New-PkiOid {
    param([string]$Oid)
    $p = @($Oid.Split('.') | ForEach-Object { [long]$_ })
    $b = New-Object Collections.Generic.List[byte]
    $b.Add([byte](40 * $p[0] + $p[1]))
    foreach ($x in $p[2..($p.Count - 1)]) {
        $t = New-Object Collections.Generic.List[byte]
        $t.Insert(0, [byte]($x -band 0x7F)); $x = $x -shr 7
        while ($x -gt 0) { $t.Insert(0, [byte](($x -band 0x7F) -bor 0x80)); $x = $x -shr 7 }
        $b.AddRange($t)
    }
    New-PkiTlv 0x06 $b.ToArray()
}

# Unsigned big-endian bytes to a DER INTEGER (a leading zero keeps it positive).
function New-PkiInteger {
    param([byte[]]$Value)
    if ($Value[0] -ge 0x80) { $Value = [byte[]](@([byte]0) + $Value) }
    New-PkiTlv 0x02 $Value
}

# Header of one TLV at $Offset: @{ Tag; Off; Val; Len; End }. $null when the header itself is unreadable:
# past the buffer, indefinite length (not DER) or a length of more than 4 bytes. The value may extend past
# the buffer (the head of a 52 MB CRL); Get-PkiValue checks that before reading it.
function Read-PkiTlv {
    param([byte[]]$Bytes, [int]$Offset)
    if ($null -eq $Bytes -or $Offset -lt 0 -or $Offset + 2 -gt $Bytes.Length) { return $null }
    $first = [int]$Bytes[$Offset + 1]
    if ($first -lt 0x80) { return @{ Tag = [int]$Bytes[$Offset]; Off = $Offset; Val = $Offset + 2; Len = [long]$first; End = $Offset + 2 + [long]$first } }
    $n = $first -band 0x7F
    if ($n -eq 0 -or $n -gt 4 -or $Offset + 2 + $n -gt $Bytes.Length) { return $null }
    [long]$len = 0
    for ($i = 0; $i -lt $n; $i++) { $len = $len * 256 + $Bytes[$Offset + 2 + $i] }
    @{ Tag = [int]$Bytes[$Offset]; Off = $Offset; Val = $Offset + 2 + $n; Len = $len; End = $Offset + 2 + $n + $len }
}

# Children of a constructed TLV that lie inside both the parent and the buffer.
function Get-PkiChildren {
    param([byte[]]$Bytes, $Tlv)
    $list = New-Object Collections.ArrayList
    $o = $Tlv.Val
    $limit = [Math]::Min([long]$Tlv.End, [long]$Bytes.Length)
    while ($o -lt $limit) {
        $c = Read-PkiTlv $Bytes ([int]$o)
        if ($null -eq $c -or $c.End -gt $Tlv.End) { break }
        [void]$list.Add($c)
        $o = $c.End
    }
    $list.ToArray()
}

function Get-PkiValue {
    param([byte[]]$Bytes, $Tlv)
    if ($Tlv.End -gt $Bytes.Length) { throw 'DER value extends past the buffer' }
    $v = [byte[]]::new([int]$Tlv.Len)
    [Array]::Copy($Bytes, [int]$Tlv.Val, $v, 0, $v.Length)
    , $v
}

function Get-PkiTlvBytes {
    param([byte[]]$Bytes, $Tlv)
    if ($Tlv.End -gt $Bytes.Length) { throw 'DER element extends past the buffer' }
    $v = [byte[]]::new([int]($Tlv.End - $Tlv.Off))
    [Array]::Copy($Bytes, [int]$Tlv.Off, $v, 0, $v.Length)
    , $v
}

function ConvertFrom-PkiOid {
    param([byte[]]$Bytes, $Tlv)
    $v = Get-PkiValue $Bytes $Tlv
    if ($v.Length -eq 0) { throw 'empty OID' }
    $parts = New-Object Collections.Generic.List[string]
    $parts.Add([string][Math]::Min(2, [Math]::Floor($v[0] / 40))); $parts.Add([string]($v[0] - 40 * [Math]::Min(2, [Math]::Floor($v[0] / 40))))
    [long]$acc = 0
    for ($i = 1; $i -lt $v.Length; $i++) { $acc = $acc * 128 + ($v[$i] -band 0x7F); if ($v[$i] -lt 0x80) { $parts.Add([string]$acc); $acc = 0 } }
    $parts -join '.'
}

# UTCTime (0x17) or GeneralizedTime (0x18, fraction dropped) to a UTC DateTime.
function ConvertFrom-PkiTime {
    param([byte[]]$Bytes, $Tlv)
    $s = [Text.Encoding]::ASCII.GetString((Get-PkiValue $Bytes $Tlv))
    if ($Tlv.Tag -eq 0x17) { $f = 'yyMMddHHmmss' } elseif ($Tlv.Tag -eq 0x18) { $f = 'yyyyMMddHHmmss'; $s = $s -replace '\.\d+Z$', 'Z' } else { throw 'not a DER time' }
    if (-not $s.EndsWith('Z')) { throw 'DER time is not UTC' }
    [datetime]::ParseExact($s.TrimEnd('Z'), $f, [Globalization.CultureInfo]::InvariantCulture, ([Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal))
}

# ---------------------------------------------------------------- CRL

# First bytes of a CRL (or the whole list): @{ Total; Issuer; ThisUpdate; NextUpdate }, or $null when the bytes
# are not a CRL. Never throws. Total is the size declared by the outer DER header.
function Read-PkiCrlHead {
    param([byte[]]$Bytes)
    try {
        $outer = Read-PkiTlv $Bytes 0
        if ($null -eq $outer -or $outer.Tag -ne 0x30) { return $null }
        $tbs = Read-PkiTlv $Bytes $outer.Val
        if ($null -eq $tbs -or $tbs.Tag -ne 0x30) { return $null }
        $t = Read-PkiTlv $Bytes $tbs.Val
        if ($null -ne $t -and $t.Tag -eq 0x02) { $t = Read-PkiTlv $Bytes ([int]$t.End) }
        if ($null -eq $t -or $t.Tag -ne 0x30) { return $null }                       # signature algorithm
        $name = Read-PkiTlv $Bytes ([int]$t.End)
        if ($null -eq $name -or $name.Tag -ne 0x30) { return $null }                 # issuer
        $thisTlv = Read-PkiTlv $Bytes ([int]$name.End)
        if ($null -eq $thisTlv -or ($thisTlv.Tag -ne 0x17 -and $thisTlv.Tag -ne 0x18)) { return $null }
        $issuer = (New-Object Security.Cryptography.X509Certificates.X500DistinguishedName (, (Get-PkiTlvBytes $Bytes $name))).Name
        $r = @{ Total = [long]$outer.End; Issuer = $issuer; ThisUpdate = ConvertFrom-PkiTime $Bytes $thisTlv; NextUpdate = $null }
        $next = Read-PkiTlv $Bytes ([int]$thisTlv.End)
        if ($null -ne $next -and ($next.Tag -eq 0x17 -or $next.Tag -eq 0x18)) { $r.NextUpdate = ConvertFrom-PkiTime $Bytes $next }
        $r
    } catch { $null }
}

# AKI keyIdentifier of a CRL found by the structure of its extension (2.5.29.35), in the tail or in a whole list.
function Find-PkiCrlAki {
    param([byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return $null }
    $hex = ConvertTo-PkiHex $Bytes
    $m = [regex]::Match($hex, '0603551D23(?:0101FF)?04(?:81..|82....|..)30(?:81..|82....|..)80([0-7][0-9A-F])')
    if (-not $m.Success) { return $null }
    $n = [Convert]::ToInt32($m.Groups[1].Value, 16) * 2
    if ($m.Index + $m.Length + $n -gt $hex.Length) { return $null }
    $hex.Substring($m.Index + $m.Length, $n)
}

# ---------------------------------------------------------------- certificates

function Get-PkiExtensionBytes {
    param($Cert, [string]$Oid)
    $e = $Cert.Extensions[$Oid]
    if ($null -eq $e) { return $null }
    , $e.RawData
}

# http addresses of CDP and AIA (ocsp, caIssuers), in certificate order. DER, not Format(): the text form is
# localized. Other schemes (ldap) are dropped here; character checks are the caller's job.
function Get-PkiCertUrls {
    param($Cert)
    $r = @{ Cdp = @(); Ocsp = @(); CaIssuers = @() }
    $isHttp = { param($u) $u -match '^(?i)http://' }
    $cdp = Get-PkiExtensionBytes $Cert '2.5.29.31'
    if ($null -ne $cdp) {
        $seq = Read-PkiTlv $cdp 0
        foreach ($dp in (Get-PkiChildren $cdp $seq)) {
            foreach ($dpName in (Get-PkiChildren $cdp $dp)) {
                if ($dpName.Tag -ne 0xA0) { continue }
                foreach ($full in (Get-PkiChildren $cdp $dpName)) {
                    if ($full.Tag -ne 0xA0) { continue }
                    foreach ($gn in (Get-PkiChildren $cdp $full)) {
                        if ($gn.Tag -ne 0x86) { continue }
                        $u = [Text.Encoding]::ASCII.GetString((Get-PkiValue $cdp $gn))
                        if (& $isHttp $u) { $r.Cdp += $u }
                    }
                }
            }
        }
    }
    $aia = Get-PkiExtensionBytes $Cert '1.3.6.1.5.5.7.1.1'
    if ($null -ne $aia) {
        $seq = Read-PkiTlv $aia 0
        foreach ($ad in (Get-PkiChildren $aia $seq)) {
            $parts = @(Get-PkiChildren $aia $ad)
            if ($parts.Count -lt 2 -or $parts[0].Tag -ne 0x06 -or $parts[1].Tag -ne 0x86) { continue }
            $u = [Text.Encoding]::ASCII.GetString((Get-PkiValue $aia $parts[1]))
            if (-not (& $isHttp $u)) { continue }
            switch (ConvertFrom-PkiOid $aia $parts[0]) {
                '1.3.6.1.5.5.7.48.1' { $r.Ocsp += $u }
                '1.3.6.1.5.5.7.48.2' { $r.CaIssuers += $u }
            }
        }
    }
    $r
}

function Get-PkiAki {
    param($Cert)
    $b = Get-PkiExtensionBytes $Cert '2.5.29.35'
    if ($null -eq $b) { return $null }
    $seq = Read-PkiTlv $b 0
    foreach ($c in (Get-PkiChildren $b $seq)) { if ($c.Tag -eq 0x80) { return ConvertTo-PkiHex (Get-PkiValue $b $c) } }
    $null
}

function Get-PkiSki {
    param($Cert)
    $e = $Cert.Extensions['2.5.29.14']
    if ($null -eq $e) { return $null }
    $e.SubjectKeyIdentifier.ToUpperInvariant()
}

# End of the private key usage period (2.5.29.16, notAfter [1]) or $null.
function Get-PkiPkupNotAfter {
    param($Cert)
    $b = Get-PkiExtensionBytes $Cert '2.5.29.16'
    if ($null -eq $b) { return $null }
    $seq = Read-PkiTlv $b 0
    foreach ($c in (Get-PkiChildren $b $seq)) {
        if ($c.Tag -eq 0x81) {
            $s = [Text.Encoding]::ASCII.GetString((Get-PkiValue $b $c))
            return [datetime]::ParseExact($s.TrimEnd('Z'), 'yyyyMMddHHmmss', [Globalization.CultureInfo]::InvariantCulture, ([Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal))
        }
    }
    $null
}

# ---------------------------------------------------------------- OCSP

# RFC 6960 request with one SHA-1 CertID; SHA-1 CertID is accepted by every working responder measured.
function New-PkiOcspRequest {
    param($Cert, $Issuer)
    $sha1 = [Security.Cryptography.SHA1]::Create()
    $alg = New-PkiTlv 0x30 ((New-PkiOid '1.3.14.3.2.26') + [byte[]](0x05, 0x00))
    $serial = $Cert.GetSerialNumber(); [Array]::Reverse($serial)
    $certId = New-PkiTlv 0x30 ($alg + (New-PkiTlv 0x04 $sha1.ComputeHash($Cert.IssuerName.RawData)) + (New-PkiTlv 0x04 $sha1.ComputeHash($Issuer.PublicKey.EncodedKeyValue.RawData)) + (New-PkiInteger $serial))
    New-PkiTlv 0x30 (New-PkiTlv 0x30 (New-PkiTlv 0x30 (New-PkiTlv 0x30 $certId)))
}

function ConvertTo-PkiSerialKey {
    param([string]$Hex)
    $h = $Hex.ToUpperInvariant().TrimStart('0')
    if ($h -eq '') { return '0' }
    $h
}

# @{ ResponseStatus; CertStatus } — CertStatus good/revoked/unknown for the requested serial, $null when the
# response is not successful or does not answer about that serial. Throws when the bytes are not OCSP.
function Read-PkiOcspResponse {
    param([byte[]]$Bytes, [string]$SerialHex)
    $top = Read-PkiTlv $Bytes 0
    if ($null -eq $top -or $top.Tag -ne 0x30) { throw 'not an OCSP response' }
    $parts = @(Get-PkiChildren $Bytes $top)
    if ($parts.Count -lt 1 -or $parts[0].Tag -ne 0x0A) { throw 'not an OCSP response' }
    $r = @{ ResponseStatus = [int](Get-PkiValue $Bytes $parts[0])[0]; CertStatus = $null }
    if ($r.ResponseStatus -ne 0 -or $parts.Count -lt 2) { return $r }
    $rb = @(Get-PkiChildren $Bytes (@(Get-PkiChildren $Bytes $parts[1])[0]))
    if ($rb.Count -lt 2 -or $rb[1].Tag -ne 0x04) { throw 'OCSP responseBytes malformed' }
    $basic = Read-PkiTlv $Bytes ([int]$rb[1].Val)
    $tbs = @(Get-PkiChildren $Bytes $basic)[0]
    $want = ConvertTo-PkiSerialKey $SerialHex
    foreach ($field in (Get-PkiChildren $Bytes $tbs)) {
        if ($field.Tag -ne 0x30) { continue }                                         # responses: SEQUENCE OF SingleResponse
        foreach ($single in (Get-PkiChildren $Bytes $field)) {
            $sp = @(Get-PkiChildren $Bytes $single)
            if ($sp.Count -lt 2 -or $sp[0].Tag -ne 0x30) { continue }
            $idParts = @(Get-PkiChildren $Bytes $sp[0])
            if ($idParts.Count -lt 4 -or $idParts[3].Tag -ne 0x02) { continue }
            if ((ConvertTo-PkiSerialKey (ConvertTo-PkiHex (Get-PkiValue $Bytes $idParts[3]))) -ne $want) { continue }
            switch ($sp[1].Tag) { 0x80 { $r.CertStatus = 'good' } 0xA1 { $r.CertStatus = 'revoked' } 0x82 { $r.CertStatus = 'unknown' } }
            return $r
        }
    }
    $r
}

# ---------------------------------------------------------------- TSP

# RFC 3161 request with a GOST R 34.11-2012 256 imprint: working services grant GOST and reject SHA-256 (measured).
# The service signs whatever value it gets, so a random 32-byte imprint needs no hashing.
function New-PkiTspRequest {
    param([byte[]]$Imprint, [byte[]]$Nonce)
    $imprintTlv = New-PkiTlv 0x30 ((New-PkiTlv 0x30 (New-PkiOid '1.2.643.7.1.1.2.2')) + (New-PkiTlv 0x04 $Imprint))
    New-PkiTlv 0x30 ((New-PkiInteger ([byte[]]1)) + $imprintTlv + (New-PkiInteger $Nonce) + [byte[]](0x01, 0x01, 0xFF))
}

# @{ Status (PKIStatus); EchoOk; GenTime; KeyNotAfter } — EchoOk only for granted answers echoing our nonce
# and imprint. Throws when the bytes are not a TimeStampResp.
function Read-PkiTspResponse {
    param([byte[]]$Bytes, [byte[]]$Imprint, [byte[]]$Nonce)
    $top = Read-PkiTlv $Bytes 0
    if ($null -eq $top -or $top.Tag -ne 0x30) { throw 'not a TSP response' }
    $parts = @(Get-PkiChildren $Bytes $top)
    if ($parts.Count -lt 1 -or $parts[0].Tag -ne 0x30) { throw 'not a TSP response' }
    $statusTlv = @(Get-PkiChildren $Bytes $parts[0])[0]
    if ($null -eq $statusTlv -or $statusTlv.Tag -ne 0x02) { throw 'not a TSP response' }
    $r = @{ Status = [int](Get-PkiValue $Bytes $statusTlv)[-1]; EchoOk = $false; GenTime = $null; KeyNotAfter = $null }
    if ($r.Status -gt 1 -or $parts.Count -lt 2) { return $r }
    # The token is read as DER, not with SignedCms: without CryptoPro SignedCms.Decode refuses GOST algorithms
    # ("Unknown cryptographic algorithm", measured on a host without CryptoPro). Signatures are not checked anyway.
    # ContentInfo { OID, [0] SignedData { version, digestAlgorithms, encapContentInfo { OID, [0] OCTET STRING TSTInfo },
    #   [0] certificates, [1] crls, signerInfos } }
    $signedData = @(Get-PkiChildren $Bytes (@(Get-PkiChildren $Bytes $parts[1])[1]))[0]
    $sd = @(Get-PkiChildren $Bytes $signedData)
    $encap = @(Get-PkiChildren $Bytes $sd[2])
    $tst = Get-PkiValue $Bytes (@(Get-PkiChildren $Bytes $encap[1])[0])
    $certs = @(); $signerInfos = $null
    for ($i = 3; $i -lt $sd.Count; $i++) {
        if ($sd[$i].Tag -eq 0xA0) { $certs = @(Get-PkiChildren $Bytes $sd[$i]) }
        elseif ($sd[$i].Tag -eq 0x31) { $signerInfos = $sd[$i] }
    }
    $f = @(Get-PkiChildren $tst (Read-PkiTlv $tst 0))
    $mi = @(Get-PkiChildren $tst $f[2])
    $echoImprint = ConvertTo-PkiHex (Get-PkiValue $tst $mi[1])
    $r.GenTime = ConvertFrom-PkiTime $tst $f[4]
    $echoNonce = $null
    foreach ($x in $f[5..($f.Count - 1)]) { if ($null -ne $x -and $x.Tag -eq 0x02) { $echoNonce = ConvertTo-PkiHex (Get-PkiValue $tst $x); break } }
    $r.EchoOk = ($echoImprint -eq (ConvertTo-PkiHex $Imprint)) -and ($null -ne $echoNonce) -and ((ConvertTo-PkiSerialKey $echoNonce) -eq (ConvertTo-PkiSerialKey (ConvertTo-PkiHex $Nonce)))
    # Signer: the certificate named by the first SignerInfo (issuer and serial, or subject key identifier).
    if ($null -ne $signerInfos -and $certs.Count -gt 0) {
        $si = @(Get-PkiChildren $Bytes (@(Get-PkiChildren $Bytes $signerInfos)[0]))
        $sid = $si[1]
        foreach ($c in $certs) {
            try { $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 (, (Get-PkiTlvBytes $Bytes $c)) } catch { continue }
            $match = $false
            if ($sid.Tag -eq 0x30) {
                $ias = @(Get-PkiChildren $Bytes $sid)
                $match = ((ConvertTo-PkiHex (Get-PkiTlvBytes $Bytes $ias[0])) -eq (ConvertTo-PkiHex $cert.IssuerName.RawData)) -and
                    ((ConvertTo-PkiSerialKey (ConvertTo-PkiHex (Get-PkiValue $Bytes $ias[1]))) -eq (ConvertTo-PkiSerialKey $cert.SerialNumber))
            } elseif ($sid.Tag -eq 0x80) {
                $match = (ConvertTo-PkiHex (Get-PkiValue $Bytes $sid)) -eq (Get-PkiSki $cert)
            }
            if ($match) { $r.KeyNotAfter = Get-PkiPkupNotAfter $cert; break }
        }
    }
    $r
}

# ---------------------------------------------------------------- pass budget and HTTP

# Budgets, ms. The pass deadline stays under the item timeout {$PKI.TIMEOUT} = 120 s with room for the
# powershell.exe start (3.8-4.3 s measured through agent2) and for the agent killing the script.
$script:PkiBudget = @{ PassMs = 90000; DiscoveryMs = 30000; HttpMs = 5000; CsptestMs = 10000; MaxRedirects = 5 }
$script:PkiPass = [Diagnostics.Stopwatch]::StartNew()
$script:PkiPassBudgetMs = $script:PkiBudget.PassMs

function Start-PkiPass {
    param([int]$BudgetMs = $script:PkiBudget.PassMs)
    $script:PkiPass = [Diagnostics.Stopwatch]::StartNew()
    $script:PkiPassBudgetMs = $BudgetMs
}

function Get-PkiPassRemainingMs { [Math]::Max(0, $script:PkiPassBudgetMs - [int]$script:PkiPass.ElapsedMilliseconds) }

function Test-PkiPassExpired { (Get-PkiPassRemainingMs) -le 0 }

# State of a network failure by socket error: 10 DNS, 20 timeout, 22 refused, 23 denied (firewall), 24 other.
function Get-PkiSocketState {
    param([Net.Sockets.SocketError]$SocketError)
    switch ($SocketError) {
        'HostNotFound' { return 10 }
        'NoData' { return 10 }
        'TryAgain' { return 10 }
        'TimedOut' { return 20 }
        'ConnectionRefused' { return 22 }
        'AccessDenied' { return 23 }
        default { return 24 }
    }
}


function Get-PkiErrorText {
    param($Exception)
    $x = $Exception.GetBaseException()
    $t = "$($x.GetType().Name): $($x.Message)"
    if ($x -is [Net.Sockets.SocketException]) { $t = "SocketException $($x.SocketErrorCode): $($x.Message)" }
    $t = ($t -replace '\s+', ' ').Trim()
    if ($t.Length -gt 200) { $t = $t.Substring(0, 200) }
    $t
}

# One HTTP exchange through the agent's own network path (no proxy, no credentials), redirects followed by hand.
# Returns @{ State; Http; Ms; Bytes; More; Total; Error; FinalUrl }: State 0 for a final 200/206, 30 for other
# codes, too many redirects or a redirect off http://, 10-24 for network failures. The budget covers the whole
# exchange including the body, and never exceeds what is left of the pass.
function Invoke-PkiHttp {
    param(
        [Parameter(Mandatory)] [string] $Url,
        [string] $Method = 'GET',
        [byte[]] $Body = $null,
        [string] $ContentType = $null,
        $RangeFrom = $null,
        $RangeTo = $null,
        [int] $Tail = 0,
        [int] $MaxBytes = 16384,
        [int] $TimeoutMs = $script:PkiBudget.HttpMs
    )
    $budget = [Math]::Min($TimeoutMs, (Get-PkiPassRemainingMs))
    $r = @{ State = 0; Http = -1; Ms = -1; Bytes = [byte[]]@(); More = $false; Total = $null; Error = ''; FinalUrl = $Url }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $current = [Uri]$Url
    try {
        for ($hop = 0; ; $hop++) {
            $left = $budget - [int]$sw.ElapsedMilliseconds
            if ($left -gt 0 -and $current.HostNameType -eq [UriHostNameType]::Dns) {
                # HttpWebRequest.Timeout does not cover name resolution (up to 15 s by its documentation): the name
                # is resolved first within the budget, the request then gets the answer from the resolver cache.
                if (-not [Net.Dns]::GetHostAddressesAsync($current.DnsSafeHost).Wait($left)) { $r.State = 20; $r.Error = "name resolution took over $left ms"; return $r }
                $left = $budget - [int]$sw.ElapsedMilliseconds
            }
            if ($left -le 0) { $r.State = 20; $r.Error = "budget of $budget ms spent"; return $r }
            $q = [Net.HttpWebRequest]::Create($current)
            $q.Proxy = $null
            $q.Method = $Method
            $q.AllowAutoRedirect = $false
            $q.KeepAlive = $false
            $q.UseDefaultCredentials = $false
            $q.UserAgent = 'edo-pki-monitor'
            $q.Timeout = $left
            $q.ReadWriteTimeout = $left
            if ($Tail -gt 0) { $q.AddRange(-$Tail) } elseif ($null -ne $RangeFrom) { $q.AddRange([long]$RangeFrom, [long]$RangeTo) }
            if ($null -ne $Body) {
                $q.ContentType = $ContentType
                $q.ContentLength = $Body.Length
                $s = $q.GetRequestStream(); $s.Write($Body, 0, $Body.Length); $s.Close()
            }
            try { $p = $q.GetResponse() }
            catch [Net.WebException] { if ($null -ne $_.Exception.Response) { $p = $_.Exception.Response } else { throw } }
            try {
                $r.Http = [int]$p.StatusCode
                if ($r.Http -in 301, 302, 303, 307, 308) {
                    $location = $p.Headers['Location']
                    if (-not $location) { $r.State = 30; $r.Error = "HTTP $($r.Http) without Location"; return $r }
                    if ($hop + 1 -ge $script:PkiBudget.MaxRedirects + 1) { $r.State = 30; $r.Error = 'too many redirects'; return $r }
                    $next = $null
                    if (-not [Uri]::TryCreate($current, $location, [ref]$next) -or $next.Scheme -ne 'http') {
                        $r.State = 30; $r.Error = 'redirect to a non-http address refused'; return $r
                    }
                    $current = $next
                    $r.FinalUrl = $next.AbsoluteUri
                    continue
                }
                if ($r.Http -ne 200 -and $r.Http -ne 206) { $r.State = 30; $r.Error = "HTTP $($r.Http)"; return $r }
                $cr = $p.Headers['Content-Range']
                if ($cr -match '/(\d+)\s*$') { $r.Total = [long]$Matches[1] }
                $st = $p.GetResponseStream()
                $buf = [byte[]]::new(16384)
                $ms = New-Object IO.MemoryStream
                while ($true) {
                    $left = $budget - [int]$sw.ElapsedMilliseconds
                    if ($left -le 0) { $r.State = 20; $r.Error = "budget of $budget ms spent reading the body"; return $r }
                    $st.ReadTimeout = $left
                    $want = [Math]::Min($buf.Length, $MaxBytes + 1 - [int]$ms.Length)
                    if ($want -le 0) { break }
                    $n = $st.Read($buf, 0, $want)
                    if ($n -le 0) { break }
                    $ms.Write($buf, 0, $n)
                }
                $all = $ms.ToArray()
                if ($all.Length -gt $MaxBytes) {
                    $r.More = $true
                    $cut = [byte[]]::new($MaxBytes); [Array]::Copy($all, $cut, $MaxBytes); $all = $cut
                }
                $r.Bytes = $all
                return $r
            } finally {
                # Abort before Close: closing a response on .NET Framework drains the rest of the body (a 52 MB list).
                $q.Abort()
                $p.Close()
            }
        }
    } catch {
        $x = $_.Exception.GetBaseException()
        $r.Error = Get-PkiErrorText $_.Exception
        # PowerShell wraps the WebException (MethodInvocationException), so its Status is looked up along the chain.
        $web = $_.Exception
        while ($null -ne $web -and $web -isnot [Net.WebException]) { $web = $web.InnerException }
        if ($x -is [Net.Sockets.SocketException]) { $r.State = Get-PkiSocketState $x.SocketErrorCode }
        elseif ($null -ne $web -and $web.Status -eq [Net.WebExceptionStatus]::NameResolutionFailure) { $r.State = 10 }
        elseif (($null -ne $web -and $web.Status -eq [Net.WebExceptionStatus]::Timeout) -or $x -is [TimeoutException]) { $r.State = 20 }
        else { $r.State = 24 }
        if ($r.State -eq 24 -and $sw.ElapsedMilliseconds -ge $budget) { $r.State = 20 }
        return $r
    } finally {
        $r.Ms = [int]$sw.ElapsedMilliseconds
        # A timeout of a budget shortened by the pass deadline says nothing about the address.
        if ($r.State -eq 20 -and $budget -lt $TimeoutMs) { $r.State = 90; $r.Error = 'pass deadline reached' }
    }
}

# ---------------------------------------------------------------- discovery

# Addresses from macros and from certificates pass the same check: they reach item keys, JSONPath filters and
# HttpWebRequest. No %, ?, &, quotes or spaces (agent2 refuses some in key parameters, cmd.exe expands %VAR%).
$script:PkiUrlPattern = '^http://[A-Za-z0-9][A-Za-z0-9.-]{0,252}(?::[0-9]{1,5})?(?:/[A-Za-z0-9._/-]*)?\z'

function Test-PkiUrl {
    param([string]$Url)
    [bool]($Url -cmatch $script:PkiUrlPattern)
}

# Short certificate id without owner data: the first 8 hex digits of SHA-256 of the thumbprint.
function Get-PkiCertId {
    param($Cert)
    (ConvertTo-PkiHex ([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::ASCII.GetBytes($Cert.Thumbprint)))).Substring(0, 8)
}


function Add-PkiExpected {
    param($Map, [string]$Url, [string]$Ca, [string]$Issuer, $Aki)
    if (-not $Map.Contains($Url)) { $Map[$Url] = @{ Ca = $Ca; Expected = New-Object Collections.ArrayList; Explicit = $false } }
    foreach ($x in $Map[$Url].Expected) { if ($x.Issuer -eq $Issuer -and $x.Aki -eq $Aki) { return } }
    [void]$Map[$Url].Expected.Add(@{ Issuer = $Issuer; Aki = $Aki })
}

# From valid certificates to what gets checked: CRL and caIssuers addresses with the expected issuer and AKI of the
# link that announces them, OCSP by certificate with its issuer, and the CAs whose local CRL is needed (issuers of
# non-self-signed links that have an http CDP). A refused address only raises Incomplete.
function Get-PkiDiscovery {
    param([object[]]$Certificates = @(), [object[]]$ExtraStore = @(), [string[]]$ExplicitCrlUrls = @(), [datetime]$Now = [datetime]::UtcNow)
    $d = @{ Crl = [ordered]@{}; Aia = [ordered]@{}; Ocsp = New-Object Collections.ArrayList; Cas = [ordered]@{}; Incomplete = 0 }
    $chains = [Diagnostics.Stopwatch]::StartNew()
    $seen = @{}; $ocspSeen = @{}
    foreach ($c in @($Certificates)) {
        if ($null -eq $c -or $seen.ContainsKey($c.Thumbprint)) { continue }
        $seen[$c.Thumbprint] = $true
        if ($c.NotBefore.ToUniversalTime() -gt $Now -or $c.NotAfter.ToUniversalTime() -lt $Now) { continue }
        # Building a chain may fetch caIssuers (1 s each): past its own share the rest is a gap. The share is counted
        # from here, not from the pass start, so a slow container extraction does not empty the address lists.
        if ($chains.ElapsedMilliseconds -ge $script:PkiBudget.DiscoveryMs) { $d.Incomplete++; continue }
        $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(1)
        foreach ($x in @($ExtraStore)) { if ($null -ne $x) { [void]$chain.ChainPolicy.ExtraStore.Add($x) } }
        try {
            # The Build result is not used: an untrusted or partial chain still lists the links that matter.
            [void]$chain.Build($c)
            $links = @($chain.ChainElements | ForEach-Object { $_.Certificate })
        } finally { $chain.Reset() }
        for ($i = 0; $i -lt $links.Count; $i++) {
            $e = $links[$i]
            $issuer = $null; if ($i + 1 -lt $links.Count) { $issuer = $links[$i + 1] }
            $selfSigned = (ConvertTo-PkiHex $e.SubjectName.RawData) -eq (ConvertTo-PkiHex $e.IssuerName.RawData)
            try { $urls = Get-PkiCertUrls $e; $aki = Get-PkiAki $e }
            catch { $d.Incomplete++; continue }
            $ca = $e.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $true)
            $httpCdp = 0
            foreach ($raw in $urls.Cdp) {
                $u = 'http://' + $raw.Substring(7)
                if (-not (Test-PkiUrl $u)) { $d.Incomplete++; continue }
                $httpCdp++
                Add-PkiExpected $d.Crl $u $ca $e.Issuer $aki
            }
            foreach ($raw in $urls.CaIssuers) {
                $u = 'http://' + $raw.Substring(7)
                if (-not (Test-PkiUrl $u)) { $d.Incomplete++; continue }
                Add-PkiExpected $d.Aia $u $ca $e.Issuer $aki
            }
            foreach ($raw in $urls.Ocsp) {
                $u = 'http://' + $raw.Substring(7)
                if (-not (Test-PkiUrl $u)) { $d.Incomplete++; continue }
                if ($ocspSeen.ContainsKey($e.Thumbprint)) { continue }
                $ocspSeen[$e.Thumbprint] = $true
                [void]$d.Ocsp.Add(@{ Cert = $e; Issuer = $issuer; Url = $u; Id = Get-PkiCertId $e; Ca = $ca; NotAfter = $e.NotAfter.ToUniversalTime().ToString('yyyy-MM-dd') })
            }
            if (-not $selfSigned -and $httpCdp -gt 0) {
                $key = 'name:' + $e.Issuer
                if ($aki) { $key = $aki }
                if (-not $d.Cas.Contains($key)) { $d.Cas[$key] = @{ Ca = $ca; Aki = $aki; Issuer = $e.Issuer } }
            }
        }
    }
    foreach ($raw in @($ExplicitCrlUrls)) {
        if (-not $raw) { continue }
        if (-not (Test-PkiUrl $raw)) { $d.Incomplete++; continue }
        if (-not $d.Crl.Contains($raw)) { $d.Crl[$raw] = @{ Ca = ([Uri]$raw).Host; Expected = New-Object Collections.ArrayList; Explicit = $true } }
    }
    $d
}

function Get-PkiStoreCertificates {
    param([string[]]$Stores = @())
    $r = @{ Certs = New-Object Collections.ArrayList; Sources = New-Object Collections.ArrayList; Incomplete = 0 }
    foreach ($name in @($Stores)) {
        if (-not $name) { continue }
        $s = New-Object Security.Cryptography.X509Certificates.X509Store($name, [Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
        try {
            $s.Open([Security.Cryptography.X509Certificates.OpenFlags]'ReadOnly, OpenExistingOnly')
            $certs = @($s.Certificates)
            foreach ($x in $certs) { [void]$r.Certs.Add($x) }
            [void]$r.Sources.Add([ordered]@{ name = "store:$name"; state = 0; certs = $certs.Count })
        } catch {
            [void]$r.Sources.Add([ordered]@{ name = "store:$name"; state = 1; certs = 0 })
            $r.Incomplete++
        } finally { $s.Close() }
    }
    $r
}

# ---------------------------------------------------------------- CryptoPro containers

function Find-PkiCsptest {
    foreach ($root in @($env:ProgramFiles, [Environment]::GetEnvironmentVariable('ProgramFiles(x86)'))) {
        if (-not $root) { continue }
        $candidate = Join-Path $root 'Crypto Pro\CSP\csptest.exe'
        if ([IO.File]::Exists($candidate)) { return $candidate }
    }
    $null
}

# A container name from csptest output is data written by users. The part after \\.\<reader>\ may hold quotes,
# spaces and Cyrillic; a backslash or a control character is refused.
function Test-PkiContainerName {
    param([string]$Name)
    [bool]($Name -cmatch '^\\\\\.\\[^\\\x00-\x1F]+\\[^\\\x00-\x1F]+\z')
}

# One command-line argument by the CommandLineToArgvW rules: backslashes before a quote and at the end are
# doubled, a quote is escaped. Without this a name starting with a quote right after the reader's backslash would
# end the argument early and pass its own arguments (-expcert, -sec_descr) to a SYSTEM process.
function ConvertTo-PkiArgument {
    param([string]$Value)
    $sb = New-Object Text.StringBuilder
    [void]$sb.Append([char]34)
    $slashes = 0
    foreach ($ch in $Value.ToCharArray()) {
        if ($ch -eq [char]92) { $slashes++; continue }
        if ($ch -eq [char]34) { [void]$sb.Append([char]92, 2 * $slashes + 1); [void]$sb.Append([char]34); $slashes = 0; continue }
        if ($slashes -gt 0) { [void]$sb.Append([char]92, $slashes); $slashes = 0 }
        [void]$sb.Append($ch)
    }
    [void]$sb.Append([char]92, 2 * $slashes)
    [void]$sb.Append([char]34)
    $sb.ToString()
}

function Invoke-PkiProcess {
    param([string]$Path, [string]$Arguments, [int]$TimeoutMs, [Text.Encoding]$Encoding = $null)
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $Path
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.WorkingDirectory = [IO.Path]::GetTempPath()
    if ($null -ne $Encoding) { $psi.StandardOutputEncoding = $Encoding }
    $p = [Diagnostics.Process]::Start($psi)
    $out = $p.StandardOutput.ReadToEndAsync()
    [void]$p.StandardError.ReadToEndAsync()
    $r = @{ TimedOut = $false; ExitCode = $null; Stdout = ''; StdoutComplete = $false }
    if (-not $p.WaitForExit($TimeoutMs)) {
        try { $p.Kill() } catch { }
        $r.TimedOut = $true
        return $r
    }
    $r.ExitCode = $p.ExitCode
    if ($out.Wait(2000)) { $r.Stdout = $out.Result; $r.StdoutComplete = $true }
    $r
}

# Certificate of one container through csptest; the export file is created in the protected cache directory.
function Export-PkiContainerCertificate {
    param([string]$CsptestPath, [string]$Name, [string]$OutDir, [int]$TimeoutMs)
    foreach ($keyType in 'exchange', 'signature') {
        $file = Join-Path $OutDir ('export-' + [guid]::NewGuid().ToString('N') + '.cer')
        try {
            $arguments = '-keyset -keytype {0} -container {1} -expcert {2}' -f $keyType, (ConvertTo-PkiArgument $Name), (ConvertTo-PkiArgument $file)
            $p = Invoke-PkiProcess -Path $CsptestPath -Arguments $arguments -TimeoutMs $TimeoutMs
            if ($p.TimedOut) { return @{ Cert = $null; TimedOut = $true } }
            if ([IO.File]::Exists($file)) {
                return @{ Cert = (New-Object Security.Cryptography.X509Certificates.X509Certificate2 (, [IO.File]::ReadAllBytes($file))); TimedOut = $false }
            }
        } catch {
        } finally {
            try { [IO.File]::Delete($file) } catch { }
        }
    }
    @{ Cert = $null; TimedOut = $false }
}

$script:PkiCacheSids = @('S-1-5-18', 'S-1-5-32-544')

function Test-PkiCacheDirTrusted {
    param([string]$Path)
    $info = New-Object IO.DirectoryInfo $Path
    if (-not $info.Exists -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return $false }
    $acl = $info.GetAccessControl()
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $foreign = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object { $script:PkiCacheSids -notcontains $_.IdentityReference.Value })
    $acl.AreAccessRulesProtected -and $script:PkiCacheSids -contains $owner -and $foreign.Count -eq 0
}

# The cache holds certificates with full names, so only SYSTEM and Administrators may reach it. Anything else at
# the path (any user may create folders and junctions in ProgramData) is not repaired in place: an ACL change or a
# cleanup would follow a junction or a hard link to its target. It is renamed aside (a rename moves the junction
# itself) and a new directory is created with the ACL. Returns $true when something was set aside.
function Initialize-PkiCacheDir {
    param([string]$Path)
    $aside = $false
    if ([IO.Directory]::Exists($Path) -or [IO.File]::Exists($Path)) {
        if (Test-PkiCacheDirTrusted $Path) { return $false }
        $target = $Path + '.untrusted-' + [guid]::NewGuid().ToString('N')
        if ([IO.Directory]::Exists($Path)) { [IO.Directory]::Move($Path, $target) } else { [IO.File]::Move($Path, $target) }
        $aside = $true
    }
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544'))
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in $script:PkiCacheSids) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule (New-Object Security.Principal.SecurityIdentifier $sid), 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
    }
    [void][IO.Directory]::CreateDirectory($Path, $acl)
    # Something planted again between the rename and the creation is not used.
    if (-not (Test-PkiCacheDirTrusted $Path)) { throw "cache directory $Path is not protected" }
    $aside
}

function Get-PkiCache {
    param([string]$Dir)
    $cache = @{ v = 1; containers = @{}; crl_issuers = @{} }
    $file = Join-Path $Dir 'cache.json'
    if (-not [IO.File]::Exists($file)) { return $cache }
    try {
        $j = [IO.File]::ReadAllText($file) | ConvertFrom-Json
        foreach ($p in @($j.containers.PSObject.Properties)) { $cache.containers[$p.Name] = @{ extracted_utc = [string]$p.Value.extracted_utc; not_after = [string]$p.Value.not_after; cert = [string]$p.Value.cert } }
        foreach ($p in @($j.crl_issuers.PSObject.Properties)) { $cache.crl_issuers[$p.Name] = @{ issuer = [string]$p.Value.issuer; aki = [string]$p.Value.aki } }
    } catch { }
    $cache
}

function Save-PkiCache {
    param([string]$Dir, $Cache)
    $file = Join-Path $Dir 'cache.json'
    $tmp = Join-Path $Dir ('cache-' + [guid]::NewGuid().ToString('N') + '.tmp')
    [IO.File]::WriteAllText($tmp, ($Cache | ConvertTo-Json -Depth 5 -Compress), (New-Object Text.UTF8Encoding $false))
    if ([IO.File]::Exists($file)) { [IO.File]::Replace($tmp, $file, [NullString]::Value) } else { [IO.File]::Move($tmp, $file) }
}

# A certificate from a cache entry, or $null when the entry does not decode.
function ConvertFrom-PkiCachedCert {
    param($Entry)
    try { New-Object Security.Cryptography.X509Certificates.X509Certificate2 (, [Convert]::FromBase64String($Entry.cert)) } catch { $null }
}

function Get-PkiNameKey {
    param([string]$Name)
    ConvertTo-PkiHex ([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($Name)))
}

# Certificates of the containers visible to this account. csptest runs only for a new name, an entry older than a
# day, or a certificate that expired after it was cached. After the first extraction that hits its limit the rest
# of the pass uses the cache only, and the discovery share of the pass deadline is never exceeded.
function Get-PkiContainerCertificates {
    param([string]$CsptestPath, [string]$CacheDir, [int]$CsptestMs = $script:PkiBudget.CsptestMs, [int]$BudgetMs = $script:PkiBudget.DiscoveryMs)
    $r = @{ Certs = New-Object Collections.ArrayList; Source = [ordered]@{ name = 'containers'; state = 0; certs = 0 }; Incomplete = 0 }
    if (-not $CsptestPath -or -not [IO.File]::Exists($CsptestPath)) { $r.Source.state = 1; $r.Incomplete = 1; return $r }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try { [void](Initialize-PkiCacheDir $CacheDir) } catch { $r.Source.state = 1; $r.Incomplete = 1; return $r }
    $cache = Get-PkiCache $CacheDir
    $enum = Invoke-PkiProcess -Path $CsptestPath -Arguments '-keyset -enum_cont -fqcn -verifycontext' -TimeoutMs ([Math]::Min($CsptestMs, $BudgetMs)) -Encoding ([Text.Encoding]::GetEncoding(866))
    # A timeout, a non-zero exit or output not read in time leaves the set unknown (the exit code on a host without
    # containers is not measured): listed names are served, and every other cached certificate stays in the list and
    # in the cache rather than silently shrinking the addresses.
    $complete = -not $enum.TimedOut -and $enum.ExitCode -eq 0 -and $enum.StdoutComplete
    if (-not $complete) { $r.Source.state = 1; $r.Incomplete++ }
    $names = @($enum.Stdout -split "`r?`n" | Where-Object { $_.StartsWith('\\.\') })
    $now = [datetime]::UtcNow
    $hung = $false
    $keep = @{}
    foreach ($name in $names) {
        if (-not (Test-PkiContainerName $name)) { $r.Incomplete++; continue }
        $key = Get-PkiNameKey $name
        $keep[$key] = $true
        $need = $true
        if ($cache.containers.ContainsKey($key)) {
            $entry = $cache.containers[$key]
            $extracted = [datetime]::Parse($entry.extracted_utc, [Globalization.CultureInfo]::InvariantCulture).ToUniversalTime()
            $notAfter = [datetime]::Parse($entry.not_after, [Globalization.CultureInfo]::InvariantCulture).ToUniversalTime()
            $need = ($extracted -lt $now.AddHours(-24)) -or ($notAfter -lt $now -and $notAfter -gt $extracted)
        }
        $cert = $null
        if ($need) {
            if ($hung -or $sw.ElapsedMilliseconds -ge $BudgetMs) { $r.Incomplete++ }
            else {
                $limit = [Math]::Min($CsptestMs, $BudgetMs - [int]$sw.ElapsedMilliseconds)
                $x = Export-PkiContainerCertificate -CsptestPath $CsptestPath -Name $name -OutDir $CacheDir -TimeoutMs $limit
                if ($x.TimedOut) { $hung = $true; $r.Incomplete++ }
                elseif ($null -eq $x.Cert) { $r.Incomplete++ }
                else {
                    $cert = $x.Cert
                    $cache.containers[$key] = @{ extracted_utc = $now.ToString('o'); not_after = $cert.NotAfter.ToUniversalTime().ToString('o'); cert = [Convert]::ToBase64String($cert.RawData) }
                }
            }
        }
        if ($null -eq $cert -and $cache.containers.ContainsKey($key)) {
            $cert = ConvertFrom-PkiCachedCert $cache.containers[$key]
        }
        if ($null -ne $cert) { [void]$r.Certs.Add($cert) }
    }
    foreach ($k in @($cache.containers.Keys)) {
        if ($keep.ContainsKey($k)) { continue }
        if ($complete) { $cache.containers.Remove($k); continue }
        $cached = ConvertFrom-PkiCachedCert $cache.containers[$k]
        if ($null -ne $cached) { [void]$r.Certs.Add($cached) }
    }
    Save-PkiCache $CacheDir $cache
    $r.Source.certs = $r.Certs.Count
    $r
}

# ---------------------------------------------------------------- local CRLs (machine CA store)

$script:PkiCrlStoreType = @'
using System; using System.Collections.Generic; using System.Runtime.InteropServices;
namespace EdoPki {
    public static class CrlStore {
        [StructLayout(LayoutKind.Sequential)] struct CRL_CONTEXT { public uint Encoding; public IntPtr Data; public uint Size; public IntPtr Info; public IntPtr Store; }
        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern IntPtr CertOpenStore(IntPtr prov, uint enc, IntPtr hp, uint flags, string para);
        [DllImport("crypt32.dll", SetLastError = true)] static extern IntPtr CertEnumCRLsInStore(IntPtr store, IntPtr prev);
        [DllImport("crypt32.dll")] public static extern bool CertCloseStore(IntPtr store, uint flags);
        // CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG
        public static IntPtr OpenMachine(string name) {
            IntPtr s = CertOpenStore((IntPtr)10, 0, IntPtr.Zero, 0x20000 | 0x8000 | 0x4000, name);
            if (s == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            return s;
        }
        // Only the head and the tail of every CRL are copied: the FNS list is 52 MB.
        public static List<byte[][]> Read(IntPtr store, int head, int tail) {
            var list = new List<byte[][]>(); IntPtr p = IntPtr.Zero;
            while ((p = CertEnumCRLsInStore(store, p)) != IntPtr.Zero) {
                var c = (CRL_CONTEXT)Marshal.PtrToStructure(p, typeof(CRL_CONTEXT));
                int size = (int)c.Size, h = Math.Min(head, size), t = Math.Min(tail, size);
                var hb = new byte[h]; Marshal.Copy(c.Data, hb, 0, h);
                var tb = new byte[t]; Marshal.Copy(new IntPtr(c.Data.ToInt64() + size - t), tb, 0, t);
                list.Add(new byte[][] { hb, tb });
            }
            return list;
        }
    }
}
'@

function Read-PkiLocalCrls {
    param([IntPtr]$StoreHandle = [IntPtr]::Zero)
    if (-not ('EdoPki.CrlStore' -as [type])) { Add-Type -TypeDefinition $script:PkiCrlStoreType }
    $own = $StoreHandle -eq [IntPtr]::Zero
    if ($own) { $StoreHandle = [EdoPki.CrlStore]::OpenMachine('CA') }
    try {
        foreach ($pair in [EdoPki.CrlStore]::Read($StoreHandle, 16384, 4096)) {
            $h = Read-PkiCrlHead $pair[0]
            if ($null -eq $h) { continue }
            $aki = Find-PkiCrlAki $pair[1]
            if (-not $aki) { $aki = Find-PkiCrlAki $pair[0] }
            @{ Issuer = $h.Issuer; Aki = $aki; ThisUpdate = $h.ThisUpdate; NextUpdate = $h.NextUpdate }
        }
    } finally {
        if ($own) { [void][EdoPki.CrlStore]::CertCloseStore($StoreHandle, 0) }
    }
}

# One row per needed CA: 0 a valid list, 1 no list, 2 the newest matching list expired. Matched by AKI (an old
# list of the same name but another key does not count), by issuer name only for a link without AKI.
function Get-PkiLocalCheck {
    param($Cas, [object[]]$Crls, [datetime]$Now = [datetime]::UtcNow)
    foreach ($key in @($Cas.Keys)) {
        $ca = $Cas[$key]
        $matching = @($Crls | Where-Object { if ($ca.Aki) { $_.Aki -eq $ca.Aki } else { $_.Issuer -eq $ca.Issuer } })
        $best = $null
        foreach ($c in $matching) { if ($null -eq $best -or ($null -ne $c.NextUpdate -and ($null -eq $best.NextUpdate -or $c.NextUpdate -gt $best.NextUpdate))) { $best = $c } }
        $row = [ordered]@{ ca = $ca.Ca; aki = $key; state = 1; hours_left = -1; pct_left = -1 }
        if ($null -ne $best) {
            $row.state = 0
            if ($null -ne $best.NextUpdate) {
                $left = ($best.NextUpdate - $Now).TotalHours
                $period = ($best.NextUpdate - $best.ThisUpdate).TotalHours
                $row.hours_left = [Math]::Round($left, 1)
                if ($period -gt 0) { $row.pct_left = [Math]::Round(100 * $left / $period, 1) }
                if ($left -lt 0) { $row.state = 2 }
            }
        }
        $row
    }
}

# ---------------------------------------------------------------- checks

function Get-PkiCommonName {
    param([string]$Dn)
    if ($Dn -match '(?:^|,\s*)CN=("(?:[^"]|"")*"|[^,]*)') { return $Matches[1].Trim('"') }
    $Dn
}

# A row of a list left unchecked by the pass deadline, in the field order of the output contract.
function New-PkiUncheckedRow {
    param([string]$List, [string]$Url, [string]$Ca = '')
    $row = [ordered]@{}
    foreach ($f in $script:PkiContract[$List]) { if ($f -notin 'skew_s', 'key_days') { $row[$f] = -1 } }
    $row.url = $Url; $row.state = 90; $row.error = 'pass deadline reached'
    if ($row.Contains('ca')) { $row.ca = $Ca }
    $row
}

function Test-PkiAkiExpected {
    param($Expected, $Aki)
    $keyed = @($Expected | Where-Object { $_.Aki })
    if ($keyed.Count -eq 0) { return $true }
    [bool](@($keyed | Where-Object { $_.Aki -eq $Aki }).Count)
}

# CRL by address from its head and tail. Returns @{ Row; Learned } where Learned is the issuer and AKI of a list
# from the explicit list.
function Test-PkiCrlAddress {
    param([string]$Url, $Entry, [datetime]$Now = [datetime]::UtcNow)
    $row = [ordered]@{ url = $Url; ca = $Entry.Ca; state = 0; http = -1; ms = -1; hours_left = -1; error = '' }
    $out = @{ Row = $row; Learned = $null }
    $head = Invoke-PkiHttp -Url $Url -RangeFrom 0 -RangeTo 16383 -MaxBytes 16384
    $row.http = $head.Http; $row.ms = $head.Ms; $row.error = $head.Error; $row.state = $head.State
    if ($head.State -ne 0) { return $out }
    $h = Read-PkiCrlHead $head.Bytes
    if ($null -eq $h) { $row.state = 40; $row.error = 'not a CRL'; return $out }
    if ($null -ne $h.NextUpdate) { $row.hours_left = [Math]::Round(($h.NextUpdate - $Now).TotalHours, 1) }
    # A list from the explicit list is named by its issuer once parsed; until then by the host of its address.
    if ($Entry.Explicit) { $row.ca = Get-PkiCommonName $h.Issuer }
    $expired = $null -ne $h.NextUpdate -and $h.NextUpdate -lt $Now
    if ($head.Http -eq 200 -and $head.More) {
        # The head alone proves an expired list; the rest of the content stays unchecked.
        if ($expired) { $row.state = 44; $row.error = 'nextUpdate is in the past' } else { $row.state = 1; $row.error = 'server ignores Range: content not checked' }
        return $out
    }
    $akiSource = $head.Bytes
    if ($head.Http -eq 206 -and $null -ne $head.Total -and $head.Total -ne $h.Total) { $row.state = 41; $row.error = "size $($head.Total) on the server, $($h.Total) by DER"; return $out }
    if ($head.Http -eq 200 -and $h.Total -ne $head.Bytes.Length) { $row.state = 41; $row.error = "size $($head.Bytes.Length) received, $($h.Total) by DER"; return $out }
    if ($h.Total -gt $head.Bytes.Length) {
        $tail = Invoke-PkiHttp -Url $Url -Tail 4096 -MaxBytes 4096
        $row.ms += [Math]::Max(0, $tail.Ms)
        if ($tail.State -ne 0) { $row.state = $tail.State; $row.http = $tail.Http; $row.error = $tail.Error; return $out }
        if ($tail.Http -ne 206) {
            # The tail request got the file from its start: there is no end of the list to read the AKI from.
            if ($expired) { $row.state = 44; $row.error = 'nextUpdate is in the past' } else { $row.state = 1; $row.error = 'server ignores Range on the tail: content not checked' }
            return $out
        }
        $akiSource = $tail.Bytes
    }
    $aki = Find-PkiCrlAki $akiSource
    if ($Entry.Explicit) {
        if ($aki) { $out.Learned = @{ Issuer = $h.Issuer; Aki = $aki; Ca = $row.ca } }
    } else {
        if (@($Entry.Expected | Where-Object { $_.Issuer -eq $h.Issuer }).Count -eq 0) { $row.state = 42; $row.error = 'issuer differs from the certificate'; return $out }
        if (-not (Test-PkiAkiExpected $Entry.Expected $aki)) { $row.state = 43; $row.error = 'AKI differs from the certificate'; return $out }
    }
    if ($expired) { $row.state = 44; $row.error = 'nextUpdate is in the past' }
    $out
}

function Test-PkiAiaAddress {
    param([string]$Url, $Entry)
    $row = [ordered]@{ url = $Url; ca = $Entry.Ca; state = 0; http = -1; ms = -1; error = '' }
    $r = Invoke-PkiHttp -Url $Url -MaxBytes 262144
    $row.http = $r.Http; $row.ms = $r.Ms; $row.error = $r.Error; $row.state = $r.State
    if ($r.State -ne 0) { return $row }
    try {
        if ($r.More) { throw 'too large for a certificate' }
        $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 (, [byte[]]$r.Bytes)
        $ski = Get-PkiSki $cert
    } catch { $row.state = 40; $row.error = 'not a certificate'; return $row }
    if (@($Entry.Expected | Where-Object { $_.Issuer -eq $cert.Subject }).Count -eq 0) { $row.state = 42; $row.error = 'subject differs from the issuer of the link'; return $row }
    if (-not (Test-PkiAkiExpected $Entry.Expected $ski)) { $row.state = 43; $row.error = 'SKI differs from the AKI of the link' }
    $row
}

function New-PkiRandomBytes {
    param([int]$Count)
    $b = [byte[]]::new($Count)
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    , $b
}

function Test-PkiTspService {
    param([string]$Url)
    $row = [ordered]@{ url = $Url; state = 0; http = -1; ms = -1; error = '' }
    $imprint = New-PkiRandomBytes 32
    $nonce = New-PkiRandomBytes 8
    $nonce[0] = ($nonce[0] -band 0x7F) -bor 0x01
    $sent = [datetime]::UtcNow
    $r = Invoke-PkiHttp -Url $Url -Method POST -Body (New-PkiTspRequest -Imprint $imprint -Nonce $nonce) -ContentType 'application/timestamp-query' -MaxBytes 262144
    $received = [datetime]::UtcNow
    $row.http = $r.Http; $row.ms = $r.Ms; $row.error = $r.Error; $row.state = $r.State
    if ($r.State -ne 0) { return $row }
    try { $t = Read-PkiTspResponse -Bytes $r.Bytes -Imprint $imprint -Nonce $nonce }
    catch { $row.state = 40; $row.error = 'not a time-stamp response'; return $row }
    if ($t.Status -gt 1) { $row.state = 50; $row.error = "PKIStatus $($t.Status)"; return $row }
    if (-not $t.EchoOk) { $row.state = 51; $row.error = 'nonce or imprint not echoed'; return $row }
    # genTime has a 1 s resolution; the middle of the exchange is the fairest local moment to compare with.
    $row.skew_s = [Math]::Round(($sent.AddTicks(($received - $sent).Ticks / 2) - $t.GenTime).TotalSeconds, 1)
    if ($null -ne $t.KeyNotAfter) { $row.key_days = [int][Math]::Floor(($t.KeyNotAfter - [datetime]::UtcNow).TotalDays) }
    $row.Remove('error'); $row.error = ''
    $row
}

# ---------------------------------------------------------------- pass

$script:PkiVersion = '1.0.3'

# Positional arguments: network, local, stores, containers, crl_urls, tsp_urls. Lists are comma-separated.
function Test-PkiArgs {
    param([string[]]$Argv)
    $a = @($Argv)
    if ($a.Count -lt 6) { return @{ Error = "invalid arguments: expected 6, got $($a.Count)" } }
    foreach ($i in 0, 1, 3) { if ([string]$a[$i] -cnotmatch '^[01]\z') { return @{ Error = "invalid argument $($i + 1): expected 0 or 1" } } }
    $split = { param($s) @([string]$s -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    $stores = @(& $split $a[2])
    foreach ($s in $stores) { if ($s -cnotmatch '^[A-Za-z0-9 ]{1,64}\z') { return @{ Error = 'invalid argument 3: store names use A-Z a-z 0-9 and spaces' } } }
    $crl = @(& $split $a[4])
    $tsp = @(& $split $a[5])
    foreach ($u in @($crl) + @($tsp)) { if (-not (Test-PkiUrl $u)) { return @{ Error = 'invalid argument: addresses must be http:// with A-Z a-z 0-9 . _ / - only' } } }
    @{ Error = $null; Network = $a[0] -eq '1'; Local = $a[1] -eq '1'; Stores = $stores; Containers = $a[3] -eq '1'; CrlUrls = $crl; TspUrls = $tsp }
}

function New-PkiErrorResult {
    param([string]$Message, [int]$Ms = -1)
    if ($Message.Length -gt 300) { $Message = $Message.Substring(0, 300) }
    [ordered]@{ v = 1; ver = $script:PkiVersion; ms = $Ms; deadline = 0; error = $Message; incomplete = 0 }
}

function Invoke-PkiCollector {
    param(
        [string[]] $Argv,
        [object[]] $Certificates = @(),
        [object[]] $ExtraStore = @(),
        [string] $CsptestPath = $null,
        [string] $CacheDir = (Join-Path $env:ProgramData 'zabbix-edo-pki-monitor'),
        [IntPtr] $LocalStoreHandle = [IntPtr]::Zero,
        [int] $PassBudgetMs = $script:PkiBudget.PassMs
    )
    Start-PkiPass -BudgetMs $PassBudgetMs
    $opt = Test-PkiArgs $Argv
    if ($opt.Error) { return New-PkiErrorResult $opt.Error ([int]$script:PkiPass.ElapsedMilliseconds) }
    $now = [datetime]::UtcNow
    $r = [ordered]@{ v = 1; ver = $script:PkiVersion; ms = 0; deadline = 0; error = ''; incomplete = 0; sources = New-Object Collections.ArrayList
        crl = New-Object Collections.ArrayList; aia = New-Object Collections.ArrayList; ocsp = New-Object Collections.ArrayList; certs = New-Object Collections.ArrayList
        local = New-Object Collections.ArrayList; tsp = New-Object Collections.ArrayList }

    $all = New-Object Collections.ArrayList
    foreach ($c in @($Certificates)) { if ($null -ne $c) { [void]$all.Add($c) } }
    if ($opt.Stores.Count) {
        $s = Get-PkiStoreCertificates -Stores $opt.Stores
        foreach ($x in $s.Certs) { [void]$all.Add($x) }
        foreach ($x in $s.Sources) { [void]$r.sources.Add($x) }
        $r.incomplete += $s.Incomplete
    }
    $useCache = $opt.Containers -or $opt.CrlUrls.Count -gt 0
    $cache = $null
    if ($useCache) {
        # A cache path a user keeps planted or holds open must not blind the network checks: they run without it.
        try { [void](Initialize-PkiCacheDir $CacheDir) }
        catch { $useCache = $false; [void]$r.sources.Add([ordered]@{ name = 'cache'; state = 1; certs = 0 }); $r.incomplete++ }
    }
    if ($opt.Containers) {
        if (-not $CsptestPath) { $CsptestPath = Find-PkiCsptest }
        $cc = Get-PkiContainerCertificates -CsptestPath $CsptestPath -CacheDir $CacheDir
        foreach ($x in $cc.Certs) { [void]$all.Add($x) }
        [void]$r.sources.Add($cc.Source)
        $r.incomplete += $cc.Incomplete
    }
    $d = Get-PkiDiscovery -Certificates $all.ToArray() -ExtraStore (@($ExtraStore) + $all.ToArray()) -ExplicitCrlUrls $opt.CrlUrls -Now $now
    $r.incomplete += $d.Incomplete

    if ($useCache) { $cache = Get-PkiCache $CacheDir }
    if ($opt.Network) {
        foreach ($url in @($d.Crl.Keys)) {
            if (Test-PkiPassExpired) { [void]$r.crl.Add((New-PkiUncheckedRow crl $url $d.Crl[$url].Ca)); continue }
            $x = Test-PkiCrlAddress -Url $url -Entry $d.Crl[$url] -Now $now
            [void]$r.crl.Add($x.Row)
            if ($null -ne $x.Learned -and $null -ne $cache) { $cache.crl_issuers[$url] = @{ issuer = $x.Learned.Issuer; aki = $x.Learned.Aki } }
        }
        foreach ($url in @($d.Aia.Keys)) {
            if (Test-PkiPassExpired) { [void]$r.aia.Add((New-PkiUncheckedRow aia $url $d.Aia[$url].Ca)); continue }
            [void]$r.aia.Add((Test-PkiAiaAddress -Url $url -Entry $d.Aia[$url]))
        }
        $responders = [ordered]@{}
        foreach ($o in $d.Ocsp) {
            $cert = [ordered]@{ id = $o.Id; ca = $o.Ca; not_after = $o.NotAfter; ocsp = $o.Url; status = -1 }
            [void]$r.certs.Add($cert)
            if ($null -eq $o.Issuer) { $r.incomplete++; continue }
            # A responder that failed on the network is not asked again in this pass: a request per certificate to
            # a silent responder would spend the pass and leave the time-stamping services unchecked.
            if ($responders.Contains($o.Url) -and $responders[$o.Url].state -ge 10 -and $responders[$o.Url].state -le 24) { continue }
            if (Test-PkiPassExpired) { if (-not $responders.Contains($o.Url)) { $responders[$o.Url] = New-PkiUncheckedRow ocsp $o.Url }; $r.deadline = 1; continue }
            $h = Invoke-PkiHttp -Url $o.Url -Method POST -Body (New-PkiOcspRequest -Cert $o.Cert -Issuer $o.Issuer) -ContentType 'application/ocsp-request' -MaxBytes 262144
            $row = [ordered]@{ url = $o.Url; state = $h.State; http = $h.Http; ms = $h.Ms; error = $h.Error }
            if ($h.State -eq 0) {
                try {
                    $resp = Read-PkiOcspResponse -Bytes $h.Bytes -SerialHex $o.Cert.SerialNumber
                    if ($resp.ResponseStatus -ne 0) { $row.state = 50; $row.error = "responseStatus $($resp.ResponseStatus)" }
                    elseif ($null -eq $resp.CertStatus) { $row.state = 51; $row.error = 'no answer about the requested serial number' }
                    else { $cert.status = @{ good = 0; revoked = 1; unknown = 2 }[$resp.CertStatus] }
                } catch { $row.state = 40; $row.error = 'not an OCSP response' }
            }
            # The address state is the best outcome of its requests in this pass.
            if (-not $responders.Contains($o.Url) -or $responders[$o.Url].state -ne 0) { $responders[$o.Url] = $row }
        }
        foreach ($row in $responders.Values) { [void]$r.ocsp.Add($row) }
        foreach ($url in $opt.TspUrls) {
            if (Test-PkiPassExpired) { [void]$r.tsp.Add((New-PkiUncheckedRow tsp $url)); continue }
            [void]$r.tsp.Add((Test-PkiTspService -Url $url))
        }
    }

    if ($null -ne $cache) {
        foreach ($k in @($cache.crl_issuers.Keys)) { if ($opt.CrlUrls -notcontains $k) { $cache.crl_issuers.Remove($k) } }
        foreach ($url in $opt.CrlUrls) {
            if (-not $cache.crl_issuers.ContainsKey($url)) { continue }
            $learned = $cache.crl_issuers[$url]
            if ($learned.aki -and -not $d.Cas.Contains($learned.aki)) {
                $d.Cas[$learned.aki] = @{ Ca = (Get-PkiCommonName $learned.issuer); Aki = $learned.aki; Issuer = $learned.issuer }
            }
        }
        Save-PkiCache $CacheDir $cache
    }
    if ($opt.Local -and $d.Cas.Count -gt 0) {
        try {
            $crls = @(Read-PkiLocalCrls -StoreHandle $LocalStoreHandle)
            foreach ($row in (Get-PkiLocalCheck -Cas $d.Cas -Crls $crls -Now $now)) { [void]$r.local.Add($row) }
        } catch {
            [void]$r.sources.Add([ordered]@{ name = 'store:CA crls'; state = 1; certs = 0 })
            $r.incomplete++
        }
    }

    foreach ($list in $r.crl, $r.aia, $r.ocsp, $r.tsp) { if (@($list | Where-Object { $_.state -eq 90 }).Count) { $r.deadline = 1 } }
    $granted = @($r.tsp | Where-Object { $_.state -eq 0 -and $_.Contains('skew_s') })
    if ($granted.Count) { $r.clock_skew_s = @($granted | Sort-Object { [Math]::Abs($_.skew_s) })[0].skew_s }
    $r.ms = [int]$script:PkiPass.ElapsedMilliseconds
    $r
}

# ---------------------------------------------------------------- output

# Output contract, shared with the template: row fields by list (skew_s and key_days of tsp are optional)
# and the value maps. Template.Tests.ps1 checks the template against these tables.
$script:PkiContract = [ordered]@{
    result = @('v', 'ver', 'ms', 'deadline', 'error', 'incomplete', 'sources', 'crl', 'aia', 'ocsp', 'certs', 'local', 'tsp', 'clock_skew_s')
    sources = @('name', 'state', 'certs')
    crl = @('url', 'ca', 'state', 'http', 'ms', 'hours_left', 'error')
    aia = @('url', 'ca', 'state', 'http', 'ms', 'error')
    ocsp = @('url', 'state', 'http', 'ms', 'error')
    certs = @('id', 'ca', 'not_after', 'ocsp', 'status')
    local = @('ca', 'aki', 'state', 'hours_left', 'pct_left')
    tsp = @('url', 'state', 'http', 'ms', 'skew_s', 'key_days', 'error')
}
$script:PkiStateNames = [ordered]@{
    '0' = 'OK'; '1' = 'CONTENT_UNCHECKED'; '10' = 'DNS_FAIL'; '20' = 'TIMEOUT'; '22' = 'REFUSED'; '23' = 'FIREWALL_DENIED'; '24' = 'NETWORK_FAIL'
    '30' = 'HTTP_BAD'; '40' = 'BAD_FORMAT'; '41' = 'SIZE_MISMATCH'; '42' = 'ISSUER_MISMATCH'; '43' = 'KEY_MISMATCH'; '44' = 'LIST_EXPIRED'
    '50' = 'SERVICE_REFUSED'; '51' = 'ECHO_MISMATCH'; '90' = 'NOT_CHECKED'
}
$script:PkiCertStatusNames = [ordered]@{ '-1' = 'NOT_CHECKED'; '0' = 'GOOD'; '1' = 'REVOKED'; '2' = 'UNKNOWN' }
$script:PkiLocalStateNames = [ordered]@{ '0' = 'VALID'; '1' = 'MISSING'; '2' = 'EXPIRED' }
$script:PkiMaxOutput = 60000
$script:PkiFallbackJson = '{"v":1,"ver":"1.0.3","ms":-1,"deadline":0,"error":"JSON serialization failed","incomplete":0}'

# One line of ASCII JSON: non-ASCII as \uXXXX so the console code page cannot corrupt it. Longer than 60 000
# characters becomes a collector error without lists: the server cuts values at 65 535 characters silently.
function ConvertTo-PkiOutput {
    param($Result)
    foreach ($k in @($Result.Keys)) { if ($Result[$k] -is [Collections.IList]) { $Result[$k] = [object[]]@($Result[$k]) } }
    $json = ConvertTo-Json -InputObject $Result -Depth 6 -Compress
    $json = [regex]::Replace($json, '[^\x00-\x7F]', { param($m) '\u{0:x4}' -f [int][char]$m.Value })
    if ($json.Length -gt $script:PkiMaxOutput) {
        $e = New-PkiErrorResult ("output too large: $($json.Length) characters") $Result['ms']
        $e.incomplete = $Result['incomplete']
        $json = ConvertTo-Json -InputObject $e -Compress
    }
    $json
}

if ($MyInvocation.InvocationName -ne '.') {
    $ProgressPreference = 'SilentlyContinue'
    $WarningPreference = 'SilentlyContinue'
    $json = $script:PkiFallbackJson
    try {
        $result = Invoke-PkiCollector -Argv ([string[]]@($args))
        $json = ConvertTo-PkiOutput $result
    } catch {
        try { $json = ConvertTo-PkiOutput (New-PkiErrorResult ('collector failed: ' + (Get-PkiErrorText $_.Exception))) } catch { $json = $script:PkiFallbackJson }
    }
    [Console]::Out.Write($json)
    exit 0
}
