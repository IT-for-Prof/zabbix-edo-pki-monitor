# itforprof.com by Konstantin Tyutyunnik
# DER parsing of agent/edo-pki.ps1: CRL head and tail, certificate URLs, OCSP, TSP.
# Run under Windows PowerShell 5.1 with Pester 6.2.0:
#   powershell.exe -NoProfile -Command "Invoke-Pester -Path tests -CI"

BeforeAll {
    $script:CollectorPath = (Resolve-Path (Join-Path $PSScriptRoot '..\agent\edo-pki.ps1')).Path
    Import-Module (Join-Path $PSScriptRoot 'Helpers\Fixtures.psm1') -Force
    . $script:CollectorPath
    $script:Root = New-TestCert -Subject 'CN=Test Root CA, O=Test' -Ca
    $script:Mid = New-TestCert -Subject 'CN=Тестовый УЦ, O="ООО ""Тест"""' -Issuer $script:Root -Ca -Cdp 'http://cdp.test/root.crl', 'ldap:///CN=Root,CN=CDP'
    $script:Leaf = New-TestCert -Subject 'CN=Иванов Иван, SERIALNUMBER=123' -Issuer $script:Mid `
        -Cdp 'http://cdp.test/mid.crl', 'http://cdp2.test/mid.crl', 'ldap:///CN=Mid' -Ocsp 'http://ocsp.test/ocsp.srf' -CaIssuers 'http://aia.test/mid.cer', 'ldap:///CN=Mid,CN=AIA'
    $script:MidSki = @($script:Mid.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.14' })[0].SubjectKeyIdentifier

    function Get-Head([byte[]]$b, [int]$n = 16384) { $x = [byte[]]::new([Math]::Min($n, $b.Length)); [Array]::Copy($b, $x, $x.Length); , $x }
    function Get-Tail([byte[]]$b, [int]$n = 4096) { $len = [Math]::Min($n, $b.Length); $x = [byte[]]::new($len); [Array]::Copy($b, $b.Length - $len, $x, 0, $len); , $x }
}

Describe 'Source invariants' {
    It 'parses under Windows PowerShell 5.1, starts with a UTF-8 BOM and enables strict mode 2.0' {
        $PSVersionTable.PSVersion.Major | Should -Be 5
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($script:CollectorPath, [ref]$null, [ref]$errors)
        @($errors).Count | Should -Be 0
        $bytes = [IO.File]::ReadAllBytes($script:CollectorPath)
        ($bytes[0], $bytes[1], $bytes[2]) -join ',' | Should -Be '239,187,191'
        [IO.File]::ReadAllText($script:CollectorPath) | Should -Match '(?m)^\s*Set-StrictMode -Version 2\.0'
        [IO.File]::ReadAllText($script:CollectorPath) | Should -Match 'itforprof\.com by Konstantin Tyutyunnik'
    }
}

Describe 'CRL head and tail' {
    It 'reads issuer, thisUpdate, nextUpdate and DER size from the first 16 KB of a large list; AKI from the last 4 KB' {
        $next = [datetime]::UtcNow.AddHours(65)
        $crl = New-TestCrl -IssuerCert $script:Mid -NextUpdate $next -PadEntries 2000
        $crl.Length | Should -BeGreaterThan 30000
        $h = Read-PkiCrlHead (Get-Head $crl)
        $h.Total | Should -Be $crl.Length
        $h.Issuer | Should -Be $script:Mid.Subject
        ([datetime]$h.NextUpdate - $next).TotalSeconds | Should -BeGreaterThan -1.5
        ([datetime]$h.NextUpdate - $next).TotalSeconds | Should -BeLessThan 1.5
        $h.ThisUpdate | Should -BeLessThan $h.NextUpdate
        Find-PkiCrlAki (Get-Head $crl) | Should -BeNullOrEmpty -Because 'the extensions follow the revoked list'
        Find-PkiCrlAki (Get-Tail $crl) | Should -Be $script:MidSki
    }

    It 'a list smaller than the head gives every field from one read (the 2 KB Mintsifry case)' {
        $crl = New-TestCrl -IssuerCert $script:Mid
        $h = Read-PkiCrlHead $crl
        $h.Total | Should -Be $crl.Length
        Find-PkiCrlAki $crl | Should -Be $script:MidSki
    }

    It 'reads UTCTime as well as GeneralizedTime with a fraction' {
        $crl = New-TestCrl -IssuerCert $script:Mid -UtcTime -ThisUpdate ([datetime]'2026-09-16T16:50:45Z').ToUniversalTime() -NextUpdate ([datetime]'2026-09-19T11:10:00Z').ToUniversalTime()
        (Read-PkiCrlHead $crl).NextUpdate.ToString('o') | Should -Be '2026-09-19T11:10:00.0000000Z'
        $gt = New-PkiTlv 0x18 ([Text.Encoding]::ASCII.GetBytes('20260919111000.123Z'))
        (ConvertFrom-PkiTime $gt (Read-PkiTlv $gt 0)).ToString('o') | Should -Be '2026-09-19T11:10:00.0000000Z'
    }

    It 'a list without nextUpdate gives NextUpdate $null' {
        (Read-PkiCrlHead (New-TestCrl -IssuerCert $script:Mid -NextUpdate $null)).NextUpdate | Should -BeNullOrEmpty
    }

    It 'garbage never throws and is not a CRL: <name>' -ForEach @(
        @{ name = 'HTML'; bytes = [Text.Encoding]::ASCII.GetBytes('<html><body>Not found</body></html>') }
        @{ name = 'empty'; bytes = [byte[]]@() }
        @{ name = 'one byte'; bytes = [byte[]](0x30) }
        @{ name = 'length beyond 4 bytes'; bytes = [byte[]](0x30, 0x85, 1, 2, 3, 4, 5, 0x30) }
        @{ name = 'indefinite length'; bytes = [byte[]](0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x01) }
        @{ name = 'truncated inner'; bytes = [byte[]](0x30, 0x82, 0x10, 0x00, 0x30, 0x82, 0x0F, 0xF0, 0x02, 0x01) }
        @{ name = 'certificate instead of CRL'; bytes = $null }
    ) {
        if ($null -eq $bytes) { $bytes = $script:Leaf.RawData }
        { Read-PkiCrlHead $bytes } | Should -Not -Throw
        Read-PkiCrlHead $bytes | Should -BeNullOrEmpty
        { Find-PkiCrlAki $bytes } | Should -Not -Throw
    }
}

Describe 'Certificate URLs and key identifiers' {
    It 'takes only http addresses of CDP, AIA ocsp and caIssuers, in certificate order' {
        $u = Get-PkiCertUrls $script:Leaf
        @($u.Cdp) | Should -Be @('http://cdp.test/mid.crl', 'http://cdp2.test/mid.crl')
        @($u.Ocsp) | Should -Be @('http://ocsp.test/ocsp.srf')
        @($u.CaIssuers) | Should -Be @('http://aia.test/mid.cer')
    }

    It 'a certificate without the extensions gives empty lists' {
        $u = Get-PkiCertUrls $script:Root
        @($u.Cdp).Count | Should -Be 0
        @($u.Ocsp).Count | Should -Be 0
        @($u.CaIssuers).Count | Should -Be 0
    }

    It 'AKI of the leaf equals SKI of its issuer; a root without AKI gives $null' {
        Get-PkiAki $script:Leaf | Should -Be $script:MidSki
        Get-PkiSki $script:Mid | Should -Be $script:MidSki
        Get-PkiAki $script:Root | Should -BeNullOrEmpty
    }
}

Describe 'OCSP' {
    It 'the request carries SHA-1 hashes of the issuer name and key and the serial number' {
        $req = New-PkiOcspRequest -Cert $script:Leaf -Issuer $script:Mid
        $hex = ConvertTo-PkiHex $req
        $sha1 = [Security.Cryptography.SHA1]::Create()
        $hex | Should -Match '06052B0E03021A'
        $hex | Should -Match (ConvertTo-PkiHex $sha1.ComputeHash($script:Leaf.IssuerName.RawData))
        $hex | Should -Match (ConvertTo-PkiHex $sha1.ComputeHash($script:Mid.PublicKey.EncodedKeyValue.RawData))
        $hex | Should -Match ($script:Leaf.SerialNumber.TrimStart('0'))
    }

    It 'response <status> gives certStatus <status>' -ForEach @(@{ status = 'good' }, @{ status = 'revoked' }, @{ status = 'unknown' }) {
        $r = Read-PkiOcspResponse -Bytes (New-TestOcspResponse -SerialHex $script:Leaf.SerialNumber -Status $status) -SerialHex $script:Leaf.SerialNumber
        $r.ResponseStatus | Should -Be 0
        $r.CertStatus | Should -Be $status
    }

    It 'malformedRequest (30 03 0A 01 01) is not successful and has no certStatus' {
        $r = Read-PkiOcspResponse -Bytes ([byte[]](0x30, 0x03, 0x0A, 0x01, 0x01)) -SerialHex $script:Leaf.SerialNumber
        $r.ResponseStatus | Should -Be 1
        $r.CertStatus | Should -BeNullOrEmpty
    }

    It 'a response about another serial number has no certStatus for ours' {
        $r = Read-PkiOcspResponse -Bytes (New-TestOcspResponse -SerialHex '0A0B0C' -Status 'revoked') -SerialHex $script:Leaf.SerialNumber
        $r.ResponseStatus | Should -Be 0
        $r.CertStatus | Should -BeNullOrEmpty
    }

    It 'garbage throws for the caller to classify, never loops' {
        { Read-PkiOcspResponse -Bytes ([Text.Encoding]::ASCII.GetBytes('<html>')) -SerialHex '01' } | Should -Throw
    }
}

Describe 'TSP' {
    BeforeAll {
        $script:Tsa = New-TestCert -Subject 'CN=Сотрудник ТСП' -Issuer $script:Mid -PkupNotAfter ([datetime]::UtcNow.AddDays(100))
        $script:Imprint = [byte[]](1..32)
        $script:Nonce = [byte[]](0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x08)
    }

    It 'the request carries GOST R 34.11-2012 256 OID, the imprint, the nonce and certReq' {
        $hex = ConvertTo-PkiHex (New-PkiTspRequest -Imprint $script:Imprint -Nonce $script:Nonce)
        $hex | Should -Match ('06082A8503070101020204' + '20' + (ConvertTo-PkiHex $script:Imprint))
        $hex | Should -Match ('0208' + (ConvertTo-PkiHex $script:Nonce))
        $hex | Should -Match '0101FF$'
    }

    It 'granted with matching nonce and imprint: genTime and the signer key end (PKUP)' {
        $gen = [datetime]::UtcNow.AddSeconds(-3)
        $r = Read-PkiTspResponse -Bytes (New-TestTspResponse -Imprint $script:Imprint -Nonce $script:Nonce -GenTime $gen -Signer $script:Tsa) -Imprint $script:Imprint -Nonce $script:Nonce
        $r.Status | Should -Be 0
        $r.EchoOk | Should -BeTrue
        [Math]::Abs(($r.GenTime - $gen).TotalSeconds) | Should -BeLessThan 1.5
        [Math]::Abs(($r.KeyNotAfter - [datetime]::UtcNow.AddDays(100)).TotalDays) | Should -BeLessThan 1
    }

    It 'a GOST-signed token is read without CryptoPro, where SignedCms.Decode refuses it' {
        $gen = [datetime]::UtcNow.AddSeconds(-2)
        $bytes = New-TestTspResponse -Imprint $script:Imprint -Nonce $script:Nonce -GenTime $gen -Signer $script:Tsa -GostOids
        $token = Get-PkiTlvBytes $bytes (@(Get-PkiChildren $bytes (Read-PkiTlv $bytes 0))[1])
        { (New-Object Security.Cryptography.Pkcs.SignedCms).Decode($token) } | Should -Throw
        $r = Read-PkiTspResponse -Bytes $bytes -Imprint $script:Imprint -Nonce $script:Nonce
        $r.Status | Should -Be 0
        $r.EchoOk | Should -BeTrue
        [Math]::Abs(($r.GenTime - $gen).TotalSeconds) | Should -BeLessThan 1.5
        [Math]::Abs(($r.KeyNotAfter - [datetime]::UtcNow.AddDays(100)).TotalDays) | Should -BeLessThan 1
    }

    It 'rejection gives status 2 and no token' {
        $r = Read-PkiTspResponse -Bytes (New-TestTspResponse -Status 2) -Imprint $script:Imprint -Nonce $script:Nonce
        $r.Status | Should -Be 2
        $r.EchoOk | Should -BeFalse
    }

    It 'systemFailure in failInfo is told apart from a rejected request' {
        $failure = Read-PkiTspResponse -Bytes (New-TestTspResponse -Status 2 -SystemFailure) -Imprint $script:Imprint -Nonce $script:Nonce
        $failure.Status | Should -Be 2
        $failure.SystemFailure | Should -BeTrue
        $plain = Read-PkiTspResponse -Bytes (New-TestTspResponse -Status 2) -Imprint $script:Imprint -Nonce $script:Nonce
        $plain.SystemFailure | Should -BeFalse
    }

    It 'another nonce or imprint breaks the echo' {
        $bytes = New-TestTspResponse -Imprint $script:Imprint -Nonce ([byte[]](0x01, 0x02)) -Signer $script:Tsa
        (Read-PkiTspResponse -Bytes $bytes -Imprint $script:Imprint -Nonce $script:Nonce).EchoOk | Should -BeFalse
        $bytes = New-TestTspResponse -Imprint ([byte[]](2..33)) -Nonce $script:Nonce -Signer $script:Tsa
        (Read-PkiTspResponse -Bytes $bytes -Imprint $script:Imprint -Nonce $script:Nonce).EchoOk | Should -BeFalse
    }

    It 'a signer without PKUP gives KeyNotAfter $null' {
        $tsa = New-TestCert -Subject 'CN=No PKUP' -Issuer $script:Mid
        (Read-PkiTspResponse -Bytes (New-TestTspResponse -Imprint $script:Imprint -Nonce $script:Nonce -Signer $tsa) -Imprint $script:Imprint -Nonce $script:Nonce).KeyNotAfter | Should -BeNullOrEmpty
    }
}
