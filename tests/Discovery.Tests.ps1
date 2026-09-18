# itforprof.com by Konstantin Tyutyunnik
# Discovery of agent/edo-pki.ps1: stores, CryptoPro containers with the cache, chains, addresses, CA set.
# Run under Windows PowerShell 5.1 with Pester 6.2.0 (elevated: the cache ACL tests set owners):
#   powershell.exe -NoProfile -Command "Invoke-Pester -Path tests -CI"

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'Helpers\Fixtures.psm1') -Force
    . (Join-Path $PSScriptRoot '..\agent\edo-pki.ps1')
    $script:Root = New-TestCert -Subject 'CN=Test Root CA' -Ca
    $script:Mid = New-TestCert -Subject 'CN=Test Issuing CA' -Issuer $script:Root -Ca -Cdp 'http://cdp.test/root.crl'
    $script:MidSki = Get-PkiSki $script:Mid
    $script:RootSki = Get-PkiSki $script:Root
    $script:Leaf = New-TestCert -Subject 'CN=Иванов Иван' -Issuer $script:Mid -Cdp 'http://cdp.test/mid.crl', 'ldap:///CN=Mid' -Ocsp 'http://ocsp.test/ocsp.srf' -CaIssuers 'http://aia.test/mid.cer'
    $script:Extra = @($script:Root, $script:Mid)

    function New-CacheDir { $d = Join-Path $TestDrive ('cache-' + [guid]::NewGuid().ToString('N')); $d }
}

Describe 'Addresses, expected values and the CA set' {
    # Discovery stops building chains past its share of the pass: every test starts its own pass.
    BeforeEach { Start-PkiPass }

    It 'Expired and not-yet-valid leaves give no addresses, no OCSP and no CA' {
        $expired = New-TestCert -Subject 'CN=Old' -Issuer $script:Mid -Cdp 'http://cdp.test/old.crl' -Ocsp 'http://ocsp.test/ocsp.srf' -NotBefore ([DateTimeOffset]::UtcNow.AddDays(-400)) -NotAfter ([DateTimeOffset]::UtcNow.AddDays(-1))
        $future = New-TestCert -Subject 'CN=Future' -Issuer $script:Mid -Cdp 'http://cdp.test/future.crl' -NotBefore ([DateTimeOffset]::UtcNow.AddDays(2))
        $d = Get-PkiDiscovery -Certificates @($expired, $future) -ExtraStore $script:Extra
        @($d.Crl.Keys).Count | Should -Be 0
        @($d.Ocsp).Count | Should -Be 0
        @($d.Cas.Keys).Count | Should -Be 0
    }

    It 'collects CDP of every link with the issuer and AKI of that link; the self-signed root is not a CA to check' {
        $d = Get-PkiDiscovery -Certificates @($script:Leaf) -ExtraStore $script:Extra
        @($d.Crl.Keys | Sort-Object) | Should -Be @('http://cdp.test/mid.crl', 'http://cdp.test/root.crl')
        $d.Crl['http://cdp.test/mid.crl'].Expected[0].Issuer | Should -Be $script:Mid.Subject
        $d.Crl['http://cdp.test/mid.crl'].Expected[0].Aki | Should -Be $script:MidSki
        $d.Crl['http://cdp.test/root.crl'].Expected[0].Aki | Should -Be $script:RootSki
        $d.Crl['http://cdp.test/mid.crl'].Ca | Should -Be 'Test Issuing CA'
        @($d.Aia.Keys) | Should -Be @('http://aia.test/mid.cer')
        @($d.Cas.Keys | Sort-Object) | Should -Be (@($script:MidSki, $script:RootSki) | Sort-Object)
        $d.Incomplete | Should -Be 0
    }

    It 'OCSP goes by certificate with its issuer from the chain; without the issuer the status is not checked' {
        $d = Get-PkiDiscovery -Certificates @($script:Leaf) -ExtraStore $script:Extra
        @($d.Ocsp).Count | Should -Be 1
        $d.Ocsp[0].Url | Should -Be 'http://ocsp.test/ocsp.srf'
        $d.Ocsp[0].Issuer.Thumbprint | Should -Be $script:Mid.Thumbprint
        $d.Ocsp[0].Id | Should -Match '^[0-9A-F]{8}$'
        $d.Ocsp[0].Ca | Should -Be 'Test Issuing CA'
        $orphan = New-TestCert -Subject 'CN=Orphan' -Issuer $script:Mid -Ocsp 'http://ocsp.test/ocsp.srf'
        $d = Get-PkiDiscovery -Certificates @($orphan) -ExtraStore @()
        @($d.Ocsp).Count | Should -Be 1
        $d.Ocsp[0].Issuer | Should -BeNullOrEmpty
    }

    It 'one CDP address announced by certificates of two CA keys keeps both AKI' {
        $mid2 = New-TestCert -Subject 'CN=Test Issuing CA' -Issuer $script:Root -Ca -Cdp 'http://cdp.test/root.crl'
        $a = New-TestCert -Subject 'CN=A' -Issuer $script:Mid -Cdp 'http://cdp.test/same.crl'
        $b = New-TestCert -Subject 'CN=B' -Issuer $mid2 -Cdp 'http://cdp.test/same.crl'
        $d = Get-PkiDiscovery -Certificates @($a, $b) -ExtraStore @($script:Root, $script:Mid, $mid2)
        @($d.Crl['http://cdp.test/same.crl'].Expected | ForEach-Object { $_.Aki } | Sort-Object) | Should -Be (@($script:MidSki, (Get-PkiSki $mid2)) | Sort-Object)
    }

    It 'a self-signed root publishing its own CDP gives the address but is not a CA to check' {
        $root = New-TestCert -Subject 'CN=Root With CDP' -Ca -Cdp 'http://cdp.test/self.crl'
        $d = Get-PkiDiscovery -Certificates @($root)
        $d.Crl.Keys | Should -Contain 'http://cdp.test/self.crl'
        @($d.Cas.Keys).Count | Should -Be 0
    }

    It 'a link without AKI is a CA keyed by issuer name, and its local list is matched by that name' {
        $noAki = New-TestCert -Subject 'CN=No AKI' -Issuer $script:Mid -NoAki -Cdp 'http://cdp.test/mid.crl'
        $d = Get-PkiDiscovery -Certificates @($noAki) -ExtraStore $script:Extra
        $d.Cas.Keys | Should -Contain 'name:CN=Test Issuing CA'
        $now = [datetime]::UtcNow
        $other = @{ Issuer = 'CN=Other'; Aki = $null; ThisUpdate = $now.AddDays(-1); NextUpdate = $now.AddDays(1) }
        $same = @{ Issuer = 'CN=Test Issuing CA'; Aki = 'AB'; ThisUpdate = $now.AddDays(-1); NextUpdate = $now.AddDays(1) }
        $row = @(Get-PkiLocalCheck -Cas $d.Cas -Crls @($other, $same) -Now $now | Where-Object { $_.aki -eq 'name:CN=Test Issuing CA' })[0]
        $row.state | Should -Be 0
        @(Get-PkiLocalCheck -Cas $d.Cas -Crls @($other) -Now $now | Where-Object { $_.aki -eq 'name:CN=Test Issuing CA' })[0].state | Should -Be 1
    }

    It 'past the discovery share of the pass no more chains are built: each skipped certificate is a gap' {
        $saved = $script:PkiBudget.DiscoveryMs
        $script:PkiBudget.DiscoveryMs = 0
        try { Start-PkiPass; $d = Get-PkiDiscovery -Certificates @($script:Leaf) -ExtraStore $script:Extra } finally { $script:PkiBudget.DiscoveryMs = $saved; Start-PkiPass }
        $d.Incomplete | Should -Be 1
        @($d.Crl.Keys).Count | Should -Be 0
    }

    It 'the chain share is counted from the start of chain building, not from the pass start (slow containers do not empty the lists)' {
        $saved = $script:PkiBudget.DiscoveryMs
        $script:PkiBudget.DiscoveryMs = 1000
        try { Start-PkiPass; Start-Sleep -Milliseconds 1200; $d = Get-PkiDiscovery -Certificates @($script:Leaf) -ExtraStore $script:Extra } finally { $script:PkiBudget.DiscoveryMs = $saved; Start-PkiPass }
        $d.Incomplete | Should -Be 0
        $d.Crl.Keys | Should -Contain 'http://cdp.test/mid.crl'
    }

    It 'a certificate with a malformed CDP is a gap in discovery, not a failed pass' {
        # Every length fits its parent, the URI runs past the end of the extension: Get-PkiValue refuses to read it.
        $bad = New-TestCert -Subject 'CN=Bad' -Issuer $script:Mid -CdpRaw ([byte[]](0x30, 0x7F, 0x30, 0x7D, 0xA0, 0x7B, 0xA0, 0x79, 0x86, 0x77, 0x68))
        $d = Get-PkiDiscovery -Certificates @($bad, $script:Leaf) -ExtraStore $script:Extra
        $d.Incomplete | Should -BeGreaterThan 0
        $d.Crl.Keys | Should -Contain 'http://cdp.test/mid.crl'
    }

    It 'a link with only ldap CDP does not put its issuer into the CA set (internal CA case)' {
        $internal = New-TestCert -Subject 'CN=host.corp.example' -Issuer $script:Mid -Cdp 'ldap:///CN=corp-CA-1,CN=CDP'
        $d = Get-PkiDiscovery -Certificates @($internal) -ExtraStore $script:Extra
        $d.Cas.Keys | Should -Not -Contain $script:MidSki
        $d.Cas.Keys | Should -Contain $script:RootSki -Because 'the issuing CA link itself has an http CDP'
    }

    It 'a CDP address with <name> is refused: not checked, not printed, discovery incomplete' -ForEach @(
        @{ name = 'a quote'; url = "http://cdp.test/a'b.crl" }
        @{ name = 'a double quote'; url = 'http://cdp.test/a"b.crl' }
        @{ name = 'a bracket'; url = 'http://cdp.test/a[b].crl' }
        @{ name = 'a query'; url = 'http://cdp.test/a.crl?x=1' }
        @{ name = 'a percent'; url = 'http://cdp.test/%COMPUTERNAME%.crl' }
    ) {
        $bad = New-TestCert -Subject 'CN=Bad' -Issuer $script:Mid -Cdp $url
        $d = Get-PkiDiscovery -Certificates @($bad) -ExtraStore $script:Extra
        $d.Crl.Keys | Should -Not -Contain $url
        $d.Incomplete | Should -Be 1
    }

    It 'with stores and containers off, an explicit list gives addresses without expected values and no incompleteness' {
        $d = Get-PkiDiscovery -Certificates @() -ExplicitCrlUrls @('http://cdp.test/extra.crl')
        @($d.Crl.Keys) | Should -Be @('http://cdp.test/extra.crl')
        $d.Crl['http://cdp.test/extra.crl'].Explicit | Should -BeTrue
        $d.Crl['http://cdp.test/extra.crl'].Ca | Should -Be 'cdp.test' -Because 'a problem name without a CA reads with a gap'
        @($d.Crl['http://cdp.test/extra.crl'].Expected).Count | Should -Be 0
        $d.Incomplete | Should -Be 0
    }

    It 'address check: <url> is <ok>' -ForEach @(
        @{ url = 'http://c0000-app005/cdp/23f0da4a5de30c96e91f976a3e641689a1f8553c.crl'; ok = $true }
        @{ url = 'http://pki3.sertum-pro.ru/tspq/tspservice'; ok = $true }
        @{ url = 'http://cdp.test:8080/x_y-z.crl'; ok = $true }
        @{ url = 'https://cdp.test/x.crl'; ok = $false }
        @{ url = 'http://cdp.test/x y.crl'; ok = $false }
        @{ url = "http://cdp.test/x.crl`n"; ok = $false }
        @{ url = 'http://cdp.test/a~b'; ok = $false }
    ) {
        Test-PkiUrl $url | Should -Be $ok
    }
}

Describe 'Machine stores' {
    It 'a CA certificate is the one whose basicConstraints says so; without the extension it is an end-entity one' {
        $ca = New-TestCert -Subject 'CN=Test CA' -Ca
        $leaf = New-TestCert -Subject 'CN=Test leaf' -Issuer $ca
        $noExt = New-TestCert -Subject 'CN=Test leaf without basicConstraints' -Issuer $ca -NoBasicConstraints
        (Test-PkiCaCertificate $ca) | Should -BeTrue
        (Test-PkiCaCertificate $leaf) | Should -BeFalse
        (Test-PkiCaCertificate $noExt) | Should -BeFalse
    }

    It 'opens LocalMachine My read-only; a missing store is a failed source' {
        $r = Get-PkiStoreCertificates -Stores @('My', 'NoSuchStoreForEdoPkiTests')
        @($r.Sources | Where-Object { $_.name -eq 'store:My' })[0].state | Should -Be 0
        @($r.Sources | Where-Object { $_.name -eq 'store:NoSuchStoreForEdoPkiTests' })[0].state | Should -Be 1
        $r.Incomplete | Should -Be 1
    }
}

Describe 'CryptoPro containers' {
    BeforeEach {
        $script:Csp = Join-Path $TestDrive ('csp-' + [guid]::NewGuid().ToString('N'))
        $script:Exe = New-FakeCsptest $script:Csp
        $script:Cache = New-CacheDir
    }

    It 'a container holding keys alone is not an unread object' {
        Set-FakeContainer $script:Csp '\\.\FAT12_A\keys-only' -Behavior 'nocert'
        $r = Get-PkiContainerCertificates -CsptestPath $script:Exe -CacheDir $script:Cache
        @($r.Certs).Count | Should -Be 0
        $r.Incomplete | Should -Be 0
        $r.Source.state | Should -Be 0
    }

    It 'a container that lost its certificate stops serving the cached one' {
        $name = '\\.\FAT12_A\emptied'
        Set-FakeContainer $script:Csp $name -Cert $script:Leaf
        @((Get-PkiContainerCertificates -CsptestPath $script:Exe -CacheDir $script:Cache).Certs).Count | Should -Be 1
        Set-FakeContainer $script:Csp $name -Behavior 'nocert'
        $cache = Get-PkiCache $script:Cache
        foreach ($k in @($cache.containers.Keys)) { $cache.containers[$k].extracted_utc = [datetime]::UtcNow.AddDays(-2).ToString('o') }
        Save-PkiCache $script:Cache $cache
        $r = Get-PkiContainerCertificates -CsptestPath $script:Exe -CacheDir $script:Cache
        @($r.Certs).Count | Should -Be 0
        $r.Incomplete | Should -Be 0
    }

    It 'no keyset of either type is not a key-only container' {
        Set-FakeContainer $script:Csp '\\.\FAT12_A\no-keys' -Behavior 'nokeys'
        $r = Get-PkiContainerCertificates -CsptestPath $script:Exe -CacheDir $script:Cache
        $r.Incomplete | Should -Be 1
    }

    It 'a container that could not be read stays a gap' {
        Set-FakeContainer $script:Csp '\\.\FAT12_A\broken' -Behavior 'fail'
        $r = Get-PkiContainerCertificates -CsptestPath $script:Exe -CacheDir $script:Cache
        @($r.Certs).Count | Should -Be 0
        $r.Incomplete | Should -Be 1
    }

    It 'reads names in cp866 and extracts the certificate by the full name' {
        $name = '\\.\FAT12_A\Иванов2027 (12.03.2027)'
        Set-FakeContainer $script:Csp $name -Cert $script:Leaf
        $r = Get-PkiContainerCertificates -CsptestPath $script:Exe -CacheDir $script:Cache
        @($r.Certs).Count | Should -Be 1
        $r.Certs[0].Thumbprint | Should -Be $script:Leaf.Thumbprint
        $r.Incomplete | Should -Be 0
        $r.Source.state | Should -Be 0
        $export = @(Get-FakeCsptestLaunches $script:Csp | Where-Object { $_ -contains '-expcert' })
        $export.Count | Should -Be 1
        $export[0][[Array]::IndexOf($export[0], '-container') + 1] | Should -Be $name
    }

    It 'a name with <name> after the reader is refused without launching csptest' -ForEach @(
        @{ name = 'a backslash'; container = '\\.\FAT12_A\dir\name' }
        @{ name = 'a control character'; container = "\\.\FAT12_A\na$([char]7)me" }
    ) {
        Set-FakeContainer $script:Csp $container -Cert $script:Leaf
        $r = Get-PkiContainerCertificates -CsptestPath $script:Exe -CacheDir $script:Cache
        @($r.Certs).Count | Should -Be 0
        $r.Incomplete | Should -Be 1
        @(Get-FakeCsptestLaunches $script:Csp | Where-Object { $_ -contains '-expcert' }).Count | Should -Be 0
    }

    It 'a hostile name <name> reaches csptest as exactly one -container argument' -ForEach @(
        @{ name = 'starting with a quote'; container = '\\.\FAT12_A\"quoted' }
        @{ name = 'injecting -expcert'; container = '\\.\FAT12_A\x" -expcert C:x' }
        @{ name = 'ending with a quote'; container = '\\.\FAT12_A\trail"' }
        @{ name = 'quote and spaces'; container = '\\.\FAT12_A\ООО "Ромашка" 2026' }
    ) {
        Set-FakeContainer $script:Csp $container -Cert $script:Leaf
        $r = Get-PkiContainerCertificates -CsptestPath $script:Exe -CacheDir $script:Cache
        $export = @(Get-FakeCsptestLaunches $script:Csp | Where-Object { $_ -contains '-expcert' })
        $export.Count | Should -Be 1
        $argv = $export[0]
        @($argv | Where-Object { $_ -eq '-expcert' }).Count | Should -Be 1
        $argv[[Array]::IndexOf($argv, '-container') + 1] | Should -Be $container
        @($r.Certs).Count | Should -Be 1
    }

    It 'A hanging extraction is killed at its limit; the cached certificate is used and discovery is incomplete' {
        $name = '\\.\FAT12_A\hangs'
        Set-FakeContainer $script:Csp $name -Cert $script:Leaf
        $first = Get-PkiContainerCertificates -CsptestPath $script:Exe -CacheDir $script:Cache
        @($first.Certs).Count | Should -Be 1
        Set-FakeContainer $script:Csp $name -Behavior hang
        $cache = Get-PkiCache $script:Cache
        foreach ($k in @($cache.containers.Keys)) { $cache.containers[$k].extracted_utc = [datetime]::UtcNow.AddDays(-2).ToString('o') }
        Save-PkiCache $script:Cache $cache
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $r = Get-PkiContainerCertificates -CsptestPath $script:Exe -CacheDir $script:Cache -CsptestMs 1500
        $sw.ElapsedMilliseconds | Should -BeLessThan 8000
        $r.Incomplete | Should -Be 1
        @($r.Certs).Count | Should -Be 1
        $r.Certs[0].Thumbprint | Should -Be $script:Leaf.Thumbprint
    }

    It 'after the first hanging extraction the rest of the pass uses only the cache' {
        Set-FakeContainer $script:Csp '\\.\FAT12_A\h1' -Behavior hang
        Set-FakeContainer $script:Csp '\\.\FAT12_A\h2' -Behavior hang
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $r = Get-PkiContainerCertificates -CsptestPath $script:Exe -CacheDir $script:Cache -CsptestMs 1500
        $sw.ElapsedMilliseconds | Should -BeLessThan 8000
        @(Get-FakeCsptestLaunches $script:Csp | Where-Object { $_ -contains '-expcert' }).Count | Should -Be 1
        $r.Incomplete | Should -Be 2
    }

    It 'the cache is reused, refreshed on a new name, on age over a day and on expiry after extraction, not in a loop' {
        Set-FakeContainer $script:Csp '\\.\FAT12_A\one' -Cert $script:Leaf
        [void](Get-PkiContainerCertificates -CsptestPath $script:Exe -CacheDir $script:Cache)
        $count = { @(Get-FakeCsptestLaunches $script:Csp | Where-Object { $_ -contains '-expcert' }).Count }
        & $count | Should -Be 1
        [void](Get-PkiContainerCertificates -CsptestPath $script:Exe -CacheDir $script:Cache)
        & $count | Should -Be 1 -Because 'same set, fresh entry'

        Set-FakeContainer $script:Csp '\\.\FAT12_A\two' -Cert $script:Mid
        [void](Get-PkiContainerCertificates -CsptestPath $script:Exe -CacheDir $script:Cache)
        & $count | Should -Be 2 -Because 'only the new name is extracted'

        $cache = Get-PkiCache $script:Cache
        foreach ($k in @($cache.containers.Keys)) { $cache.containers[$k].extracted_utc = [datetime]::UtcNow.AddHours(-25).ToString('o') }
        Save-PkiCache $script:Cache $cache
        [void](Get-PkiContainerCertificates -CsptestPath $script:Exe -CacheDir $script:Cache)
        & $count | Should -Be 4 -Because 'entries older than a day are refreshed'

        # A certificate that expired after it was cached is extracted again; the same expired one again is not.
        $old = New-TestCert -Subject 'CN=Expiring' -Issuer $script:Mid -NotBefore ([DateTimeOffset]::UtcNow.AddDays(-30)) -NotAfter ([DateTimeOffset]::UtcNow.AddMinutes(-5))
        Set-FakeContainer $script:Csp '\\.\FAT12_A\three' -Cert $old
        [void](Get-PkiContainerCertificates -CsptestPath $script:Exe -CacheDir $script:Cache)
        & $count | Should -Be 5
        $cache = Get-PkiCache $script:Cache
        foreach ($k in @($cache.containers.Keys)) { if ([datetime]::Parse($cache.containers[$k].not_after).ToUniversalTime() -lt [datetime]::UtcNow) { $cache.containers[$k].extracted_utc = [datetime]::UtcNow.AddDays(-20).ToString('o') } }
        Save-PkiCache $script:Cache $cache
        [void](Get-PkiContainerCertificates -CsptestPath $script:Exe -CacheDir $script:Cache)
        & $count | Should -Be 6 -Because 'it expired after the entry was extracted'
        [void](Get-PkiContainerCertificates -CsptestPath $script:Exe -CacheDir $script:Cache)
        & $count | Should -Be 6 -Because 'the container gives the same expired certificate again'
    }

    It 'entries of containers that are gone are dropped from the cache' {
        Set-FakeContainer $script:Csp '\\.\FAT12_A\stays' -Cert $script:Leaf
        Set-FakeContainer $script:Csp '\\.\FAT12_A\goes' -Cert $script:Mid
        [void](Get-PkiContainerCertificates -CsptestPath $script:Exe -CacheDir $script:Cache)
        @((Get-PkiCache $script:Cache).containers.Keys).Count | Should -Be 2
        Remove-FakeContainer $script:Csp '\\.\FAT12_A\goes'
        [void](Get-PkiContainerCertificates -CsptestPath $script:Exe -CacheDir $script:Cache)
        @((Get-PkiCache $script:Cache).containers.Keys).Count | Should -Be 1
        [IO.File]::ReadAllText((Join-Path $script:Cache 'cache.json')) | Should -Not -Match 'stays|goes' -Because 'container names are personal data'
    }

    It 'a failed listing (non-zero exit, no names) keeps every cached certificate and marks the source failed' {
        Set-FakeContainer $script:Csp '\\.\FAT12_A\one' -Cert $script:Leaf
        [void](Get-PkiContainerCertificates -CsptestPath $script:Exe -CacheDir $script:Cache)
        Remove-FakeContainer $script:Csp '\\.\FAT12_A\one'
        [IO.File]::WriteAllText((Join-Path $script:Csp 'enum-exit.txt'), '1')
        $r = Get-PkiContainerCertificates -CsptestPath $script:Exe -CacheDir $script:Cache
        $r.Source.state | Should -Be 1
        $r.Incomplete | Should -Be 1
        @($r.Certs).Count | Should -Be 1
        @((Get-PkiCache $script:Cache).containers.Keys).Count | Should -Be 1
    }

    It 'a listing that exits 0 but whose output was not read in time keeps the cache' {
        Set-FakeContainer $script:Csp '\\.\FAT12_A\one' -Cert $script:Leaf
        [void](Get-PkiContainerCertificates -CsptestPath $script:Exe -CacheDir $script:Cache)
        Mock Invoke-PkiProcess { @{ TimedOut = $false; ExitCode = 0; Stdout = ''; StdoutComplete = $false } } -ParameterFilter { $Arguments -like '*-enum_cont*' }
        $r = Get-PkiContainerCertificates -CsptestPath $script:Exe -CacheDir $script:Cache
        $r.Source.state | Should -Be 1
        @($r.Certs).Count | Should -Be 1
        @((Get-PkiCache $script:Cache).containers.Keys).Count | Should -Be 1
    }

    It 'a cache directory that cannot be prepared makes the container source failed, not the pass' {
        $blocker = Join-Path $TestDrive ('blocker-' + [guid]::NewGuid().ToString('N'))
        [IO.File]::WriteAllText($blocker, 'x')
        $r = Get-PkiContainerCertificates -CsptestPath $script:Exe -CacheDir (Join-Path $blocker 'cache')
        $r.Source.state | Should -Be 1
        $r.Incomplete | Should -Be 1
    }

    It 'no csptest while containers are on is a failed source' {
        $r = Get-PkiContainerCertificates -CsptestPath (Join-Path $TestDrive 'absent\csptest.exe') -CacheDir $script:Cache
        $r.Source.state | Should -Be 1
        $r.Incomplete | Should -Be 1
        @($r.Certs).Count | Should -Be 0
    }
}

Describe 'Cache directory access' {
    It 'is created with inheritance off and access only for SYSTEM and Administrators' {
        $d = New-CacheDir
        Initialize-PkiCacheDir $d | Should -BeFalse -Because 'nothing had to be reset'
        $acl = Get-Acl -LiteralPath $d
        $acl.AreAccessRulesProtected | Should -BeTrue
        $sids = @($acl.Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
        $sids | Should -Be @('S-1-5-18', 'S-1-5-32-544')
        @('S-1-5-18', 'S-1-5-32-544') | Should -Contain (New-Object Security.Principal.NTAccount $acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value
    }

    It 'a junction planted at the path is set aside: its target keeps its files and access' {
        $victim = Join-Path $TestDrive ('victim-' + [guid]::NewGuid().ToString('N'))
        [void](New-Item -ItemType Directory -Path $victim)
        [IO.File]::WriteAllText((Join-Path $victim 'keep.txt'), 'x')
        $before = (Get-Acl -LiteralPath $victim).Sddl
        $d = New-CacheDir
        cmd.exe /c mklink /J "$d" "$victim" | Out-Null
        ([IO.File]::GetAttributes($d) -band [IO.FileAttributes]::ReparsePoint) | Should -BeTrue -Because 'the test needs a real junction'
        Initialize-PkiCacheDir $d | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $victim 'keep.txt') | Should -BeTrue
        (Get-Acl -LiteralPath $victim).Sddl | Should -Be $before
        Test-PkiCacheDirTrusted $d | Should -BeTrue
        @([IO.Directory]::GetFileSystemEntries($d)).Count | Should -Be 0
        $aside = @([IO.Directory]::GetDirectories($TestDrive, ([IO.Path]::GetFileName($d) + '.untrusted-*')))
        $aside.Count | Should -Be 1
        ([IO.File]::GetAttributes($aside[0]) -band [IO.FileAttributes]::ReparsePoint) | Should -BeTrue -Because 'the junction itself was renamed'
    }

    It 'a file planted at the path is set aside and a protected directory is created' {
        $d = New-CacheDir
        [IO.File]::WriteAllText($d, 'planted')
        Initialize-PkiCacheDir $d | Should -BeTrue
        Test-PkiCacheDirTrusted $d | Should -BeTrue
        $aside = @([IO.Directory]::GetFiles($TestDrive, ([IO.Path]::GetFileName($d) + '.untrusted-*')))
        $aside.Count | Should -Be 1
        [IO.File]::ReadAllText($aside[0]) | Should -Be 'planted'
    }

    It 'a directory planted with extra access is set aside and its content is not trusted' {
        $d = New-CacheDir
        [void](New-Item -ItemType Directory -Path $d)
        [IO.File]::WriteAllText((Join-Path $d 'cache.json'), '{"v":1,"containers":{"AA":{"extracted_utc":"2099-01-01T00:00:00Z","not_after":"2099-01-01T00:00:00Z","cert":"AAAA"}},"crl_issuers":{}}')
        $acl = Get-Acl -LiteralPath $d
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule (New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-545'), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
        Set-Acl -LiteralPath $d -AclObject $acl
        Initialize-PkiCacheDir $d | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $d 'cache.json') | Should -BeFalse
        $sids = @((Get-Acl -LiteralPath $d).Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
        $sids | Should -Be @('S-1-5-18', 'S-1-5-32-544')
    }
}
