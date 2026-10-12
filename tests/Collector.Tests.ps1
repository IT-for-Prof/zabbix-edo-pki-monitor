# itforprof.com by Konstantin Tyutyunnik
# Whole pass of agent/edo-pki.ps1 against a test CA served on loopback, and the output contract.
# Run under Windows PowerShell 5.1 with Pester 6.2.0 (elevated: the cache directory gets an ACL):
#   powershell.exe -NoProfile -Command "Invoke-Pester -Path tests -CI"

BeforeAll {
    $script:CollectorPath = (Resolve-Path (Join-Path $PSScriptRoot '..\agent\edo-pki.ps1')).Path
    Import-Module (Join-Path $PSScriptRoot 'Helpers\Fixtures.psm1') -Force
    . $script:CollectorPath

    $script:Server = Start-FakeHttp -ImportFixtures -Data @{ Routes = @{} } -Handler {
        param($req, $data)
        $data['hits:' + $req.Path] = 1 + [int]$data['hits:' + $req.Path]
        if (-not $data.Routes.ContainsKey($req.Path)) { return @{ Status = 404 } }
        $route = $data.Routes[$req.Path]
        switch ($route.Kind) {
            'range' { return New-TestRangeResponse $route.Bytes $req -IgnoreRange:([bool]$route.IgnoreRange) }
            'raw' { return @{ Status = $route.Status; Body = $route.Bytes; Headers = $route.Headers } }
            'lying-size' { $resp = New-TestRangeResponse $route.Bytes $req; $resp.Headers['Content-Range'] = $resp.Headers['Content-Range'] -replace '/\d+$', '/999999'; return $resp }
            'ocsp' { return @{ Status = 200; Body = (New-TestOcspResponse -SerialHex $route.Serial -Status $route.CertStatus) } }
            'tsp' { return @{ Status = 200; Body = (New-TestTspEcho -Request $req.Body -Signer $route.Signer -Status $route.Status -SkewSeconds $route.Skew -BreakNonce:([bool]$route.BreakNonce) -SystemFailure:([bool]$route.SystemFailure)) } }
            'silent' { return @{ Silent = $true } }
            'head-range-only' { return New-TestRangeResponse $route.Bytes $req -IgnoreRange:([string]$req.Headers['range'] -like 'bytes=-*') }
        }
    }
    $script:Base = $script:Server.Url
    $script:Root = New-TestCert -Subject 'CN=Test Root CA' -Ca
    $script:Mid = New-TestCert -Subject 'CN=Test Issuing CA, O=Test' -Issuer $script:Root -Ca -Cdp "$($script:Base)/root.crl"
    $script:Leaf = New-TestCert -Subject 'CN=Иванов Иван Иванович, SERIALNUMBER=770000000000' -Issuer $script:Mid -Cdp "$($script:Base)/mid.crl" -Ocsp "$($script:Base)/ocsp" -CaIssuers "$($script:Base)/mid.cer"
    $script:Tsa = New-TestCert -Subject 'CN=Петров Пётр' -Issuer $script:Mid -PkupNotAfter ([datetime]::UtcNow.AddDays(100))
    $script:Other = New-TestCert -Subject 'CN=Other CA' -Ca
    $script:CrlMid = New-TestCrl -IssuerCert $script:Mid -PadEntries 2000
    $script:CrlRoot = New-TestCrl -IssuerCert $script:Root -NextUpdate ([datetime]::UtcNow.AddDays(29))

    function Set-DefaultRoutes {
        $script:Server.Data.Routes = @{
            '/root.crl' = @{ Kind = 'range'; Bytes = $script:CrlRoot }
            '/mid.crl' = @{ Kind = 'range'; Bytes = $script:CrlMid }
            '/mid.cer' = @{ Kind = 'raw'; Status = 200; Bytes = $script:Mid.RawData; Headers = @{} }
            '/ocsp' = @{ Kind = 'ocsp'; Serial = $script:Leaf.SerialNumber; CertStatus = 'good' }
            '/tsp1' = @{ Kind = 'tsp'; Signer = $script:Tsa; Status = 0; Skew = 0.5 }
            '/tsp2' = @{ Kind = 'tsp'; Signer = $script:Tsa; Status = 0; Skew = 30 }
        }
        foreach ($k in @($script:Server.Data.Keys | Where-Object { $_ -like 'hits:*' })) { $script:Server.Data.Remove($k) }
    }

    function Invoke-Pass {
        param([string]$Network = '1', [string]$Local = '1', [string]$CrlUrls = '', [string]$TspUrls = "$($script:Base)/tsp1,$($script:Base)/tsp2", [string]$Applicable = '1',
            [object[]]$LocalCrls = @($script:CrlMid, $script:CrlRoot), [object[]]$Certificates = @($script:Leaf), [string]$CacheDir = (Join-Path $TestDrive 'cache'), [int]$PassBudgetMs = 90000)
        $h = New-TestCrlStore $LocalCrls
        try {
            Invoke-PkiCollector -Argv @($Network, $Local, '', '0', $CrlUrls, $TspUrls, $Applicable) -Certificates $Certificates -ExtraStore @($script:Root, $script:Mid) -LocalStoreHandle $h -CacheDir $CacheDir -PassBudgetMs $PassBudgetMs
        } finally { Close-TestCrlStore $h }
    }

    function Get-Row($rows, $url) { @($rows | Where-Object { $_.url -eq $url })[0] }
}

AfterAll { Stop-FakeHttp $script:Server }

Describe 'Whole pass' {
    BeforeEach { Set-DefaultRoutes }

    It 'on a healthy test CA every object is OK and the output has the contract fields' {
        $r = Invoke-Pass
        @($r.Keys) | Should -Be $script:PkiContract.result
        $r.error | Should -Be ''
        $r.deadline | Should -Be 0
        $r.incomplete | Should -Be 0
        $r.sources_complete | Should -Be 1
        $r.ms | Should -BeGreaterThan 0
        @($r.crl).Count | Should -Be 2
        foreach ($row in $r.crl) { $row.state | Should -Be 0 -Because $row.url; @($row.Keys) | Should -Be $script:PkiContract.crl }
        (Get-Row $r.crl "$($script:Base)/mid.crl").hours_left | Should -BeGreaterThan 60
        (Get-Row $r.crl "$($script:Base)/mid.crl").ca | Should -Be 'Test Issuing CA'
        @($r.aia).Count | Should -Be 1
        $r.aia[0].state | Should -Be 0
        $r.ocsp[0].state | Should -Be 0
        @($r.certs[0].Keys) | Should -Be $script:PkiContract.certs
        $r.certs[0].status | Should -Be 0
        @($r.local).Count | Should -Be 2
        foreach ($row in $r.local) { $row.state | Should -Be 0; $row.reason | Should -Be 'VALID'; @($row.Keys) | Should -Be $script:PkiContract.local }
        @($r.tsp).Count | Should -Be 2
        foreach ($row in $r.tsp) { $row.state | Should -Be 0; $row.key_days | Should -BeIn 99, 100; @($row.Keys) | Should -Be $script:PkiContract.tsp }
        @($r.aia[0].Keys) | Should -Be $script:PkiContract.aia
        @($r.ocsp[0].Keys) | Should -Be $script:PkiContract.ocsp
        # Objects of the signature infrastructure: everything the host checks about signing, without the services.
        $r.objects | Should -Be (@($r.crl).Count + @($r.aia).Count + @($r.ocsp).Count + @($r.local).Count)
        $r.ca_certs | Should -Be ''
    }

    It 'objects count what was found, not what the network checked' {
        $r = Invoke-Pass -Network '0' -Local '0' -TspUrls ''
        $r.objects | Should -BeGreaterThan 0
    }

    It 'a host with nothing to check reports zero objects with a complete pass' {
        $r = Invoke-Pass -Certificates @() -TspUrls ''
        $r.objects | Should -Be 0
        $r.incomplete | Should -Be 0
        $r.error | Should -Be ''
        $r.diagnostic | Should -Be 'На хосте нет ни сертификатов, ни объявленных адресов. Что делать: объявить адреса в {$PKI.CRL.URLS} или отвязать шаблон'
    }

    It 'an explicitly non-applicable host has a bounded operator diagnosis' {
        $r = Invoke-Pass -Certificates @() -TspUrls '' -Applicable '0'
        $r.diagnostic | Should -Be 'Мониторинг подписи отключён макросом {$PKI.APPLICABLE}=0. Что делать: отвязать шаблон от хоста'
    }

    It 'A 200 HTML page at a CRL address gives 40' {
        $script:Server.Data.Routes['/mid.crl'] = @{ Kind = 'raw'; Status = 200; Bytes = [Text.Encoding]::ASCII.GetBytes('<html>Maintenance</html>'); Headers = @{} }
        $r = Invoke-Pass -TspUrls ''
        (Get-Row $r.crl "$($script:Base)/mid.crl").state | Should -Be 40
        # The host-level summary names the failing address before its sentence.
        $r.diagnostic | Should -BeLike "$($script:Base)/mid.crl — По адресу лежит не список отзыва. Что делать: *"
    }

    It 'a list of another issuer gives 42, of another key 43, a lying size 41, an expired list 44' {
        $script:Server.Data.Routes['/mid.crl'] = @{ Kind = 'range'; Bytes = (New-TestCrl -IssuerCert $script:Other -AkiHex (Get-PkiSki $script:Mid) -PadEntries 2000) }
        (Get-Row (Invoke-Pass -TspUrls '').crl "$($script:Base)/mid.crl").state | Should -Be 42
        $script:Server.Data.Routes['/mid.crl'] = @{ Kind = 'range'; Bytes = (New-TestCrl -IssuerCert $script:Mid -AkiHex (Get-PkiSki $script:Other) -PadEntries 2000) }
        (Get-Row (Invoke-Pass -TspUrls '').crl "$($script:Base)/mid.crl").state | Should -Be 43
        $script:Server.Data.Routes['/mid.crl'] = @{ Kind = 'lying-size'; Bytes = $script:CrlMid }
        (Get-Row (Invoke-Pass -TspUrls '').crl "$($script:Base)/mid.crl").state | Should -Be 41
        $script:Server.Data.Routes['/mid.crl'] = @{ Kind = 'range'; Bytes = (New-TestCrl -IssuerCert $script:Mid -ThisUpdate ([datetime]::UtcNow.AddDays(-5)) -NextUpdate ([datetime]::UtcNow.AddHours(-2))) }
        $row = Get-Row (Invoke-Pass -TspUrls '').crl "$($script:Base)/mid.crl"
        $row.state | Should -Be 44
        $row.hours_left | Should -BeLessThan 0
    }

    It 'A server ignoring Range gives 1 (content not checked), not a content failure' {
        $script:Server.Data.Routes['/mid.crl'] = @{ Kind = 'range'; Bytes = $script:CrlMid; IgnoreRange = $true }
        (Get-Row (Invoke-Pass -TspUrls '').crl "$($script:Base)/mid.crl").state | Should -Be 1
        $expired = New-TestCrl -IssuerCert $script:Mid -PadEntries 2000 -ThisUpdate ([datetime]::UtcNow.AddDays(-3)) -NextUpdate ([datetime]::UtcNow.AddHours(-1))
        $script:Server.Data.Routes['/mid.crl'] = @{ Kind = 'range'; Bytes = $expired; IgnoreRange = $true }
        (Get-Row (Invoke-Pass -TspUrls '').crl "$($script:Base)/mid.crl").state | Should -Be 44 -Because 'the head alone proves the list expired'
        $script:Server.Data.Routes['/mid.crl'] = @{ Kind = 'head-range-only'; Bytes = $script:CrlMid }
        $row = Get-Row (Invoke-Pass -TspUrls '').crl "$($script:Base)/mid.crl"
        $row.state | Should -Be 1 -Because 'a tail request answered from the start of the file has no AKI to compare, not another key'
        $script:Server.Data.Routes['/mid.crl'] = @{ Kind = 'head-range-only'; Bytes = $expired }
        (Get-Row (Invoke-Pass -TspUrls '').crl "$($script:Base)/mid.crl").state | Should -Be 44 -Because 'on the tail stage too the head proves the list expired'
    }

    It 'a cache directory that cannot be prepared leaves the network checks running and reports the gap' {
        $blocker = Join-Path $TestDrive ('blocker-' + [guid]::NewGuid().ToString('N'))
        [IO.File]::WriteAllText($blocker, 'x')
        $r = Invoke-Pass -CrlUrls "$($script:Base)/root.crl" -TspUrls '' -CacheDir (Join-Path $blocker 'cache')
        $r.error | Should -BeNullOrEmpty
        @($r.sources | Where-Object { $_.name -eq 'cache' -and $_.state -eq 1 }).Count | Should -Be 1
        $r.incomplete | Should -BeGreaterThan 0
        $r.diagnostic | Should -Be 'Кэш сертификатов контейнеров недоступен (источник cache). Что делать: проверить каталог кэша сборщика и права на него'
        (Get-Row $r.crl "$($script:Base)/mid.crl").state | Should -Be 0
    }

    It 'caIssuers: not a certificate 40, another subject 42, another key 43' {
        $script:Server.Data.Routes['/mid.cer'] = @{ Kind = 'raw'; Status = 200; Bytes = [byte[]](1, 2, 3); Headers = @{} }
        (Invoke-Pass -TspUrls '').aia[0].state | Should -Be 40
        $script:Server.Data.Routes['/mid.cer'] = @{ Kind = 'raw'; Status = 200; Bytes = $script:Other.RawData; Headers = @{} }
        (Invoke-Pass -TspUrls '').aia[0].state | Should -Be 42
        $sameName = New-TestCert -Subject 'CN=Test Issuing CA, O=Test' -Issuer $script:Root -Ca
        $script:Server.Data.Routes['/mid.cer'] = @{ Kind = 'raw'; Status = 200; Bytes = $sameName.RawData; Headers = @{} }
        (Invoke-Pass -TspUrls '').aia[0].state | Should -Be 43
    }

    It 'An OCSP responder answering 500 gives the address 30 and the certificate status -1' {
        $script:Server.Data.Routes['/ocsp'] = @{ Kind = 'raw'; Status = 500; Bytes = [byte[]]@(); Headers = @{} }
        $r = Invoke-Pass -TspUrls ''
        $r.ocsp[0].state | Should -Be 30
        $r.ocsp[0].http | Should -Be 500
        $r.certs[0].status | Should -Be -1
    }

    It 'Revoked gives status 1 and the output carries no subject of the leaf, the TSA or a container name' {
        $script:Server.Data.Routes['/ocsp'] = @{ Kind = 'ocsp'; Serial = $script:Leaf.SerialNumber; CertStatus = 'revoked' }
        $csp = Join-Path $TestDrive 'csp-revoked'
        $exe = New-FakeCsptest $csp
        Set-FakeContainer $csp '\\.\FAT12_A\Сидоров-2027' -Cert $script:Leaf
        $h = New-TestCrlStore @($script:CrlMid, $script:CrlRoot)
        try {
            $r = Invoke-PkiCollector -Argv @('1', '1', '', '1', '', "$($script:Base)/tsp1", '1') -ExtraStore @($script:Root, $script:Mid) -LocalStoreHandle $h -CacheDir (Join-Path $TestDrive 'cache-revoked') -CsptestPath $exe
        } finally { Close-TestCrlStore $h }
        $r.certs[0].status | Should -Be 1
        $json = ConvertTo-PkiOutput $r
        $plain = ($json | ConvertFrom-Json | ConvertTo-Json -Depth 6)
        foreach ($secret in 'Иванов', '770000000000', 'Петров', 'Сидоров', 'FAT12_A') { $plain | Should -Not -Match $secret }
    }

    It 'OCSP unknown gives status 2; no issuer in the chain gives -1 without a request' {
        $script:Server.Data.Routes['/ocsp'] = @{ Kind = 'ocsp'; Serial = $script:Leaf.SerialNumber; CertStatus = 'unknown' }
        (Invoke-Pass -TspUrls '').certs[0].status | Should -Be 2
        Set-DefaultRoutes
        $orphan = New-TestCert -Subject 'CN=Orphan' -Issuer $script:Other -Ocsp "$($script:Base)/ocsp"
        $h = New-TestCrlStore @()
        try { $r = Invoke-PkiCollector -Argv @('1', '0', '', '0', '', '', '1') -Certificates @($orphan) -ExtraStore @() -LocalStoreHandle $h -CacheDir (Join-Path $TestDrive 'cache') } finally { Close-TestCrlStore $h }
        $r.certs[0].status | Should -Be -1
        $r.incomplete | Should -Be 1 -Because 'a certificate whose status cannot be asked is a gap'
        [int]$script:Server.Data['hits:/ocsp'] | Should -Be 0
    }

    It 'an OCSP responder that fails on the network is asked once per pass, not once per certificate' {
        $silent = Start-FakeHttp -Handler { param($req, $data) @{ Silent = $true } }
        try {
            $a = New-TestCert -Subject 'CN=A' -Issuer $script:Mid -Ocsp "$($silent.Url)/ocsp"
            $b = New-TestCert -Subject 'CN=B' -Issuer $script:Mid -Ocsp "$($silent.Url)/ocsp"
            $h = New-TestCrlStore @()
            try { $r = Invoke-PkiCollector -Argv @('1', '0', '', '0', '', '', '1') -Certificates @($a, $b) -ExtraStore @($script:Root, $script:Mid) -LocalStoreHandle $h -CacheDir (Join-Path $TestDrive 'cache') } finally { Close-TestCrlStore $h }
        } finally { Stop-FakeHttp $silent }
        # The server is single-threaded and silent: a second request would wait in its backlog for its own 5 s.
        $r.ms | Should -BeLessThan 9000
        @($r.ocsp).Count | Should -Be 1
        $r.ocsp[0].state | Should -Be 20
        foreach ($c in $r.certs) { $c.status | Should -Be -1 }
    }

    It 'A time-stamping service that rejects gives 50, one that breaks the nonce 51, one that is silent 20' {
        $script:Server.Data.Routes['/tsp1'] = @{ Kind = 'tsp'; Signer = $script:Tsa; Status = 2; Skew = 0 }
        $script:Server.Data.Routes['/tsp2'] = @{ Kind = 'tsp'; Signer = $script:Tsa; Status = 0; Skew = 0; BreakNonce = $true }
        $script:Server.Data.Routes['/tsp3'] = @{ Kind = 'silent' }
        $r = Invoke-Pass -Local '0' -TspUrls "$($script:Base)/tsp1,$($script:Base)/tsp2,$($script:Base)/tsp3"
        (Get-Row $r.tsp "$($script:Base)/tsp1").state | Should -Be 50
        (Get-Row $r.tsp "$($script:Base)/tsp2").state | Should -Be 51
        (Get-Row $r.tsp "$($script:Base)/tsp3").state | Should -Be 20
        $r.Contains('clock_skew_s') | Should -BeFalse -Because 'no service granted a stamp'
    }

    It 'a time-stamping service that reports its own failure gives 52, not 50' {
        $script:Server.Data.Routes['/tsp1'] = @{ Kind = 'tsp'; Signer = $script:Tsa; Status = 2; Skew = 0; SystemFailure = $true }
        $r = Invoke-Pass -Local '0' -TspUrls "$($script:Base)/tsp1"
        $row = Get-Row $r.tsp "$($script:Base)/tsp1"
        $row.state | Should -Be 52
        $row.error | Should -Match 'systemFailure'
        $row.diagnostic | Should -Match '^Служба сообщила о своей внутренней ошибке .*Что делать: сбой на стороне УЦ'
    }

    It 'The host clock is the smallest skew among granted stamps: one wrong service does not decide' {
        # The loopback service signs slowly inside its runspace, so each skew carries a few seconds of noise;
        # 30 s against 0.5 s still tells which service is wrong.
        $r = Invoke-Pass
        $near = Get-Row $r.tsp "$($script:Base)/tsp1"
        $far = Get-Row $r.tsp "$($script:Base)/tsp2"
        $far.skew_s | Should -BeGreaterThan 20
        [Math]::Abs($near.skew_s) | Should -BeLessThan 10
        $r.clock_skew_s | Should -Be $near.skew_s
    }

    It 'An expired list of the old key next to the valid one of the current key is OK; missing 1; expired 2' {
        $oldKey = New-TestCrl -IssuerCert $script:Mid -AkiHex 'AABBCCDDEEFF00112233445566778899AABBCCDD' -ThisUpdate ([datetime]::UtcNow.AddDays(-60)) -NextUpdate ([datetime]::UtcNow.AddDays(-40))
        $r = Invoke-Pass -Network '0' -LocalCrls @($oldKey, $script:CrlMid, $script:CrlRoot)
        foreach ($row in $r.local) { $row.state | Should -Be 0 }
        $mid = @($r.local | Where-Object { $_.aki -eq (Get-PkiSki $script:Mid) })[0]
        $mid.pct_left | Should -BeGreaterThan 90
        $mid.pct_left | Should -BeLessOrEqual 100

        $r = Invoke-Pass -Network '0' -LocalCrls @($script:CrlRoot)
        @($r.local | Where-Object { $_.aki -eq (Get-PkiSki $script:Mid) })[0].state | Should -Be 1

        $expired = New-TestCrl -IssuerCert $script:Mid -ThisUpdate ([datetime]::UtcNow.AddDays(-3)) -NextUpdate ([datetime]::UtcNow.AddHours(-1))
        $r = Invoke-Pass -Network '0' -LocalCrls @($expired, $script:CrlRoot)
        $row = @($r.local | Where-Object { $_.aki -eq (Get-PkiSki $script:Mid) })[0]
        $row.state | Should -Be 2
        $row.hours_left | Should -BeLessThan 0
    }

    It 'Network off: no requests, network lists empty, local lists checked, a CA learned from the explicit list stays' {
        $cache = Join-Path $TestDrive 'cache-network-off'
        $extra = New-TestCert -Subject 'CN=Explicit CA' -Ca
        $script:Server.Data.Routes['/extra.crl'] = @{ Kind = 'range'; Bytes = (New-TestCrl -IssuerCert $extra) }
        $online = Invoke-Pass -CrlUrls "$($script:Base)/extra.crl" -TspUrls '' -CacheDir $cache
        (Get-Row $online.crl "$($script:Base)/extra.crl").state | Should -Be 0
        @($online.local | Where-Object { $_.aki -eq (Get-PkiSki $extra) }).Count | Should -Be 1 -Because 'R6: the issuer of a list from the explicit list'
        Set-DefaultRoutes
        $r = Invoke-Pass -Network '0' -CrlUrls "$($script:Base)/extra.crl" -CacheDir $cache
        @($r.crl).Count | Should -Be 0
        @($r.aia).Count | Should -Be 0
        @($r.ocsp).Count | Should -Be 0
        @($r.certs).Count | Should -Be 0
        @($r.tsp).Count | Should -Be 0
        @($script:Server.Data.Keys | Where-Object { $_ -like 'hits:*' }).Count | Should -Be 0
        @($r.local | Where-Object { $_.aki -eq (Get-PkiSki $extra) }).Count | Should -Be 1 -Because 'R22: known from the cache without network'
        @($r.local | Where-Object { $_.aki -eq (Get-PkiSki $extra) })[0].state | Should -Be 1
    }

    It 'local check off leaves the local list empty' {
        @((Invoke-Pass -Network '0' -Local '0').local).Count | Should -Be 0
    }

    It 'the pass deadline marks unchecked objects 90 and sets deadline' {
        $r = Invoke-Pass -PassBudgetMs 1
        $r.deadline | Should -Be 1
        foreach ($row in @($r.crl) + @($r.aia) + @($r.ocsp) + @($r.tsp)) { $row.state | Should -Be 90 }
        foreach ($list in 'crl', 'aia', 'ocsp', 'tsp') {
            @($r[$list]).Count | Should -BeGreaterThan 0
            (@($r[$list][0].Keys) -join ',') | Should -Be (@($script:PkiContract[$list] | Where-Object { $_ -notin 'skew_s', 'key_days' }) -join ',') -Because "$list rows follow the contract"
        }
        @($script:Server.Data.Keys | Where-Object { $_ -like 'hits:*' }).Count | Should -Be 0
    }

    It 'an invalid argument <name> is a collector error and nothing is checked' -ForEach @(
        @{ name = 'network 2'; argv = @('2', '1', 'My', '0', '', '', '1') }
        @{ name = 'a CRL address with ?'; argv = @('1', '1', 'My', '0', 'http://cdp.test/a.crl?x', '', '1') }
        @{ name = 'a store with ;'; argv = @('1', '1', 'My;CA', '0', '', '', '1') }
        @{ name = 'too few arguments'; argv = @('1', '1') }
    ) {
        $r = Invoke-PkiCollector -Argv $argv -CacheDir (Join-Path $TestDrive 'cache')
        $r.error | Should -Match 'argument'
        $r.Contains('crl') | Should -BeFalse
    }
}

Describe 'Output contract' {
    It 'does not persist exception paths and rejects overlong endpoints' {
        Get-PkiErrorText ([IO.FileNotFoundException]::new('missing C:\Users\Alice\secret.pfx')) | Should -Be 'IO_ERROR'
        Test-PkiUrl ('http://a.example/' + ('x' * 500) + '.crl') | Should -BeFalse
    }

    It 'ASCII only: Cyrillic CA names are escaped' {
        $json = ConvertTo-PkiOutput ([ordered]@{ v = 1; ver = '1.0.0'; ms = 1; deadline = 0; error = ''; incomplete = 0; sources = @(); crl = @([ordered]@{ url = 'http://x/a.crl'; ca = 'ООО "Сертум-Про"'; state = 0; http = 206; ms = 5; hours_left = 1.5; error = '' }); aia = @(); ocsp = @(); certs = @(); local = @(); tsp = @() })
        $json | Should -Not -Match '[^\x20-\x7E]'
        ($json | ConvertFrom-Json).crl[0].ca | Should -Be 'ООО "Сертум-Про"'
        ($json | ConvertFrom-Json).crl[0].hours_left | Should -Be 1.5
    }

    It 'a single row stays a JSON array' {
        $json = ConvertTo-PkiOutput ([ordered]@{ v = 1; ver = '1.0.0'; ms = 1; deadline = 0; error = ''; incomplete = 0; sources = @(); crl = @([ordered]@{ url = 'u' }); aia = @(); ocsp = @(); certs = @(); local = @(); tsp = @() })
        $json | Should -Match '"crl":\[\{'
        $json | Should -Match '"aia":\[\]'
    }

    It 'over-budget output keeps reason/action and degrades optional evidence before list tails' {
        $rows = foreach ($i in 1..400) { [ordered]@{ url = "http://cdp$i.example.test/very/long/path/to/some/revocation/list/number/$i.crl"; ca = 'Test CA'; state = 40; http = 200; ms = 10; hours_left = -1; error = 'bounded parser detail'; reason = 'CDP_HTTP_FAIL'; action = 'CHECK_ENDPOINT' } }
        $result = [ordered]@{ v = 1; ver = '1.0.0'; ms = 1; deadline = 0; error = ''; incomplete = 0; sources_complete = 1; objects = 400; ca_certs = ''; diagnostic = ''; sources = @(); crl = @($rows); aia = @(); ocsp = @(); certs = @(); local = @(); tsp = @() }
        $json = ConvertTo-PkiOutput $result
        $json.Length | Should -BeLessThan 55000
        $o = $json | ConvertFrom-Json
        $o.error | Should -BeNullOrEmpty
        $o.diagnostic | Should -Match 'вывод сокращён'
        $o.diagnostic.Length | Should -BeLessOrEqual 255 -Because 'edo.pki.diagnostic is CHAR'
        $o.crl.Count | Should -BeLessThan 400
        $o.crl[0].state | Should -Be 40
        $o.crl[0].reason | Should -Be 'CDP_HTTP_FAIL'
        $o.crl[0].action | Should -Be 'CHECK_ENDPOINT'
        Get-PkiDiagnosticLength $result | Should -BeLessOrEqual 16384
    }

    It 'output that cannot be degraded under the limit is still one ASCII object with a Russian diagnostic' {
        # Dropping list rows cannot help when a scalar alone is over the limit (Cyrillic costs six characters).
        $json = ConvertTo-PkiOutput ([ordered]@{ v = 1; ver = '1.0.0'; ms = 1; deadline = 0; error = ''; incomplete = 0; ca_certs = ('ы' * 10000); sources = @(); crl = @(); aia = @(); ocsp = @(); certs = @(); local = @(); tsp = @(); diagnostic = '' })
        $json | Should -Not -Match '[^\x20-\x7E]'
        ($json | ConvertFrom-Json).diagnostic | Should -Match '^Вывод сборщика не уложился'
    }

    It 'the last-resort JSON literal parses and reports an error' {
        $o = $script:PkiFallbackJson | ConvertFrom-Json
        $o.v | Should -Be 1
        $o.error | Should -Not -BeNullOrEmpty
    }
}

Describe 'Process contract (as agent2 runs it)' {
    It 'prints one ASCII JSON object, exit 0, empty stderr for <name>' -ForEach @(
        @{ name = 'everything off'; argv = @('0', '0', '', '0', '', '', '1'); error = $false }
        @{ name = 'an invalid argument'; argv = @('yes', '1', 'My', '0', '', '', '1'); error = $true }
        @{ name = 'six arguments (agent2 drops an empty last one)'; argv = @('0', '0', '', '0', '', ''); error = $false }
    ) {
        $p = Invoke-CollectorProcess -ScriptPath $script:CollectorPath -ArgumentList $argv
        $p.ExitCode | Should -Be 0
        $p.StdErr | Should -BeNullOrEmpty
        $p.StdOut | Should -Match '^\{.*\}$'
        $p.StdOut | Should -Not -Match '[^\x20-\x7E]'
        $o = $p.StdOut | ConvertFrom-Json
        $o.v | Should -Be 1
        [bool]$o.error | Should -Be $error
    }
}

Describe 'Manual mode' {
    BeforeAll {
        $script:SavedOid = $script:PkiSigningKeyOid
        # The test CA is RSA; manual mode judges only signing keys, so the test widens the rule.
        $script:PkiSigningKeyOid = '*'
        $script:ChainOk = { param($c) @{ Label = 'OK'; Text = 'CryptoAPI: цепочка доверена, отзыв проверен'; Flags = '' } }
        $script:RealCollect = {
            param($Argv, $UserStores, $CacheDir)
            $h = New-TestCrlStore @($script:CrlMid, $script:CrlRoot)
            try {
                Invoke-PkiCollector -Argv @('1', '1', '', '0', '', $script:Tsp, '1') -Certificates @($script:Leaf) -ExtraStore @($script:Root, $script:Mid) -LocalStoreHandle $h -CacheDir (Join-Path $TestDrive 'manual-cache') -IncludeSubjects
            } finally { Close-TestCrlStore $h }
        }
        function Invoke-Manual([object[]]$ArgList, [scriptblock]$Collect = $script:RealCollect, [scriptblock]$Chain = $script:ChainOk) {
            $lines = New-Object Collections.Generic.List[string]
            $code = Invoke-PkiInteractive -ArgList $ArgList -Collect $Collect -Chain $Chain -Sink { param($text) $lines.Add($text) }.GetNewClosure()
            [pscustomobject]@{ Code = $code; Text = ($lines -join "`n") }
        }
    }
    AfterAll { $script:PkiSigningKeyOid = $script:SavedOid }
    BeforeEach { Set-DefaultRoutes; $script:Tsp = "$($script:Base)/tsp1" }

    Context 'switches' {
        It 'console-shaped and -File-shaped values parse alike' {
            $a = ConvertFrom-PkiSwitches @('-Scope', 'user', '-Stores', @('My', 'AddressBook'), '-Tsp:', 'http://t.test/a,http://t.test/b', '-NoLocal')
            $b = ConvertFrom-PkiSwitches @('-scope:User', '-Stores', 'My,AddressBook', '-Tsp', 'http://t.test/a,http://t.test/b', '-NoLocal')
            foreach ($o in $a, $b) {
                $o.Error | Should -BeNullOrEmpty
                $o.Scope | Should -Be 'User'
                $o.Stores -join ',' | Should -Be 'My,AddressBook'
                $o.Tsp -join ',' | Should -Be 'http://t.test/a,http://t.test/b'
                $o.NoLocal | Should -BeTrue
            }
        }

        It 'rejects <case> before any collector call' -ForEach @(
            @{ case = 'an unknown switch'; argv = @('-Bogus') }
            @{ case = 'a bad scope'; argv = @('-Scope', 'Everything') }
            @{ case = 'an https TSP'; argv = @('-Tsp', 'https://t.test/a') }
            @{ case = 'a bad store name'; argv = @('-Stores', 'My;Root') }
            @{ case = 'a value for a flag'; argv = @('-NoLocal:yes') }
        ) {
            $r = Invoke-Manual $argv { throw 'must not collect' }
            $r.Code | Should -Be 2
            $r.Text | Should -Match 'Ошибка'
        }

        It '<sw> prints usage, exit 0' -ForEach @(@{ sw = '-Help' }, @{ sw = '-?' }) {
            $r = Invoke-Manual @($sw) { throw 'must not collect' }
            $r.Code | Should -Be 0
            $r.Text | Should -Match '-Scope'
        }

        It 'scope <scope> passes stores <stores>, containers <containers>, user stores <user>' -ForEach @(
            @{ scope = 'All'; stores = 'My'; containers = '1'; user = 'My' }
            @{ scope = 'Machine'; stores = 'My'; containers = '0'; user = '' }
            @{ scope = 'User'; stores = ''; containers = '1'; user = 'My' }
        ) {
            $script:Seen = $null
            [void](Invoke-Manual @('-Scope', $scope) { param($Argv, $UserStores, $CacheDir) $script:Seen = @{ Argv = $Argv; User = $UserStores; Cache = $CacheDir }; [ordered]@{ v = 1; ms = 1; error = '' } })
            $script:Seen.Argv[2] | Should -Be $stores
            $script:Seen.Argv[3] | Should -Be $containers
            (@($script:Seen.User) -join ',') | Should -Be $user
            $script:Seen.Argv.Count | Should -Be 7
            $script:Seen.Cache | Should -Match 'edo-pki-monitor$'
        }

        It 'restores the cache owner, trusted SIDs and age after the run' {
            $before = @($script:PkiCacheOwner, ($script:PkiCacheSids -join ','), $script:PkiCacheMaxAgeHours) -join '|'
            [void](Invoke-Manual @('-Scope', 'User') { param($a) [ordered]@{ v = 1; ms = 1; error = '' } })
            (@($script:PkiCacheOwner, ($script:PkiCacheSids -join ','), $script:PkiCacheMaxAgeHours) -join '|') | Should -Be $before
        }
    }

    Context 'report from a real pass against the test CA' {
        It 'a healthy pass has no FAIL, exit 0' {
            $r = Invoke-Manual @()
            $r.Code | Should -Be 0
            $r.Text | Should -Match 'Иванов Иван Иванович'
            $r.Text | Should -Match 'OCSP: действителен'
            $r.Text | Should -Match 'Списки отзыва \(CRL\) по сети'
            $r.Text | Should -Match 'Часы компьютера: расхождение'
            $r.Text | Should -Not -Match 'FAIL'
        }

        It 'a revoked certificate is FAIL, named first in the summary, exit 1' {
            $script:Server.Data.Routes['/ocsp'] = @{ Kind = 'ocsp'; Serial = $script:Leaf.SerialNumber; CertStatus = 'revoked' }
            $r = Invoke-Manual @()
            $r.Code | Should -Be 1
            $r.Text | Should -Match 'FAIL Иванов Иван Иванович'
            $r.Text | Should -Match 'OCSP: отозван'
            $r.Text | Should -Match 'Главное: Иванов Иван Иванович'
        }

        It 'a CryptoAPI chain failure fails the certificate even when OCSP says good' {
            $r = Invoke-Manual @() -Chain { param($c) @{ Label = 'FAIL'; Text = 'CryptoAPI: цепочка не доверена'; Flags = 'UntrustedRoot' } }
            $r.Code | Should -Be 1
            $r.Text | Should -Match 'FAIL Иванов.*'
            $r.Text | Should -Match 'цепочка не доверена'
        }

        It 'a CRL address answering 404 is FAIL with its diagnostic sentence' {
            $script:Server.Data.Routes.Remove('/mid.crl')
            $r = Invoke-Manual @()
            $r.Code | Should -Be 1
            $r.Text | Should -Match 'FAIL http://127\.0\.0\.1:\d+/mid\.crl'
            $r.Text | Should -Match 'Что делать'
        }

        It 'a time-stamping key under the template threshold is a warning' {
            $tsa = New-TestCert -Subject 'CN=Short TSA' -Issuer $script:Mid -PkupNotAfter ([datetime]::UtcNow.AddDays(10))
            $script:Server.Data.Routes['/tsp3'] = @{ Kind = 'tsp'; Signer = $tsa; Status = 0; Skew = 0.1 }
            $script:Tsp = "$($script:Base)/tsp3"
            $r = Invoke-Manual @()
            $r.Text | Should -Match 'WARN http://127\.0\.0\.1:\d+/tsp3.*ключ службы ещё \d+ дн'
        }

        It '-Out writes the screen text and JSON with the rendered certificate rows, relative to the PowerShell location' {
            Push-Location $TestDrive
            try { [void](Invoke-Manual @('-Out', 'pki-rel.txt')) } finally { Pop-Location }
            $json = Get-Content -LiteralPath (Join-Path $TestDrive 'pki-rel.json') -Raw | ConvertFrom-Json
            @($json.subjects).Count | Should -Be 1
            $json.subjects[0].ocsp_status | Should -Be 0
            $json.subjects[0].chain | Should -Be 'OK'
            $json.interrupted | Should -BeFalse
            Get-Content -LiteralPath (Join-Path $TestDrive 'pki-rel.txt') -Raw | Should -Match 'Итог'
        }
    }

    Context 'labels and interruption on prepared results' {
        It 'a failing address the template mutes is INFO, not FAIL' {
            $collect = {
                $row = [ordered]@{ url = 'http://c0000-app005/cdp/x.crl'; ca = 'ФНС'; state = 10; http = -1; ms = 5; hours_left = -1; error = 'x'; reason = 'CDP_DNS_FAIL'; action = 'FIX_DNS'; diagnostic = 'Имя не найдено' }
                [ordered]@{ v = 1; ms = 10; error = ''; crl = @($row) }
            }
            $r = Invoke-Manual @() $collect
            $r.Code | Should -Be 0
            $r.Text | Should -Match 'INFO http://c0000-app005'
            $r.Text | Should -Match 'Тревога по этому адресу отключена'
        }

        It 'states map to labels: 0 OK, 1 and 90 WARN, 10..89 FAIL' {
            Get-PkiStateLabel 0 | Should -Be 'OK'
            Get-PkiStateLabel 1 | Should -Be 'WARN'
            Get-PkiStateLabel 90 | Should -Be 'WARN'
            Get-PkiStateLabel 23 | Should -Be 'FAIL'
            Get-PkiStateLabel 52 | Should -Be 'FAIL'
        }

        It 'an exception after partial results prints them, says interrupted, writes -Out, exit 1' {
            $out = Join-Path $TestDrive 'partial'
            $collect = {
                $script:PkiCurrentResult = [ordered]@{ v = 1; ms = 10; error = ''; tsp = New-Object Collections.ArrayList }
                [void]$script:PkiCurrentResult.tsp.Add([ordered]@{ url = 'http://tsp.test/a'; state = 0; http = 200; ms = 50; skew_s = 0.2; key_days = 200; error = ''; reason = 'VALID'; action = 'NONE'; diagnostic = '' })
                throw 'boom'
            }
            $r = Invoke-Manual @('-Out', $out) $collect
            $r.Code | Should -Be 1
            $r.Text | Should -Match 'OK   http://tsp.test/a'
            $r.Text | Should -Match 'Проход прерван ошибкой: boom'
            (Get-Content -LiteralPath "$out.json" -Raw | ConvertFrom-Json).interrupted | Should -BeTrue
        }

        It 'a stopped pipeline (Ctrl+C) still prints the partial rows' {
            $lines = [Collections.ArrayList]::Synchronized((New-Object Collections.ArrayList))
            $ps = [powershell]::Create()
            [void]$ps.AddScript({
                param($path, $lines)
                . $path
                $collect = {
                    $script:PkiCurrentResult = [ordered]@{ v = 1; ms = 10; error = ''; tsp = New-Object Collections.ArrayList }
                    [void]$script:PkiCurrentResult.tsp.Add([ordered]@{ url = 'http://tsp.test/a'; state = 0; http = 200; ms = 50; skew_s = 0.2; key_days = 200; error = ''; reason = 'VALID'; action = 'NONE'; diagnostic = '' })
                    Start-Sleep 30
                }
                Invoke-PkiInteractive -ArgList @() -Collect $collect -Sink { param($x) [void]$lines.Add($x) }.GetNewClosure()
            }).AddArgument($script:CollectorPath).AddArgument($lines)
            [void]$ps.BeginInvoke()
            $deadline = [DateTime]::Now.AddSeconds(20)
            while (-not ($lines -match 'Проход идёт') -and [DateTime]::Now -lt $deadline) { Start-Sleep -Milliseconds 100 }
            Start-Sleep -Milliseconds 500
            $ps.Stop(); $ps.Dispose()
            ($lines -join "`n") | Should -Match 'Проход прерван\.'
            ($lines -join "`n") | Should -Match 'http://tsp.test/a'
        }
    }

    Context 'collector seams' {
        It '-IncludeSubjects lists each certificate once; without it the result has no subjects key' {
            $h = New-TestCrlStore @($script:CrlMid, $script:CrlRoot)
            try {
                $with = Invoke-PkiCollector -Argv @('0', '0', '', '0', '', '', '1') -Certificates @($script:Leaf, $script:Leaf) -ExtraStore @($script:Root, $script:Mid) -LocalStoreHandle $h -CacheDir (Join-Path $TestDrive 'seam-cache') -IncludeSubjects
                $without = Invoke-PkiCollector -Argv @('0', '0', '', '0', '', '', '1') -Certificates @($script:Leaf) -ExtraStore @($script:Root, $script:Mid) -LocalStoreHandle $h -CacheDir (Join-Path $TestDrive 'seam-cache')
            } finally { Close-TestCrlStore $h }
            @($with.subjects).Count | Should -Be 1
            $with.subjects[0].thumbprint | Should -Be $script:Leaf.Thumbprint
            $with.subjects[0].subject | Should -Be 'Иванов Иван Иванович'
            $without.Contains('subjects') | Should -BeFalse
        }

        It 'the collector publishes its result object while it runs' {
            $script:PkiCurrentResult = $null
            $h = New-TestCrlStore @()
            try { $r = Invoke-PkiCollector -Argv @('0', '0', '', '0', '', '', '1') -LocalStoreHandle $h -CacheDir (Join-Path $TestDrive 'seam-cache2') } finally { Close-TestCrlStore $h }
            [object]::ReferenceEquals($script:PkiCurrentResult, $r) | Should -BeTrue
        }

        It 'Get-PkiChainVerdict reports an untrusted test root as a chain failure' {
            $v = Get-PkiChainVerdict $script:Leaf
            $v.Label | Should -Be 'FAIL'
            $v.Text | Should -Match 'цепочка не доверена'
        }
    }

    Context 'as a process' {
        It '<case> exits <code>' -ForEach @(
            @{ case = '-Help'; argv = @('-Help'); code = 0 }
            @{ case = 'an unknown switch'; argv = @('-Bogus'); code = 2 }
            @{ case = 'an https TSP'; argv = @('-Tsp', 'https://t.test/a'); code = 2 }
        ) {
            (Invoke-CollectorProcess -ScriptPath $script:CollectorPath -ArgumentList $argv).ExitCode | Should -Be $code
        }
    }
}

Describe 'Manual mode after review' {
    BeforeAll {
        $script:SavedOid2 = $script:PkiSigningKeyOid
        $script:PkiSigningKeyOid = '*'
        function Invoke-Manual2([object[]]$ArgList, [scriptblock]$Collect, [scriptblock]$Chain = { param($c, $off) @{ Label = 'OK'; Text = 'CryptoAPI: ok'; Flags = '' } }) {
            $lines = New-Object Collections.Generic.List[string]
            $code = Invoke-PkiInteractive -ArgList $ArgList -Collect $Collect -Chain $Chain -Sink { param($text) $lines.Add($text) }.GetNewClosure()
            [pscustomobject]@{ Code = $code; Text = ($lines -join "`n") }
        }
        function New-Subject([datetime]$NotAfter, [bool]$InStore, [bool]$HasKey, [string]$Source = 'CONTAINER') {
            [ordered]@{ thumbprint = $script:Leaf.Thumbprint; id = (Get-PkiCertId $script:Leaf); subject = 'Иванов'; issuer = 'Test CA'; not_after = $NotAfter
                source = $Source; in_store = $InStore; has_private_key = $HasKey; cert = $script:Leaf }
        }
    }
    AfterAll { $script:PkiSigningKeyOid = $script:SavedOid2 }

    It 'switches select manual mode only when not SYSTEM; no arguments always do' {
        Test-PkiManualCall @() $true | Should -BeTrue
        Test-PkiManualCall @('-Out://host/s/x', '-NoLocal') $false | Should -BeTrue
        Test-PkiManualCall @('-Out://host/s/x', '-NoLocal') $true | Should -BeFalse
        Test-PkiManualCall @('-1', '1', 'My', '1', '', '', '1') $false | Should -BeFalse
        Test-PkiManualCall @('1', '1', 'My', '1', '', '', '1') $false | Should -BeFalse
    }

    It '-Out refuses a UNC or device path: <path>' -ForEach @(@{ path = '\\host\share\x' }, @{ path = '//host/share/x' }, @{ path = '\\?\C:\x' }) {
        (ConvertFrom-PkiSwitches @('-Out', $path)).Error | Should -Match '-Out'
    }

    It 'a collector error is never reported as healthy: exit 1' {
        $r = Invoke-Manual2 @() { [ordered]@{ v = 1; ms = 1; error = 'invalid argument 3'; incomplete = 0 } }
        $r.Code | Should -Be 1
        $r.Text | Should -Match 'Ошибка сборщика'
        $r.Text | Should -Not -Match 'проблем не найдено'
    }

    It 'an incomplete pass is a warning, not healthy' {
        $r = Invoke-Manual2 @() { [ordered]@{ v = 1; ms = 1; error = ''; incomplete = 2; deadline = 0; diagnostic = 'перечисление контейнеров не уложилось во время' } }
        $r.Text | Should -Match 'WARN Проход неполный'
        $r.Text | Should -Match 'перечисление контейнеров'
        $r.Text | Should -Not -Match 'проблем не найдено'
    }

    It 'no GOST certificate is a warning that becomes the main finding' {
        $saved = $script:PkiSigningKeyOid
        try {
            $script:PkiSigningKeyOid = '1.2.643.*'
            $r = Invoke-Manual2 @() { [ordered]@{ v = 1; ms = 1; error = ''; incomplete = 0; subjects = @((New-Subject (Get-Date).AddDays(100) $true $true 'USER_STORE')) } }
        } finally { $script:PkiSigningKeyOid = $saved }
        $r.Text | Should -Match 'WARN Сертификатов ГОСТ для подписи в ЭДО не найдено'
        $r.Text | Should -Match 'Главное: Сертификатов ГОСТ'
        $r.Text | Should -Match 'прочие сертификаты'
    }

    It '<case>' -ForEach @(
        @{ case = 'a store copy without a key link warns even when a container holds the certificate'; inStore = $true; hasKey = $false; expect = 'WARN Иванов.*'; note = 'в хранилище нет связи с закрытым ключом' }
        @{ case = 'a container-only certificate is noted as not installed, label stays OK'; inStore = $false; hasKey = $false; expect = 'OK   Иванов'; note = 'в личное хранилище не установлен' }
        @{ case = 'a linked store copy is OK'; inStore = $true; hasKey = $true; expect = 'OK   Иванов'; note = 'CryptoAPI: ok' }
    ) {
        $sub = New-Subject (Get-Date).AddDays(200) $inStore $hasKey
        $r = Invoke-Manual2 @() { [ordered]@{ v = 1; ms = 1; error = ''; incomplete = 0; subjects = @($sub) } }.GetNewClosure()
        $r.Text | Should -Match $expect
        $r.Text | Should -Match $note
    }

    It 'an expired certificate gets an offline chain check and FAIL' {
        $script:OfflineSeen = $null
        $sub = New-Subject (Get-Date).AddDays(-3) $true $true
        $r = Invoke-Manual2 @() { [ordered]@{ v = 1; ms = 1; error = ''; incomplete = 0; subjects = @($sub) } }.GetNewClosure() { param($c, $off) $script:OfflineSeen = $off; @{ Label = 'FAIL'; Text = 'CryptoAPI: срок истёк'; Flags = 'NotTimeValid' } }
        $script:OfflineSeen | Should -BeTrue
        $r.Code | Should -Be 1
        $r.Text | Should -Match 'FAIL Иванов'
    }

    It 'a TSP row without a stamp shows no empty key or skew and only its state label' {
        $row = [ordered]@{ url = 'http://tsp.test/a'; state = 20; http = -1; ms = 5000; error = 'нет ответа'; reason = 'CDP_NETWORK_FAIL'; action = 'CHECK_NETWORK'; diagnostic = 'Узел не отвечает' }
        $r = Invoke-Manual2 @() { [ordered]@{ v = 1; ms = 1; error = ''; incomplete = 0; tsp = @($row) } }.GetNewClosure()
        $r.Text | Should -Match 'FAIL http://tsp.test/a \| 5000 мс'
        $r.Text | Should -Not -Match 'ключ службы ещё  дн'
        $r.Text | Should -Not -Match 'расхождение часов  с'
    }
}
