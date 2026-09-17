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
            'tsp' { return @{ Status = 200; Body = (New-TestTspEcho -Request $req.Body -Signer $route.Signer -Status $route.Status -SkewSeconds $route.Skew -BreakNonce:([bool]$route.BreakNonce)) } }
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
        param([string]$Network = '1', [string]$Local = '1', [string]$CrlUrls = '', [string]$TspUrls = "$($script:Base)/tsp1,$($script:Base)/tsp2",
            [object[]]$LocalCrls = @($script:CrlMid, $script:CrlRoot), [object[]]$Certificates = @($script:Leaf), [string]$CacheDir = (Join-Path $TestDrive 'cache'), [int]$PassBudgetMs = 90000)
        $h = New-TestCrlStore $LocalCrls
        try {
            Invoke-PkiCollector -Argv @($Network, $Local, '', '0', $CrlUrls, $TspUrls) -Certificates $Certificates -ExtraStore @($script:Root, $script:Mid) -LocalStoreHandle $h -CacheDir $CacheDir -PassBudgetMs $PassBudgetMs
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
        foreach ($row in $r.local) { $row.state | Should -Be 0; @($row.Keys) | Should -Be $script:PkiContract.local }
        @($r.tsp).Count | Should -Be 2
        foreach ($row in $r.tsp) { $row.state | Should -Be 0; $row.key_days | Should -BeIn 99, 100; @($row.Keys) | Should -Be $script:PkiContract.tsp }
        @($r.aia[0].Keys) | Should -Be $script:PkiContract.aia
        @($r.ocsp[0].Keys) | Should -Be $script:PkiContract.ocsp
    }

    It 'A 200 HTML page at a CRL address gives 40' {
        $script:Server.Data.Routes['/mid.crl'] = @{ Kind = 'raw'; Status = 200; Bytes = [Text.Encoding]::ASCII.GetBytes('<html>Maintenance</html>'); Headers = @{} }
        (Get-Row (Invoke-Pass -TspUrls '').crl "$($script:Base)/mid.crl").state | Should -Be 40
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
            $r = Invoke-PkiCollector -Argv @('1', '1', '', '1', '', "$($script:Base)/tsp1") -ExtraStore @($script:Root, $script:Mid) -LocalStoreHandle $h -CacheDir (Join-Path $TestDrive 'cache-revoked') -CsptestPath $exe
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
        try { $r = Invoke-PkiCollector -Argv @('1', '0', '', '0', '', '') -Certificates @($orphan) -ExtraStore @() -LocalStoreHandle $h -CacheDir (Join-Path $TestDrive 'cache') } finally { Close-TestCrlStore $h }
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
            try { $r = Invoke-PkiCollector -Argv @('1', '0', '', '0', '', '') -Certificates @($a, $b) -ExtraStore @($script:Root, $script:Mid) -LocalStoreHandle $h -CacheDir (Join-Path $TestDrive 'cache') } finally { Close-TestCrlStore $h }
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
        @{ name = 'network 2'; argv = @('2', '1', 'My', '0', '', '') }
        @{ name = 'a CRL address with ?'; argv = @('1', '1', 'My', '0', 'http://cdp.test/a.crl?x', '') }
        @{ name = 'a store with ;'; argv = @('1', '1', 'My;CA', '0', '', '') }
        @{ name = 'too few arguments'; argv = @('1', '1') }
    ) {
        $r = Invoke-PkiCollector -Argv $argv -CacheDir (Join-Path $TestDrive 'cache')
        $r.error | Should -Match 'argument'
        $r.Contains('crl') | Should -BeFalse
    }
}

Describe 'Output contract' {
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

    It 'output over 60 000 characters becomes a collector error without lists' {
        $rows = foreach ($i in 1..400) { [ordered]@{ url = "http://cdp$i.example.test/very/long/path/to/some/revocation/list/number/$i.crl"; ca = 'Test CA'; state = 0; http = 206; ms = 10; hours_left = 60.5; error = '' } }
        $json = ConvertTo-PkiOutput ([ordered]@{ v = 1; ver = '1.0.0'; ms = 1; deadline = 0; error = ''; incomplete = 0; sources = @(); crl = @($rows); aia = @(); ocsp = @(); certs = @(); local = @(); tsp = @() })
        $json.Length | Should -BeLessThan 60000
        $o = $json | ConvertFrom-Json
        $o.error | Should -Match 'too large'
        $o.PSObject.Properties.Name | Should -Not -Contain 'crl'
    }

    It 'the last-resort JSON literal parses and reports an error' {
        $o = $script:PkiFallbackJson | ConvertFrom-Json
        $o.v | Should -Be 1
        $o.error | Should -Not -BeNullOrEmpty
    }
}

Describe 'Process contract (as agent2 runs it)' {
    It 'prints one ASCII JSON object, exit 0, empty stderr for <name>' -ForEach @(
        @{ name = 'everything off'; argv = @('0', '0', '', '0', '', ''); error = $false }
        @{ name = 'an invalid argument'; argv = @('yes', '1', 'My', '0', '', ''); error = $true }
        @{ name = 'an argument that looks like a parameter'; argv = @('-Verbose', '1', 'My', '0', '', ''); error = $true }
        @{ name = 'no arguments'; argv = @(); error = $true }
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
