# itforprof.com by Konstantin Tyutyunnik
# HTTP of agent/edo-pki.ps1 on loopback servers: redirects, partial content, budget, failure classes.
# Run under Windows PowerShell 5.1 with Pester 6.2.0:
#   powershell.exe -NoProfile -Command "Invoke-Pester -Path tests -CI"

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'Helpers\Fixtures.psm1') -Force
    . (Join-Path $PSScriptRoot '..\agent\edo-pki.ps1')
    $script:Body = [byte[]]::new(40000); for ($i = 0; $i -lt $script:Body.Length; $i++) { $script:Body[$i] = [byte]($i % 251) }
}

Describe 'Redirects and partial content' {
    It 'Two 307 (the second with a relative Location), then 206: state 0 and the final address' {
        $s = Start-FakeHttp -Data @{ Body = $script:Body } -Handler {
            param($req, $data)
            switch -Regex ($req.Path) {
                '^/cdp/list\.crl$' { if (-not $data.ContainsKey('Hop')) { $data.Hop = 1; return @{ Status = 307; Headers = @{ Location = '/DDoS01/token/cdp/list.crl' } } } ; return New-TestRangeResponse $data.Body $req }
                '^/DDoS01/' { return @{ Status = 307; Headers = @{ Location = '../../../cdp/list.crl' } } }
                default { return @{ Status = 404 } }
            }
        }
        try { $r = Invoke-PkiHttp -Url "$($s.Url)/cdp/list.crl" -RangeFrom 0 -RangeTo 16383 } finally { Stop-FakeHttp $s }
        $r.State | Should -Be 0
        $r.Http | Should -Be 206
        $r.Total | Should -Be 40000
        $r.Bytes.Length | Should -Be 16384
        $r.FinalUrl | Should -Be "$($s.Url)/cdp/list.crl"
        $s.Data.Requests | Should -Be 3
    }

    It 'a tail request gets the last bytes' {
        $s = Start-FakeHttp -Data @{ Body = $script:Body } -Handler { param($req, $data) New-TestRangeResponse $data.Body $req }
        try { $r = Invoke-PkiHttp -Url "$($s.Url)/x.crl" -Tail 4096 } finally { Stop-FakeHttp $s }
        $r.State | Should -Be 0
        $r.Bytes.Length | Should -Be 4096
        $r.Bytes[4095] | Should -Be $script:Body[39999]
    }

    It 'six redirects in a row give 30' {
        $s = Start-FakeHttp -Handler { param($req, $data) @{ Status = 302; Headers = @{ Location = '/again' } } }
        try { $r = Invoke-PkiHttp -Url "$($s.Url)/start" } finally { Stop-FakeHttp $s }
        $r.State | Should -Be 30
        $s.Data.Requests | Should -Be 6
    }

    It 'a redirect to <name> gives 30 without another connection' -ForEach @(
        @{ name = 'file://'; location = 'file://127.0.0.1/c$/windows/win.ini' }
        @{ name = 'UNC'; location = '\\127.0.0.1\c$\windows\win.ini' }
        @{ name = 'ldap://'; location = 'ldap://127.0.0.1/CN=x' }
        @{ name = 'https://'; location = 'https://127.0.0.1/x.crl' }
    ) {
        $s = Start-FakeHttp -Data @{ Location = $location } -Handler { param($req, $data) @{ Status = 307; Headers = @{ Location = $data.Location } } }
        try { $r = Invoke-PkiHttp -Url "$($s.Url)/x.crl" } finally { Stop-FakeHttp $s }
        $r.State | Should -Be 30
        $r.Error | Should -Match 'redirect'
        $s.Data.Requests | Should -Be 1
    }

    It 'A server ignoring Range with a large 200 is flagged More, reads no more than asked' {
        $s = Start-FakeHttp -Data @{ Body = $script:Body } -Handler { param($req, $data) New-TestRangeResponse $data.Body $req -IgnoreRange }
        try { $r = Invoke-PkiHttp -Url "$($s.Url)/x.crl" -RangeFrom 0 -RangeTo 16383 } finally { Stop-FakeHttp $s }
        $r.State | Should -Be 0
        $r.Http | Should -Be 200
        $r.More | Should -BeTrue
        $r.Bytes.Length | Should -Be 16384
    }

    It 'a small 200 body is complete: More is false' {
        $s = Start-FakeHttp -Handler { param($req, $data) @{ Status = 200; Body = [byte[]](1, 2, 3) } }
        try { $r = Invoke-PkiHttp -Url "$($s.Url)/x.cer" -MaxBytes 262144 } finally { Stop-FakeHttp $s }
        $r.More | Should -BeFalse
        $r.Bytes.Length | Should -Be 3
    }

    It 'POST sends the body and content type' {
        $s = Start-FakeHttp -Handler { param($req, $data) @{ Status = 200; Body = [byte[]]($req.Body.Length, [byte][char]$req.Headers['content-type'][12]) } }
        try { $r = Invoke-PkiHttp -Url "$($s.Url)/ocsp" -Method POST -Body ([byte[]](1..10)) -ContentType 'application/ocsp-request' } finally { Stop-FakeHttp $s }
        $r.State | Should -Be 0
        $r.Bytes[0] | Should -Be 10
        [char]$r.Bytes[1] | Should -Be 'o'
    }

    It 'POST follows 307 then 307 with the same method, body and content type (the measured Kontur time-stamping path)' {
        $s = Start-FakeHttp -Handler {
            param($req, $data)
            switch ($req.Path) {
                '/tsp2012/tsp.srf' { return @{ Status = 307; Headers = @{ Location = '/tsp3/tsp.srf' } } }
                '/tsp3/tsp.srf' { return @{ Status = 307; Headers = @{ Location = '/tspq/tspservice' } } }
                default { return @{ Status = 200; Body = [byte[]]([byte][char]$req.Method[0], $req.Body.Length, [byte][char]$req.Headers['content-type'][12]) } }
            }
        }
        try { $r = Invoke-PkiHttp -Url "$($s.Url)/tsp2012/tsp.srf" -Method POST -Body ([byte[]](1..10)) -ContentType 'application/timestamp-query' } finally { Stop-FakeHttp $s }
        $r.State | Should -Be 0
        [char]$r.Bytes[0] | Should -Be 'P'
        $r.Bytes[1] | Should -Be 10
        [char]$r.Bytes[2] | Should -Be 't'
        $r.FinalUrl | Should -Be "$($s.Url)/tspq/tspservice"
        $s.Data.Requests | Should -Be 3
    }
}

Describe 'Failure classes and budget' {
    It 'HTTP 500 gives 30 with the code' {
        $s = Start-FakeHttp -Handler { param($req, $data) @{ Status = 500 } }
        try { $r = Invoke-PkiHttp -Url "$($s.Url)/nuc/ocsp.srf" -Method POST -Body ([byte[]](0x30, 0x00)) -ContentType 'application/ocsp-request' } finally { Stop-FakeHttp $s }
        $r.State | Should -Be 30
        $r.Http | Should -Be 500
    }

    It 'a closed port gives 22' {
        $r = Invoke-PkiHttp -Url "http://127.0.0.1:$(Get-ClosedPort)/x.crl"
        $r.State | Should -Be 22
        $r.Ms | Should -BeGreaterOrEqual 0
    }

    It 'an unresolvable name gives 10' {
        (Invoke-PkiHttp -Url 'http://no-such-host.invalid/x.crl').State | Should -Be 10
    }

    It 'a silent server gives 20 within the budget' {
        $s = Start-FakeHttp -Handler { param($req, $data) @{ Silent = $true } }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try { $r = Invoke-PkiHttp -Url "$($s.Url)/tsp" -TimeoutMs 2000 } finally { Stop-FakeHttp $s }
        $r.State | Should -Be 20
        $sw.ElapsedMilliseconds | Should -BeLessThan 3500
    }

    It 'a body dripped byte by byte ends at the budget with 20' {
        $s = Start-FakeHttp -Handler { param($req, $data) @{ Status = 200; Body = [byte[]]::new(100); DripMs = 100 } }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try { $r = Invoke-PkiHttp -Url "$($s.Url)/x.cer" -TimeoutMs 1500 } finally { Stop-FakeHttp $s }
        $r.State | Should -Be 20
        $sw.ElapsedMilliseconds | Should -BeLessThan 3500
    }

    It 'Socket error <code> maps to <state>' -ForEach @(
        @{ code = 'AccessDenied'; state = 23 }
        @{ code = 'TimedOut'; state = 20 }
        @{ code = 'ConnectionRefused'; state = 22 }
        @{ code = 'HostNotFound'; state = 10 }
        @{ code = 'NetworkUnreachable'; state = 24 }
    ) {
        Get-PkiSocketState ([Net.Sockets.SocketError]$code) | Should -Be $state
    }

    It 'the pass deadline shortens a request and reports it as not checked (90), not as a timeout of the address' {
        Start-PkiPass -BudgetMs 800
        $s = Start-FakeHttp -Handler { param($req, $data) @{ Silent = $true } }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try { $r = Invoke-PkiHttp -Url "$($s.Url)/tsp" } finally { Stop-FakeHttp $s }
        $r.State | Should -Be 90
        $sw.ElapsedMilliseconds | Should -BeLessThan 2500
        Test-PkiPassExpired | Should -BeTrue
        Start-PkiPass
        Test-PkiPassExpired | Should -BeFalse
    }
}
