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
        $r.Error | Should -Match '^переадресация на .+ не выполнена: разрешён только http://$'
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
        $r.Error | Should -Be 'сервер ответил HTTP 500 X' -Because 'no body: the status line alone'
    }

    It 'an error page is shown as its text: code, status phrase and the page without markup' {
        $page = [Text.Encoding]::UTF8.GetBytes('<html><head><title>Сервис недоступен</title><style>h1{color:red}</style></head><body><h1>Service&nbsp;Unavailable</h1>' + ("`n" * 3) + '</body></html>')
        $s = Start-FakeHttp -Data @{ Page = $page } -Handler { param($req, $data) @{ Status = 503; Body = $data.Page; Headers = @{ 'Content-Type' = 'text/html; charset=utf-8' } } }
        try { $r = Invoke-PkiHttp -Url "$($s.Url)/tsp/tsp.srf" -Method POST -Body ([byte[]](0x30, 0x00)) -ContentType 'application/timestamp-query' } finally { Stop-FakeHttp $s }
        $r.State | Should -Be 30
        $r.Error | Should -Be 'сервер ответил HTTP 503 X: «Сервис недоступен Service Unavailable»'
    }

    It 'an error page cut inside a UTF-8 character is still read as UTF-8' {
        $page = [Text.Encoding]::UTF8.GetBytes('<p>' + ('ы' * 3000) + '</p>')
        $s = Start-FakeHttp -Data @{ Page = $page } -Handler { param($req, $data) @{ Status = 503; Body = $data.Page; Headers = @{ 'Content-Type' = 'text/html' } } }
        try { $r = Invoke-PkiHttp -Url "$($s.Url)/x.crl" } finally { Stop-FakeHttp $s }
        $r.Error | Should -Match '^сервер ответил HTTP 503 X: «ыыы'
    }

    It 'a dripping error page ends at the budget with 20, like a dripping body of 200' {
        # .NET Framework reads a failing answer's body before it hands over the status: an answer not received in
        # the budget has no code to report.
        $s = Start-FakeHttp -Handler { param($req, $data) @{ Status = 503; Body = [byte[]]::new(100); DripMs = 100; Headers = @{ 'Content-Type' = 'text/plain' } } }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try { $r = Invoke-PkiHttp -Url "$($s.Url)/x.crl" -TimeoutMs 1500 } finally { Stop-FakeHttp $s }
        $sw.ElapsedMilliseconds | Should -BeLessThan 3500
        $r.State | Should -Be 20
        $r.Http | Should -Be -1
        $r.Error | Should -Be "нет ответа от 127.0.0.1:$($s.Port) за 1500 мс"
    }

    It 'a dripping error page POSTed to a service ends at the budget with 20' {
        $s = Start-FakeHttp -Handler { param($req, $data) @{ Status = 500; Body = [byte[]]::new(100); DripMs = 100; Headers = @{ 'Content-Type' = 'text/html' } } }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try { $r = Invoke-PkiHttp -Url "$($s.Url)/tsp/tsp.srf" -Method POST -Body ([byte[]](0x30, 0x00)) -ContentType 'application/timestamp-query' -TimeoutMs 1500 } finally { Stop-FakeHttp $s }
        $sw.ElapsedMilliseconds | Should -BeLessThan 3500
        $r.State | Should -Be 20
        $r.Http | Should -Be -1
        $r.Error | Should -Be "нет ответа от 127.0.0.1:$($s.Port) за 1500 мс"
    }

    It 'a silent service gives 20 within the budget after the request body was sent' {
        # The response wait is bounded by the budget, not by HttpWebRequest.Timeout (which async calls ignore).
        $s = Start-FakeHttp -Handler { param($req, $data) @{ Silent = $true } }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try { $r = Invoke-PkiHttp -Url "$($s.Url)/ocsp" -Method POST -Body ([byte[]](0x30, 0x00)) -ContentType 'application/ocsp-request' -TimeoutMs 1500 } finally { Stop-FakeHttp $s }
        $sw.ElapsedMilliseconds | Should -BeLessThan 3500
        $r.State | Should -Be 20
        $s.Data.Requests | Should -Be 1
    }

    It 'a binary error body is not shown' {
        $s = Start-FakeHttp -Handler { param($req, $data) @{ Status = 502; Body = [byte[]](0x30, 0x03, 0x0A, 0x01, 0x02); Headers = @{ 'Content-Type' = 'application/ocsp-response' } } }
        try { $r = Invoke-PkiHttp -Url "$($s.Url)/ocsp" } finally { Stop-FakeHttp $s }
        $r.Error | Should -Be 'сервер ответил HTTP 502 X'
    }

    It 'a failure after a redirect names the address that failed and drops the redirect code' {
        $s = Start-FakeHttp -Handler { param($req, $data) if ($req.Path -eq '/tsp2012/tsp.srf') { @{ Status = 307; Headers = @{ Location = '/DDoS01/tsp.srf' } } } else { @{ Silent = $true } } }
        try { $r = Invoke-PkiHttp -Url "$($s.Url)/tsp2012/tsp.srf" -TimeoutMs 1500 } finally { Stop-FakeHttp $s }
        $r.State | Should -Be 20
        $r.Http | Should -Be -1
        $r.Error | Should -Match "^нет ответа от 127\.0\.0\.1:$($s.Port) за 1500 мс \(после переадресации на http://127\.0\.0\.1:$($s.Port)/DDoS01/tsp\.srf\)$"
    }

    It 'a closed port gives 22' {
        $r = Invoke-PkiHttp -Url "http://127.0.0.1:$(Get-ClosedPort)/x.crl"
        $r.State | Should -Be 22
        $r.Error | Should -Match '^127\.0\.0\.1:\d+ отклоняет соединение$'
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

Describe 'Several addresses of one name' {
    # 127.0.0.2 is loopback with nothing listening: refused at once, like a dead address of a CA node, without a 21 s wait.
    BeforeEach { Start-PkiPass }

    It 'asks through the address that connects, names the dead one and keeps the name in Host' {
        Mock Resolve-PkiHostAddress { , @('127.0.0.2', '127.0.0.1') }
        $s = Start-FakeHttp -Handler { param($req, $data) $data.Host = $req.Headers['host']; @{ Status = 200; Body = [byte[]](1, 2, 3) } }
        try { $r = Invoke-PkiHttp -Url "http://cdp.test:$($s.Port)/x.crl" } finally { Stop-FakeHttp $s }
        $r.State | Should -Be 0
        $r.Bytes.Length | Should -Be 3
        $r.Dead | Should -Be @('127.0.0.2')
        $s.Data.Host | Should -Be "cdp.test:$($s.Port)"
    }

    It 'remembers the dead address for the pass and still names it' {
        Mock Resolve-PkiHostAddress { , @('127.0.0.2', '127.0.0.1') }
        $s = Start-FakeHttp -Handler { param($req, $data) @{ Status = 200; Body = [byte[]](1) } }
        try {
            $first = Invoke-PkiHttp -Url "http://cdp.test:$($s.Port)/x.crl"
            $script:PkiDeadAddresses.ContainsKey("127.0.0.2:$($s.Port)") | Should -BeTrue
            $second = Invoke-PkiHttp -Url "http://cdp.test:$($s.Port)/x.crl"
        } finally { Stop-FakeHttp $s }
        $first.Dead | Should -Be @('127.0.0.2')
        $second.State | Should -Be 0
        $second.Dead | Should -Be @('127.0.0.2')
        Start-PkiPass
        $script:PkiDeadAddresses.Count | Should -Be 0
    }

    It 'every address refused: the refusal, no dead list and nothing remembered' {
        Mock Resolve-PkiHostAddress { , @('127.0.0.2', '127.0.0.3') }
        $r = Invoke-PkiHttp -Url 'http://cdp.test:1/x.crl'
        $r.State | Should -Be 22
        $r.Error | Should -Be 'cdp.test:1 отклоняет соединение'
        $r.Dead.Count | Should -Be 0
        $script:PkiDeadAddresses.Count | Should -Be 0
    }

    It 'an address still connecting when the answer came is waited out within the budget and named dead' {
        Mock Resolve-PkiHostAddress { , @('10.255.255.1', '127.0.0.1') }
        Mock Select-PkiAddress { @{ Ip = '127.0.0.1'; Port = $Port; Failed = @(); Pending = @(@{ Ip = '10.255.255.1'; Client = (New-Object Net.Sockets.TcpClient); Task = (New-Object 'Threading.Tasks.TaskCompletionSource[bool]').Task }) } }
        $s = Start-FakeHttp -Handler { param($req, $data) @{ Status = 200; Body = [byte[]](1) } }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try { $r = Invoke-PkiHttp -Url "http://cdp.test:$($s.Port)/x.crl" -TimeoutMs 1000 } finally { Stop-FakeHttp $s }
        $sw.ElapsedMilliseconds | Should -BeLessThan 2500
        $r.State | Should -Be 0
        $r.Ms | Should -BeLessThan 900
        $r.Dead | Should -Be @('10.255.255.1')
        $script:PkiDeadAddresses.ContainsKey("10.255.255.1:$($s.Port)") | Should -BeTrue
    }

    It 'an address still connecting when the pass deadline cut the budget is not named dead' {
        Start-PkiPass -BudgetMs 1000
        Mock Resolve-PkiHostAddress { , @('10.255.255.1', '127.0.0.1') }
        Mock Select-PkiAddress { @{ Ip = '127.0.0.1'; Port = $Port; Failed = @(); Pending = @(@{ Ip = '10.255.255.1'; Client = (New-Object Net.Sockets.TcpClient); Task = (New-Object 'Threading.Tasks.TaskCompletionSource[bool]').Task }) } }
        $s = Start-FakeHttp -Handler { param($req, $data) @{ Status = 200; Body = [byte[]](1) } }
        try { $r = Invoke-PkiHttp -Url "http://cdp.test:$($s.Port)/x.crl" } finally { Stop-FakeHttp $s }
        $r.State | Should -Be 0
        $r.Dead.Count | Should -Be 0
        $script:PkiDeadAddresses.Count | Should -Be 0
    }

    It 'a redirect off the name with several addresses keeps its dead list' {
        Mock Resolve-PkiHostAddress { , @('127.0.0.2', '127.0.0.1') }
        $s = Start-FakeHttp -Handler { param($req, $data) if ($req.Path -eq '/x.crl') { return @{ Status = 302; Headers = @{ Location = "http://127.0.0.1:$($req.Headers['host'] -replace '^.*:')/y.crl" } } }; @{ Status = 200; Body = [byte[]](1) } }
        try { $r = Invoke-PkiHttp -Url "http://cdp.test:$($s.Port)/x.crl" } finally { Stop-FakeHttp $s }
        $r.State | Should -Be 0
        $r.FinalUrl | Should -Be "http://127.0.0.1:$($s.Port)/y.crl"
        $r.Dead | Should -Be @('127.0.0.2')
    }
}
