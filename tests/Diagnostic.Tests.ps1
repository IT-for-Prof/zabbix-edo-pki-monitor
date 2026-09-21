# itforprof.com by Konstantin Tyutyunnik
# Operator diagnostics of agent/edo-pki.ps1: the sentence a problem shows in its operational data.
# Run under Windows PowerShell 5.1 with Pester 6.2.0:
#   powershell.exe -NoProfile -Command "Invoke-Pester -Path tests -CI"

BeforeAll {
    $script:CollectorPath = (Resolve-Path (Join-Path $PSScriptRoot '..\agent\edo-pki.ps1')).Path
    . $script:CollectorPath
}

Describe 'Row diagnostics' {
    It 'a network row reads as what happened and what to do, codes stay in reason and action' {
        $row = [ordered]@{ url = 'http://example.test/a.crl'; state = 10; http = -1; ms = 1; error = 'имя example.test не найдено в DNS' }
        $out = Set-PkiRowDiagnostic $row
        $out.reason | Should -Be 'CDP_DNS_FAIL'
        $out.action | Should -Be 'FIX_DNS'
        $out.diagnostic | Should -Be 'Имя example.test не найдено в DNS. Что делать: проверить DNS-серверы хоста и разрешение этого имени'
    }

    It 'a healthy row has no diagnostic' {
        (Set-PkiRowDiagnostic ([ordered]@{ url = 'u'; state = 0; http = 200; ms = 1; error = '' })).diagnostic | Should -Be ''
    }

    It 'a long server answer is cut, the action survives and the sentence fits a CHAR item' {
        $row = [ordered]@{ url = 'u'; state = 30; http = 503; ms = 1; error = 'сервер ответил HTTP 503: «' + ('ы' * 400) + '»' }
        $d = (Set-PkiRowDiagnostic $row).diagnostic
        $d.Length | Should -BeLessOrEqual 250
        $d | Should -Match '…\. Что делать: сравнить с другими хостами'
    }

    It 'a missing local list names the address it cannot be fetched from' {
        $row = [ordered]@{ ca = 'Test CA'; aki = 'ab'; state = 1; hours_left = -1; pct_left = -1; source = 'store:My'; crl_count = 0; reason = 'MISSING_CRL'; action = 'FIX_DNS_OR_INSTALL_CRL'; network_reason = 'CDP_DNS_FAIL'; endpoint = 'http://cdp.test/a.crl'; diagnostic = '' }
        (Set-PkiRowDiagnostic $row -PreserveReason).diagnostic | Should -Be 'Список отзыва УЦ не установлен на хосте; скачать его с http://cdp.test/a.crl нельзя: имя не найдено в DNS. Что делать: починить DNS хоста или установить список отзыва вручную'
    }

    It 'a missing local list whose address is silent says so' {
        $row = [ordered]@{ ca = 'Test CA'; aki = 'ab'; state = 1; hours_left = -1; pct_left = -1; source = 'store:My'; crl_count = 0; reason = 'MISSING_CRL'; action = 'CHECK_NETWORK_OR_INSTALL_CRL'; network_reason = 'CDP_NETWORK_FAIL'; endpoint = 'http://cdp.test/a.crl'; diagnostic = '' }
        (Set-PkiRowDiagnostic $row -PreserveReason).diagnostic | Should -Match '^Список отзыва УЦ не установлен на хосте; скачать его с http://cdp\.test/a\.crl нельзя: узел не отвечает\. Что делать: '
    }

    It 'an expired local list says how long ago' {
        $row = [ordered]@{ ca = 'Test CA'; aki = 'ab'; state = 2; hours_left = -37.4; pct_left = -5; source = 'store:My'; crl_count = 1; reason = 'EXPIRED_CRL'; action = 'REFRESH_CRL'; network_reason = ''; endpoint = ''; diagnostic = '' }
        (Set-PkiRowDiagnostic $row -PreserveReason).diagnostic | Should -Match '^Установленный на хосте список отзыва УЦ просрочен 37 ч назад\. Что делать: '
    }

    It 'every action the collector can emit has operator text' {
        $source = [IO.File]::ReadAllText($script:CollectorPath)
        $actions = @([regex]::Matches($source, "(?i)action\s*=\s*'([A-Z_]+)'") | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
        $actions.Count | Should -BeGreaterThan 10
        foreach ($a in $actions) { $script:PkiActionText.ContainsKey($a) | Should -BeTrue -Because $a }
        foreach ($s in 0..99) { $script:PkiActionText.ContainsKey((Get-PkiStateDiagnostic $s).Action) | Should -BeTrue -Because "state $s" }
    }
}

Describe 'Server evidence' {
    It 'markup, entities and control characters are stripped; the text is cut with an ellipsis' {
        ConvertTo-PkiPlainText "<html><script>x()</script><b>Bad&amp;Gateway</b>`r`n`t tail</html>" | Should -Be 'Bad&Gateway tail'
        (ConvertTo-PkiPlainText ('a' * 300) 50).Length | Should -Be 50
    }

    It 'hostile markup of the largest accepted answer is cleaned in bounded time' {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        [void](ConvertTo-PkiPlainText ('<script' * 40000))
        $sw.ElapsedMilliseconds | Should -BeLessThan 3000 -Because '262 KB of unclosed <script took 106 s before the input cut'
    }

    It 'a WebException status names the failure instead of INTERNAL_ERROR' {
        Get-PkiErrorText ([Net.WebException]::new('x', [Net.WebExceptionStatus]::ConnectionClosed)) | Should -Be 'WEB_CONNECTIONCLOSED'
        ConvertTo-PkiPlainText '&lt;script&gt;alert(1)&lt;/script&gt; down' | Should -Be 'script alert(1) /script down' -Because 'opdata reaches HTML e-mail unescaped'
    }

    It 'a refused stamp carries the failInfo names and the service statusString' {
        $said = New-PkiTlv 0x30 (New-PkiTlv 0x0C ([Text.Encoding]::UTF8.GetBytes('Алгоритм не поддерживается')))
        $info = New-PkiTlv 0x30 ((New-PkiInteger ([byte[]]2)) + $said + (New-PkiTlv 0x03 ([byte[]](0x07, 0x80))))
        $t = Read-PkiTspResponse -Bytes (New-PkiTlv 0x30 $info) -Imprint ([byte[]](1..32)) -Nonce ([byte[]](1, 2))
        $t.Status | Should -Be 2
        $t.FailInfo | Should -Be @('badAlg')
        $t.SystemFailure | Should -BeFalse
        $t.StatusText | Should -Be 'Алгоритм не поддерживается'
    }

    It 'failInfo bits off a byte boundary land in their own byte: badDataFormat 5, timeNotAvailable 14' {
        $info = New-PkiTlv 0x30 ((New-PkiInteger ([byte[]]2)) + (New-PkiTlv 0x03 ([byte[]](0x01, 0x04, 0x02))))
        $t = Read-PkiTspResponse -Bytes (New-PkiTlv 0x30 $info) -Imprint ([byte[]](1..32)) -Nonce ([byte[]](1, 2))
        $t.FailInfo | Should -Be @('badDataFormat', 'timeNotAvailable')
    }

    It 'failInfo bits are named by number, not by position: systemFailure is bit 25 (the ФНС answer)' {
        $info = New-PkiTlv 0x30 ((New-PkiInteger ([byte[]]2)) + (New-PkiTlv 0x03 ([byte[]](0x06, 0x00, 0x00, 0x00, 0x40))))
        $t = Read-PkiTspResponse -Bytes (New-PkiTlv 0x30 $info) -Imprint ([byte[]](1..32)) -Nonce ([byte[]](1, 2))
        $t.SystemFailure | Should -BeTrue
        $t.FailInfo | Should -Be @('systemFailure')
    }
}
