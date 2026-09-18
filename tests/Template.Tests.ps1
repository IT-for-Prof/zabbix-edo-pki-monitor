# itforprof.com by Konstantin Tyutyunnik
# Contract tests: Zabbix template <-> collector <-> agent config <-> README.
# Run under Windows PowerShell 5.1 with Pester 6.2.0 and powershell-yaml 0.4.12:
#   powershell.exe -NoProfile -Command "Invoke-Pester -Path tests -CI"

BeforeAll {
    Import-Module powershell-yaml -RequiredVersion 0.4.12 -ErrorAction Stop
    $root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $script:CollectorPath = Join-Path $root 'agent\edo-pki.ps1'
    $script:ConfPath = Join-Path $root 'agent\edo-pki-monitor.conf'
    $script:ReadmePath = Join-Path $root 'README.md'
    $script:TemplatePath = Join-Path $root 'template\edo-pki-monitor-by-zabbix-agent-active.yaml'
    . $script:CollectorPath

    $script:Export = ConvertFrom-Yaml ([IO.File]::ReadAllText($script:TemplatePath))
    $script:T = $script:Export.zabbix_export.templates[0]
    $script:Name = $script:T.template
    $script:Rules = @($script:T.discovery_rules)
    $script:Macros = @{}
    foreach ($m in $script:T.macros) { $script:Macros[$m.macro] = $m }
    $script:MasterKey = 'edo.pki["{$PKI.NETWORK}","{$PKI.LOCAL}","{$PKI.STORES}","{$PKI.CONTAINERS}","{$PKI.CRL.URLS}","{$PKI.TSP.URLS}"]'
    $script:WindowsDependencies = @(
        @{ name = 'Windows: Active checks are not available'; expression = 'min(/Windows by Zabbix agent active/zabbix[host,active_agent,available],{$AGENT.TIMEOUT})=2' }
        @{ name = 'Windows: Zabbix agent is not available'; expression = 'nodata(/Windows by Zabbix agent active/agent.ping,{$AGENT.NODATA_TIMEOUT})=1' }
    )

    function Get-MacroValue([string]$Name) {
        $m = $script:Macros[$Name]
        if ($null -eq $m -or -not $m.ContainsKey('value')) { return '' }
        [string]$m.value
    }

    function ConvertTo-Seconds([string]$Duration) {
        if ($Duration -notmatch '^(\d+)([smhdw]?)$') { throw "not a Zabbix duration: $Duration" }
        $n = [int]$Matches[1]
        switch ($Matches[2]) { 'm' { $n * 60 } 'h' { $n * 3600 } 'd' { $n * 86400 } 'w' { $n * 604800 } default { $n } }
    }

    function Get-AllItems { @($script:T.items) + @($script:Rules | ForEach-Object { $_.item_prototypes }) }
    function Get-AllTriggers {
        foreach ($i in $script:T.items) { if ($i.ContainsKey('triggers')) { $i.triggers } }
        foreach ($r in $script:Rules) { if ($r.ContainsKey('trigger_prototypes')) { $r.trigger_prototypes } }
    }
    $script:DeclaredKeys = @(Get-AllItems | ForEach-Object { $_.key })
    $script:CollectorTrigger = @($script:T.items | Where-Object { $_.key -eq 'edo.pki.error' })[0].triggers[0]
}

Describe 'Template shape' {
    It 'is a Zabbix 7.0 export with one template, team tags and unique UUIDs' {
        $script:Export.zabbix_export.version | Should -Be '7.0'
        @($script:Export.zabbix_export.templates).Count | Should -Be 1
        $script:Name | Should -Be 'EDO PKI Monitor by Zabbix agent active'
        $tags = @{}; foreach ($tag in $script:T.tags) { $tags[$tag.tag] = $tag.value }
        $tags['class'] | Should -Be 'service'
        $tags['target'] | Should -Be 'edo-pki'
        $tags['vendor'] | Should -Be 'itforprof'
        $uuids = @([regex]::Matches([IO.File]::ReadAllText($script:TemplatePath), '(?m)^\s*-?\s*uuid: (\S+)') | ForEach-Object { $_.Groups[1].Value })
        $uuids | ForEach-Object { $_ | Should -Match '^[0-9a-f]{32}$' }
        @($uuids | Sort-Object -Unique).Count | Should -Be $uuids.Count
    }

    It 'every item has a component tag and no key of Windows by Zabbix agent active is reused' {
        foreach ($i in Get-AllItems) { @($i.tags | Where-Object { $_.tag -eq 'component' }).Count | Should -Be 1 -Because $i.key }
        foreach ($key in 'agent.version', 'agent.variant', 'agent.ping', 'system.localtime', 'zabbix[host,active_agent,available]') { $script:DeclaredKeys | Should -Not -Contain $key }
    }

    It 'names, tags and descriptions use only LLD macros without owner data (R27)' {
        $allowed = @('{#URL}', '{#CA}', '{#AKI}', '{#CERT.ID}', '{#CERT.CA}', '{#CERT.NOTAFTER}')
        $used = @([regex]::Matches([IO.File]::ReadAllText($script:TemplatePath), '\{#[A-Z.]+\}') | ForEach-Object { $_.Value } | Sort-Object -Unique)
        foreach ($u in $used) { $allowed | Should -Contain $u }
    }
}

Describe 'Collector item and agent config' {
    It 'the master item passes the macros in the collector argument order with the timeout and interval macros' {
        $master = @($script:T.items | Where-Object { $_.type -eq 'ZABBIX_ACTIVE' -and $_.key -like 'edo.pki*' })
        $master.Count | Should -Be 1
        $master[0].key | Should -Be $script:MasterKey
        $master[0].value_type | Should -Be 'TEXT'
        $master[0].timeout | Should -Be '{$PKI.TIMEOUT}'
        $master[0].delay | Should -Be '{$PKI.INTERVAL}'
        foreach ($i in @(Get-AllItems | Where-Object { $_.type -eq 'DEPENDENT' })) { $i.master_item.key | Should -Be $script:MasterKey -Because $i.key }
        foreach ($r in $script:Rules) { $r.master_item.key | Should -Be $script:MasterKey -Because $r.key }
    }

    It 'UserParameter passes six quoted arguments; install advice is a service restart' {
        $lines = @(Get-Content $script:ConfPath | Where-Object { $_ -match '^UserParameter=' })
        $lines.Count | Should -Be 1
        $lines[0] | Should -Match '^UserParameter=edo\.pki\[\*\],'
        foreach ($n in 1..6) { $lines[0] | Should -Match ([regex]::Escape("""`$$n""")) }
        $lines[0] | Should -Not -Match '\$7'
        [IO.File]::ReadAllText($script:ConfPath) | Should -Match 'Restart-Service'
    }

    It 'the script path is the same in the config, the md5sum item and README' {
        $line = @(Get-Content $script:ConfPath | Where-Object { $_ -match '^UserParameter=' })[0]
        $path = [regex]::Match($line, '-File "([^"]+)"').Groups[1].Value
        $path | Should -Be 'C:\Program Files\Zabbix Agent 2\scripts\edo-pki.ps1'
        $script:DeclaredKeys | Should -Contain ('vfs.file.md5sum["' + $path + '"]')
        [IO.File]::ReadAllText($script:ReadmePath) | Should -Match ([regex]::Escape($path))
    }

    It '{$PKI.SCRIPT.MD5} is the MD5 of agent/edo-pki.ps1 as deployed (BOM, CRLF)' {
        $text = [IO.File]::ReadAllText($script:CollectorPath) -replace "`r?`n", "`r`n"
        $bytes = [byte[]](0xEF, 0xBB, 0xBF) + (New-Object Text.UTF8Encoding($false)).GetBytes($text)
        $md5 = [BitConverter]::ToString([Security.Cryptography.MD5]::Create().ComputeHash($bytes)).Replace('-', '').ToLower()
        Get-MacroValue '{$PKI.SCRIPT.MD5}' | Should -Be $md5
    }
}

Describe 'Discovery rules and item prototypes' {
    It 'every rule is dependent, reads a list of the output contract and keeps lost objects 7 days, disabled at once' {
        foreach ($r in $script:Rules) {
            $r.type | Should -Be 'DEPENDENT'
            $list = $r.preprocessing[0].parameters[0] -replace '^\$\.', ''
            $script:PkiContract.Keys | Should -Contain $list -Because $r.key
            $r.lifetime | Should -Be '7d'
            $r.enabled_lifetime_type | Should -Be 'DISABLE_IMMEDIATELY'
            foreach ($p in $r.lld_macro_paths) { $script:PkiContract[$list] | Should -Contain ($p.path -replace '^\$\.', '') -Because "$($r.key) $($p.lld_macro)" }
        }
    }

    It 'every prototype filters its own list by an LLD macro and reads a field of that list' {
        foreach ($r in $script:Rules) {
            $list = $r.preprocessing[0].parameters[0] -replace '^\$\.', ''
            $macroField = @{}; foreach ($p in $r.lld_macro_paths) { $macroField[$p.lld_macro] = $p.path -replace '^\$\.', '' }
            foreach ($i in $r.item_prototypes) {
                $jp = $i.preprocessing[0].parameters[0]
                $m = [regex]::Match($jp, "^\$\.([a-z]+)\[\?\(@\.([a-z_]+)=='(\{#[A-Z.]+\})'\)\]\.([a-z_]+)\.first\(\)$")
                $m.Success | Should -BeTrue -Because $jp
                $m.Groups[1].Value | Should -Be $list
                $macroField[$m.Groups[3].Value] | Should -Be $m.Groups[2].Value -Because $jp
                $script:PkiContract[$list] | Should -Contain $m.Groups[4].Value -Because $jp
                $i.preprocessing[0].error_handler | Should -Be 'DISCARD_VALUE' -Because 'an object missing from one pass must not break the item'
            }
        }
    }

    It 'host items read existing top-level fields' {
        foreach ($i in @($script:T.items | Where-Object { $_.type -eq 'DEPENDENT' })) {
            $field = $i.preprocessing[0].parameters[0] -replace '^\$\.', ''
            $script:PkiContract.result | Should -Contain $field -Because $i.key
        }
    }

    It 'value maps name every state exactly as the collector does' {
        $pairs = @{ 'EDO PKI state' = $script:PkiStateNames; 'EDO PKI certificate status' = $script:PkiCertStatusNames; 'EDO PKI local CRL' = $script:PkiLocalStateNames }
        foreach ($name in $pairs.Keys) {
            $map = @($script:T.valuemaps | Where-Object { $_.name -eq $name })[0]
            @($map.mappings | ForEach-Object { '{0}={1}' -f $_.value, $_.newvalue } | Sort-Object) | Should -Be @($pairs[$name].GetEnumerator() | ForEach-Object { '{0}={1}' -f $_.Key, $_.Value } | Sort-Object)
        }
    }

    It 'values that may be -1 are FLOAT' {
        foreach ($i in Get-AllItems) {
            if ($i.key -match '\.(ms|hours_left|pct_left|skew|key_days|status|clock_skew)(\[|$)') { $i.value_type | Should -Be 'FLOAT' -Because $i.key }
        }
    }
}

Describe 'Macros' {
    It 'every referenced macro is declared, every declared one is used and described' {
        $text = [IO.File]::ReadAllText($script:TemplatePath)
        $body = $text.Substring(0, $text.IndexOf('      macros:'))
        foreach ($d in $script:WindowsDependencies) { $body = $body.Replace($d.expression, '') }
        $used = @([regex]::Matches($body, '\{\$[A-Z0-9_.]+(?::[^}]*)?\}') | ForEach-Object { $_.Value -replace ':.*\}$', '}' } | Sort-Object -Unique)
        $declared = @($script:T.macros | ForEach-Object { $_.macro -replace ':.*\}$', '}' } | Sort-Object -Unique)
        $used | Should -Be $declared
        foreach ($m in $script:T.macros) { $m.description | Should -Not -BeNullOrEmpty -Because $m.macro }
    }

    It 'nodata outlasts two intervals and the stock agent nodata; the item timeout covers the pass deadline' {
        (ConvertTo-Seconds (Get-MacroValue '{$PKI.NODATA}')) | Should -BeGreaterThan (2 * (ConvertTo-Seconds (Get-MacroValue '{$PKI.INTERVAL}')))
        (ConvertTo-Seconds (Get-MacroValue '{$PKI.NODATA}')) | Should -BeGreaterThan (30 * 60)
        (ConvertTo-Seconds (Get-MacroValue '{$PKI.TIMEOUT}')) | Should -BeGreaterOrEqual ($script:PkiBudget.PassMs / 1000 + 25)
    }

    It 'default exclusions: the FNS internal name and the VTB NUC OCSP responder, nothing else of those CAs' {
        $m = @($script:T.macros | Where-Object { $_.macro -like '{$PKI.ALERT:regex:*' })
        $m.Count | Should -Be 2
        foreach ($x in $m) { $x.value | Should -Be '0' -Because $x.macro }
        $patterns = @($m | ForEach-Object { [regex]::Match($_.macro, 'regex:"(.+)"\}$').Groups[1].Value })
        $excluded = { param($url) @($patterns | Where-Object { $url -match $_ }).Count -gt 0 }
        foreach ($url in 'http://c0000-app005/cdp/23f0da4a5de30c96e91f976a3e641689a1f8553c.crl', 'http://c0000-app005/crt/ca_fns_russia_2024_01.crt', 'http://ca.vtb.ru/nuc/ocsp.srf') {
            & $excluded $url | Should -BeTrue -Because $url
        }
        # Public addresses of the same CAs that answer stay alerting.
        foreach ($url in 'http://pki.tax.gov.ru/cdp/23f0da4a5de30c96e91f976a3e641689a1f8553c.crl', 'http://cdp.tax.gov.ru/cdp/23f0da4a5de30c96e91f976a3e641689a1f8553c.crl', 'http://pki.tax.gov.ru/ocsp02/ocsp.srf',
            'http://ca.vtb.ru/cdp/nuc/vtbn_2024.crl', 'http://pki1.vtb.ru/cdp/nuc/vtbn_2024.crl', 'http://ca.vtb.ru/aia/nuc/vtbn_2024.cer', 'http://pki1.vtb.ru/aia/nuc/vtbn_2024.cer', 'http://ca.vtb.ru/auc/ocsp.srf') {
            & $excluded $url | Should -BeFalse -Because $url
        }
    }

    It 'default arguments pass the collector argument check' {
        $argv = @('{$PKI.NETWORK}', '{$PKI.LOCAL}', '{$PKI.STORES}', '{$PKI.CONTAINERS}', '{$PKI.CRL.URLS}', '{$PKI.TSP.URLS}') | ForEach-Object { Get-MacroValue $_ }
        (Test-PkiArgs $argv).Error | Should -BeNullOrEmpty
        @((Test-PkiArgs $argv).TspUrls).Count | Should -Be 3
    }

    It 'the failure period is a Zabbix count and no macro sits inside a function count' {
        Get-MacroValue '{$PKI.FAIL.PERIOD}' | Should -Match '^#\d+$'
        foreach ($t in Get-AllTriggers) { $t.expression | Should -Not -Match '#\{\$' -Because $t.name }
    }
}

Describe 'Triggers' {
    It 'every trigger has event name, operational data, manual close, a scope tag and "Что делать"; Warning is dashboard-only' {
        foreach ($t in Get-AllTriggers) {
            $t.event_name | Should -Not -BeNullOrEmpty -Because $t.name
            $t.opdata | Should -Not -BeNullOrEmpty -Because $t.name
            $t.manual_close | Should -Be 'YES' -Because $t.name
            $t.description | Should -Match 'Что делать' -Because $t.name
            @($t.tags | Where-Object { $_.tag -eq 'scope' }).Count | Should -Be 1 -Because $t.name
            if ($t.priority -eq 'WARNING') { $t.description | Should -Match '^Только для дашборда' -Because $t.name }
        }
    }

    It 'expressions use only this template and its own keys' {
        foreach ($t in Get-AllTriggers) {
            $text = $t.expression; if ($t.ContainsKey('recovery_expression')) { $text += ' ' + $t.recovery_expression }
            $keys = @([regex]::Matches($text,'/([^/]+)/([a-z0-9_.]+(?:\[[^\]]*\])?)') | ForEach-Object { $_.Groups[1].Value | Should -Be $script:Name -Because $t.name; $_.Groups[2].Value })
            $keys.Count | Should -BeGreaterThan 0
            foreach ($k in $keys) { $script:DeclaredKeys | Should -Contain $k -Because $t.name }
        }
    }

    It 'severities follow the plan: High for revocation and invalid local lists, Warning for expiring list and key' {
        $high = @(Get-AllTriggers | Where-Object { $_.priority -eq 'HIGH' } | ForEach-Object { $_.expression })
        $high.Count | Should -Be 3
        $high | Should -Contain 'last(/EDO PKI Monitor by Zabbix agent active/edo.pki.cert.status["{#CERT.ID}"])=1'
        $high | Should -Contain 'last(/EDO PKI Monitor by Zabbix agent active/edo.pki.local.state["{#AKI}"])=1'
        $high | Should -Contain 'last(/EDO PKI Monitor by Zabbix agent active/edo.pki.local.state["{#AKI}"])=2'
        @(Get-AllTriggers | Where-Object { $_.priority -eq 'WARNING' }).Count | Should -Be 2
    }

    It 'address problems partition the failed period: one class, or mixed failures; at most one is open (measured on the server)' {
        $classes = [ordered]@{ network = @(10, 29); http = @(30, 39); content = @(40, 49); service = @(50, 89) }
        $expected = [ordered]@{ crl = @('network', 'http', 'content', 'mixed'); aia = @('network', 'http', 'content', 'mixed'); ocsp = @('network', 'http', 'content', 'service', 'mixed'); tsp = @('network', 'http', 'content', 'service', 'mixed') }
        # States each list can report (collector): every one of them in 10..89 falls into exactly one class of that list.
        $emitted = @{ crl = @(10, 20, 22, 23, 24, 30, 40, 41, 42, 43, 44); aia = @(10, 20, 22, 23, 24, 30, 40, 42, 43); ocsp = @(10, 20, 22, 23, 24, 30, 40, 50, 51); tsp = @(10, 20, 22, 23, 24, 30, 40, 50, 51) }
        foreach ($s in $script:PkiStateNames.Keys | ForEach-Object { [int]$_ } | Where-Object { $_ -ge 10 -and $_ -lt 90 }) {
            @($classes.Values | Where-Object { $s -ge $_[0] -and $s -le $_[1] }).Count | Should -Be 1 -Because "state $s"
        }
        foreach ($list in $expected.Keys) {
            $rule = @($script:Rules | Where-Object { $_.key -eq "edo.pki.$list.discovery" })[0]
            $state = @($rule.trigger_prototypes | Where-Object { $_.expression -match "edo\.pki\.$list\.state" -and $_.priority -eq 'AVERAGE' })
            @($state | ForEach-Object { @($_.tags | Where-Object { $_.tag -eq 'failure' })[0].value }) | Should -Be $expected[$list] -Because $list
            $own = @($expected[$list] | Where-Object { $_ -ne 'mixed' })
            foreach ($s in $emitted[$list]) { @($own | Where-Object { $s -ge $classes[$_][0] -and $s -le $classes[$_][1] }).Count | Should -Be 1 -Because "$list state $s" }
            $k = "/$($script:Name)/edo.pki.$list.state[`"{#URL}`"]"
            $period = '{$PKI.FAIL.PERIOD}'
            $inClass = @($own | ForEach-Object { "min($k,$period)>=$($classes[$_][0]) and max($k,$period)<=$($classes[$_][1])" })
            foreach ($tr in $state) {
                $cls = @($tr.tags | Where-Object { $_.tag -eq 'failure' })[0].value
                $tr.recovery_mode | Should -Be 'RECOVERY_EXPRESSION' -Because $tr.name
                if ($cls -eq 'mixed') {
                    $tr.expression | Should -Be ("min($k,$period)>=10 and max($k,$period)<90 and {`$PKI.ALERT:`"{#URL}`"}=1" + (($inClass | ForEach-Object { " and not ($_)" }) -join '')) -Because $tr.name
                    $tr.recovery_expression | Should -Be ("last($k)<10 or {`$PKI.ALERT:`"{#URL}`"}=0" + (($inClass | ForEach-Object { " or ($_)" }) -join '')) -Because $tr.name
                    @($tr.dependencies).Count | Should -Be 1 -Because 'a dependency on the class triggers froze the mixed problem open (measured 17.09.2026)'
                    continue
                }
                $lo = $classes[$cls][0]; $hi = $classes[$cls][1]
                $tr.expression | Should -Be "min($k,$period)>=$lo and max($k,$period)<=$hi and {`$PKI.ALERT:`"{#URL}`"}=1" -Because $tr.name
                $tr.recovery_expression | Should -Be "last($k)<10 or {`$PKI.ALERT:`"{#URL}`"}=0 or (min($k,$period)>=10 and max($k,$period)<90 and not (min($k,$period)>=$lo and max($k,$period)<=$hi))" -Because $tr.name
            }
        }
    }

    It 'the clock problem closes when no stamp arrives for {$PKI.NODATA}' {
        $t = @($script:T.items | Where-Object { $_.key -eq 'edo.pki.clock_skew' })[0].triggers[0]
        $t.expression | Should -Be "abs(last(/$($script:Name)/edo.pki.clock_skew))>{`$PKI.CLOCK.MAX} and nodata(/$($script:Name)/edo.pki.clock_skew,{`$PKI.NODATA})=0"
    }

    It 'a certificate status that was not checked (-1) does not close REVOKED or UNKNOWN' {
        $cert = "/$($script:Name)/edo.pki.cert.status[`"{#CERT.ID}`"]"
        $rule = @($script:Rules | Where-Object { $_.key -eq 'edo.pki.cert.discovery' })[0]
        $revoked = @($rule.trigger_prototypes | Where-Object { $_.priority -eq 'HIGH' })[0]
        $revoked.recovery_mode | Should -Be 'RECOVERY_EXPRESSION'
        $revoked.recovery_expression | Should -Be "last($cert)=0 or last($cert)=2"
        $unknown = @($rule.trigger_prototypes | Where-Object { $_.priority -eq 'AVERAGE' })[0]
        $unknown.recovery_mode | Should -Be 'RECOVERY_EXPRESSION'
        $unknown.recovery_expression | Should -Be "last($cert)=0 or last($cert)=1"
    }

    It 'the collector trigger depends on both stock agent triggers; every other trigger depends on it or on siblings of its own rule' {
        @($script:CollectorTrigger.dependencies).Count | Should -Be 2
        foreach ($d in $script:WindowsDependencies) { @($script:CollectorTrigger.dependencies | Where-Object { $_.name -eq $d.name -and $_.expression -eq $d.expression }).Count | Should -Be 1 }
        $all = @(Get-AllTriggers)
        foreach ($t in $all) {
            if ($t.name -eq $script:CollectorTrigger.name -or $t.name -like '*версия скрипта*') { continue }
            @($t.dependencies).Count | Should -BeGreaterThan 0 -Because $t.name
            # Zabbix 7.0.30 keeps a prototype dependency on discovered triggers only within one LLD rule (measured 17.09.2026).
            $rule = @($script:Rules | Where-Object { $_.ContainsKey('trigger_prototypes') -and @($_.trigger_prototypes | Where-Object { $_.name -eq $t.name }).Count })
            foreach ($dep in $t.dependencies) {
                $target = @($all | Where-Object { $_.name -eq $dep.name -and $_.expression -eq $dep.expression -and [string]$_['recovery_expression'] -eq [string]$dep['recovery_expression'] })
                $target.Count | Should -Be 1 -Because "$($t.name) -> $($dep.name)"
                if ($dep.name -ne $script:CollectorTrigger.name) {
                    $rule.Count | Should -Be 1 -Because "$($t.name) depends on a prototype"
                    @($rule[0].trigger_prototypes | Where-Object { $_.name -eq $dep.name }).Count | Should -Be 1 -Because "$($t.name) -> $($dep.name) must be in the same rule"
                }
            }
        }
        $keyDays = @(Get-AllTriggers | Where-Object { $_.expression -match 'tsp\.key_days' })[0]
        @($keyDays.dependencies | ForEach-Object name | Sort-Object) | Should -Be @(@(Get-AllTriggers | Where-Object { $_.expression -match 'tsp\.state' } | ForEach-Object name) | Sort-Object) -Because 'an expiring key is not news while the service fails'
    }
}

Describe 'README agrees with the template and the collector' {
    It 'describes every macro and every state name' {
        $readme = [IO.File]::ReadAllText($script:ReadmePath)
        foreach ($m in $script:T.macros) { $readme | Should -Match ([regex]::Escape($m.macro)) -Because $m.macro }
        foreach ($s in $script:PkiStateNames.GetEnumerator()) { $readme | Should -Match "\b$($s.Key)\b.*$($s.Value)" -Because "state $($s.Key)" }
    }
}
