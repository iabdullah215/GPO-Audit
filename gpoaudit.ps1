

[CmdletBinding()]
param(
  [string]$Html,
  [string]$Xml,
  [string]$JsonOut,
  [string]$CsvOut,
  [string]$Baseline,

  [Alias('h')]
  [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Banner {
  param([string]$Name)
  Write-Host ""
  Write-Host ("=" * 60) -ForegroundColor Cyan
  Write-Host (" AUDITING GPO: {0}" -f $Name) -ForegroundColor Cyan
  Write-Host ("=" * 60) -ForegroundColor Cyan
}

function Read-TextFile {
  param([string]$Path)
  foreach ($enc in @('Unicode','utf8')) {
    try {
      return Get-Content -LiteralPath $Path -Raw -Encoding $enc
    } catch {
    }
  }
  return Get-Content -LiteralPath $Path -Raw
}

function Sha256Hex {
  param([string]$Text)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
  } finally {
    $sha.Dispose()
  }
}

$SidRegex = [regex]'S-1-5-[0-9-]+'

function Collect-Sids {
  param([string]$Text)
  ($SidRegex.Matches($Text) | ForEach-Object { $_.Value } | Sort-Object -Unique)
}

function Parse-DurationMinutes {
  param([int]$Value, [string]$Unit)
  $u = $Unit.ToLower().Trim()
  if ($u.StartsWith('min')) { return $Value }
  if ($u.StartsWith('hour') -or $u -eq 'h') { return $Value * 60 }
  if ($u.StartsWith('day') -or $u -eq 'd') { return $Value * 24 * 60 }
  return $null
}

$Reports = @()
$ActiveReport = $null

function Start-Report {
  param(
    [string]$Source,
    [string]$InputFile,
    [string]$GpoName,
    [hashtable]$Metadata
  )
  $report = [ordered]@{
    source = $Source
    input_file = $InputFile
    gpo_name = $GpoName
    metadata = $Metadata
    findings = @()
    fingerprints = New-Object 'System.Collections.Generic.HashSet[string]'
  }
  $script:Reports += $report
  $script:ActiveReport = $report
}

function Add-Finding {
  param(
    [ValidateSet('CRITICAL','HIGH','MED','INFO')][string]$Level,
    [string]$Category,
    [string]$Title,
    [string]$Message,
    [string]$Context = $null
  )

  if (-not $script:ActiveReport) { return }

  $payload = "{0}|{1}|{2}|{3}" -f $Level, $Category, $Title, $Message
  $fp = Sha256Hex $payload
  if ($script:ActiveReport.fingerprints -and $script:ActiveReport.fingerprints.Contains($fp)) { return }
  if ($script:ActiveReport.fingerprints) { [void]$script:ActiveReport.fingerprints.Add($fp) }

  $finding = [ordered]@{
    level = $Level
    category = $Category
    title = $Title
    message = $Message
    context = $Context
    source = $script:ActiveReport.source
    gpo_name = $script:ActiveReport.gpo_name
    input_file = $script:ActiveReport.input_file
  }
  $script:ActiveReport.findings += $finding
}

function Finding-Fingerprint {
  param([hashtable]$Finding)
  $payload = "{0}|{1}|{2}|{3}" -f $Finding.level, $Finding.category, $Finding.title, $Finding.message
  Sha256Hex $payload
}

function Severity-Counts {
  $counts = @{ CRITICAL = 0; HIGH = 0; MED = 0; INFO = 0 }
  foreach ($r in $script:Reports) {
    foreach ($f in $r.findings) {
      if (-not $counts.ContainsKey($f.level)) { $counts[$f.level] = 0 }
      $counts[$f.level]++
    }
  }
  return $counts
}

function Print-Summary {
  $counts = Severity-Counts
  $total = ($counts.Values | Measure-Object -Sum).Sum
  Write-Host ""
  Write-Host "[Summary] Findings by severity:" -ForegroundColor White
  Write-Host ("  CRITICAL: {0}" -f $counts.CRITICAL) -ForegroundColor Red
  Write-Host ("  HIGH:     {0}" -f $counts.HIGH) -ForegroundColor Yellow
  Write-Host ("  MED:      {0}" -f $counts.MED)
  Write-Host ("  INFO:     {0}" -f $counts.INFO)
  Write-Host ("  Total:    {0}" -f $total)
}

function Compare-WithBaseline {
  param([string]$BaselinePath)
  $baseline = Get-Content -LiteralPath $BaselinePath -Raw -Encoding utf8 | ConvertFrom-Json

  $old = New-Object 'System.Collections.Generic.HashSet[string]'
  foreach ($rep in $baseline.reports) {
    foreach ($f in $rep.findings) {
      $payload = "{0}|{1}|{2}|{3}" -f $f.level, $f.category, $f.title, $f.message
      [void]$old.Add((Sha256Hex $payload))
    }
  }

  $new = New-Object 'System.Collections.Generic.HashSet[string]'
  foreach ($rep in $script:Reports) {
    foreach ($f in $rep.findings) {
      [void]$new.Add((Finding-Fingerprint $f))
    }
  }

  $added = 0
  foreach ($x in $new) { if (-not $old.Contains($x)) { $added++ } }
  $resolved = 0
  foreach ($x in $old) { if (-not $new.Contains($x)) { $resolved++ } }

  return @{ added = $added; resolved = $resolved }
}

function Export-Json {
  param([string]$Path)
  $counts = Severity-Counts
  $payload = [ordered]@{
    generated_at = (Get-Date).ToUniversalTime().ToString('o')
    tool = 'gpoaudit'
    summary = [ordered]@{
      counts = $counts
      total_findings = ($counts.Values | Measure-Object -Sum).Sum
    }
    reports = $script:Reports
  }
  $json = $payload | ConvertTo-Json -Depth 8
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
  Set-Content -LiteralPath $Path -Value $json -Encoding utf8
}

function Export-Csv {
  param([string]$Path)
  $rows = @()
  foreach ($rep in $script:Reports) {
    foreach ($f in $rep.findings) {
      $rows += [pscustomobject]@{
        gpo_name = $f.gpo_name
        source = $f.source
        input_file = $f.input_file
        level = $f.level
        category = $f.category
        title = $f.title
        message = $f.message
        context = $f.context
      }
    }
  }
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
  $rows | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding utf8
}

function Audit-Sids {
  param(
    [string]$Content,
    [hashtable]$ContextsBySid,
    [string[]]$OnlyTheseSids
  )

  Write-Host ""
  Write-Host "[Step 2] SID References:" -ForegroundColor White
  $sids = if ($OnlyTheseSids) { $OnlyTheseSids } else { Collect-Sids $Content }
  if (-not $sids -or $sids.Count -eq 0) {
    Write-Host "[+] No ghost/unresolved SIDs detected." -ForegroundColor Green
    Add-Finding -Level INFO -Category 'SIDs' -Title 'No ghost SIDs' -Message 'No ghost/unresolved SIDs detected.'
    return
  }

  foreach ($sid in $sids) {
    $ctx = $null
    if ($ContextsBySid -and $ContextsBySid.ContainsKey($sid) -and $ContextsBySid[$sid].Count -gt 0) {
      foreach ($c in $ContextsBySid[$sid] | Select-Object -First 3) {
        Write-Host ("       Context: {0}" -f $c)
      }
      $ctx = $ContextsBySid[$sid][0]
    } else {
      Write-Host "       Context: (could not extract a nearby setting/label)"
    }

    $level = 'HIGH'
    if ($ctx -and ($ctx.ToLower().Contains('edit, delete, modify security') -or $ctx.ToLower().Contains('full control') -or $ctx.ToLower().Contains('modify security') -or $ctx.ToLower().Contains('edit settings'))) {
      $level = 'CRITICAL'
    }

    $color = if ($level -eq 'CRITICAL') { 'Red' } else { 'Yellow' }
    Write-Host ("[{0}] Ghost/Unresolved SID found: {1}" -f $level, $sid) -ForegroundColor $color
    if ($level -eq 'CRITICAL') {
      Write-Host "       Risk: Orphaned security principal with administrative control."
    }

    Write-Host "       Action: Confirm this SID still exists; remove if orphaned."
    $isAdmin = ($level -eq 'CRITICAL')
    $title = if ($isAdmin) { 'Orphaned Security Principal with Administrative Control' } else { 'Ghost/Unresolved SID' }
    $category = if ($isAdmin) { 'Delegation' } else { 'SIDs' }
    $message = if ($isAdmin) { ("Unresolved SID {0} is granted administrative delegation permissions." -f $sid) } else { ("Ghost/Unresolved SID found: {0}" -f $sid) }
    Add-Finding -Level $level -Category $category -Title $title -Message $message -Context $ctx
  }
}

function Kerberos-LifetimeChecks {
  param([string]$Text)
  $baselines = @{ service_ticket = 600; user_ticket = 600; renewal = 10080; clock_skew = 5 }
  $patterns = @{
    service_ticket = [regex]'Maximum lifetime for service ticket\s*:?\s*(\d+)\s*(minutes|minute|hours|hour|days|day)'
    user_ticket    = [regex]'Maximum lifetime for user ticket\s*:?\s*(\d+)\s*(minutes|minute|hours|hour|days|day)'
    renewal        = [regex]'Maximum lifetime for user ticket renewal\s*:?\s*(\d+)\s*(minutes|minute|hours|hour|days|day)'
    clock_skew     = [regex]'Maximum tolerance for computer clock synchronization\s*:?\s*(\d+)\s*(minutes|minute|hours|hour)'
  }
  $labels = @{
    service_ticket = 'Maximum lifetime for service ticket'
    user_ticket    = 'Maximum lifetime for user ticket'
    renewal        = 'Maximum lifetime for user ticket renewal'
    clock_skew     = 'Maximum tolerance for computer clock synchronization'
  }

  $issues = 0
  foreach ($k in $patterns.Keys) {
    $m = $patterns[$k].Match($Text)
    if (-not $m.Success) { continue }
    $val = [int]$m.Groups[1].Value
    $unit = $m.Groups[2].Value
    $mins = Parse-DurationMinutes -Value $val -Unit $unit
    if ($null -eq $mins) { continue }

    $baseline = $baselines[$k]
    if ($mins -le $baseline) { continue }

    $level = if ($mins -le ($baseline * 2)) { 'MED' } else { 'HIGH' }
    $msg = "{0} is {1} {2} (baseline {3} minutes)." -f $labels[$k], $val, $unit, $baseline
    Write-Host ("[{0}] Kerberos policy: {1}" -f $level, $msg) -ForegroundColor Yellow
    Add-Finding -Level $level -Category 'Kerberos' -Title $labels[$k] -Message $msg
    $issues++
  }
  return $issues
}

function Audit-Hardening {
  param([string]$Text)

  Write-Host ""
  Write-Host "[Step 3] Hardening & Protocol Checks:" -ForegroundColor White

  $checks = @(
    @{ name='Firewall'; level='CRITICAL'; pattern=[regex]'Firewall state.*(Disabled|Off)'; msg='Windows Firewall is DISABLED.' },
    @{ name='WSUS HTTP'; level='CRITICAL'; pattern=[regex]'http://.*:8530'; msg='WSUS is using insecure HTTP (WSUSpect risk).' },
    @{ name='SMB Signing'; level='HIGH'; pattern=[regex]'Digitally sign communications.*Disabled'; msg='SMB Signing is DISABLED (Relay risk).' },
    @{ name='PS Logging'; level='HIGH'; pattern=[regex]'PowerShell Script Block Logging.*Disabled'; msg='PowerShell Audit Logging is DISABLED.' },
    @{ name='Anonymous SAM'; level='HIGH'; pattern=[regex]'Network access: Do not allow anonymous enumeration.*Disabled'; msg='Anonymous SAM enumeration allowed.' },
    @{ name='LAPS'; level='HIGH'; pattern=[regex]'LAPS.*Disabled'; msg='LAPS (Local Admin Passwords) appears DISABLED.' },
    @{ name='SSL/TLS'; level='CRITICAL'; pattern=[regex]'Use (SSL 3\.0|TLS 1\.0).*Enabled'; msg='Legacy/Crackable Encryption protocols enabled.' },

    @{ name='NTLMv1 allowed'; level='HIGH'; pattern=[regex]'LAN Manager authentication level.*(Send LM|LM\s*&\s*NTLM|NTLMv1|Send NTLM response only)'; msg='NTLMv1/LM responses appear allowed.' },
    @{ name='LDAP server signing'; level='HIGH'; pattern=[regex]'LDAP server signing requirements.*(None|Not required|Disabled|Off)'; msg='LDAP server signing is not required.' },
    @{ name='LDAP client signing'; level='MED'; pattern=[regex]'LDAP client signing requirements.*(None|Not required|Disabled|Off)'; msg='LDAP client signing is not required.' },
    @{ name='LDAP channel binding'; level='MED'; pattern=[regex]'LDAP server channel binding token requirements.*(Never|When supported|Disabled|Off)'; msg='LDAP channel binding appears not enforced.' },

    @{ name='Defender real-time off'; level='CRITICAL'; pattern=[regex]'Turn off real-time protection.*Enabled'; msg='Microsoft Defender real-time protection appears turned OFF.' },
    @{ name='ASR disabled'; level='MED'; pattern=[regex]'(Attack Surface Reduction|ASR).*(Disabled|Not configured)'; msg='ASR appears disabled or not configured.' },

    @{ name='WDigest UseLogonCredential'; level='CRITICAL'; pattern=[regex]'UseLogonCredential.*(1|Enabled|True)'; msg='WDigest UseLogonCredential appears enabled.' },
    @{ name='RunAsPPL off'; level='HIGH'; pattern=[regex]'(RunAsPPL|LSA protection).*(0|Disabled|Off)'; msg='LSA protection (RunAsPPL) appears disabled.' },
    @{ name='Credential Guard off'; level='MED'; pattern=[regex]'Credential Guard.*(Disabled|Off|Not enabled)'; msg='Credential Guard/VBS appears disabled.' }
  )

  $issues = 0
  foreach ($c in $checks) {
    if ($c.pattern.IsMatch($Text)) {
      $color = if ($c.level -eq 'CRITICAL') { 'Red' } else { 'Yellow' }
      Write-Host ("[{0}] {1}" -f $c.level, $c.msg) -ForegroundColor $color
      Add-Finding -Level $c.level -Category 'Hardening' -Title $c.name -Message $c.msg
      $issues++
    }
  }

  $issues += (Kerberos-LifetimeChecks -Text $Text)

  if ($issues -eq 0) {
    Write-Host "[+] All baseline security checks passed." -ForegroundColor Green
    Add-Finding -Level INFO -Category 'Hardening' -Title 'Baseline checks' -Message 'All baseline security checks passed.'
  }
}

function Get-XmlDisplayText {
  param([xml]$Doc)
  $nodes = $Doc.SelectNodes("//*[local-name()='Display']")
  $lines = @()
  foreach ($d in $nodes) {
    $n = $d.SelectSingleNode("./*[local-name()='Name']")
    $v = $d.SelectSingleNode("./*[local-name()='DisplayString']")
    if ($n -and $v -and $n.InnerText -and $v.InnerText) {
      $lines += ("{0}: {1}" -f ($n.InnerText.Trim()), ($v.InnerText.Trim()))
    }
  }
  return ($lines -join "`n")
}

function Extract-MetadataFromXml {
  param([xml]$Doc)
  $meta = @{}
  $meta.name = ($Doc.SelectSingleNode("//*[local-name()='GPO']/*[local-name()='Name']")?.InnerText)
  $meta.guid = ($Doc.SelectSingleNode("//*[local-name()='Identifier']/*[local-name()='Identifier']")?.InnerText)
  $meta.domain = ($Doc.SelectSingleNode("//*[local-name()='Identifier']/*[local-name()='Domain']")?.InnerText)
  $meta.created = ($Doc.SelectSingleNode("//*[local-name()='CreatedTime']")?.InnerText)
  $meta.modified = ($Doc.SelectSingleNode("//*[local-name()='ModifiedTime']")?.InnerText)
  $meta.owner = ($Doc.SelectSingleNode("//*[local-name()='Owner']//*[local-name()='Name'][1]")?.InnerText)
  $meta.wmi_filter = ($Doc.SelectSingleNode("//*[local-name()='WmiFilter']")?.InnerText)
  $meta.security_filtering = @()
  $meta.links = @()
  $meta.link_details = @()
  return $meta
}

function Extract-SecurityOptionsXml {
  param([xml]$Doc)
  $map = @{}
  $nodes = $Doc.SelectNodes("//*[local-name()='SecurityOptions']")
  foreach ($so in $nodes) {
    $k = $so.SelectSingleNode("./*[local-name()='KeyName']")
    $v = $so.SelectSingleNode("./*[local-name()='SettingNumber']")
    if (-not $v) { $v = $so.SelectSingleNode("./*[local-name()='SettingString']") }
    if (-not $v) { $v = $so.SelectSingleNode("./*[local-name()='SettingBoolean']") }
    if ($k -and $k.InnerText -and $v -and $v.InnerText) {
      $map[$k.InnerText.Trim()] = $v.InnerText.Trim()
    }
  }
  return $map
}

function Audit-SecurityOptionsXml {
  param([hashtable]$Opts)

  function Get-Int($Key) {
    if (-not $Opts.ContainsKey($Key)) { return $null }
    $raw = $Opts[$Key].Trim().Trim('"')
    try { return [int]$raw } catch { return $null }
  }

  $issues = 0

  $lm = Get-Int "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel"
  if ($null -ne $lm -and $lm -lt 5) {
    $msg = "LmCompatibilityLevel is $lm (recommend 5: NTLMv2 only; refuse LM/NTLM)."
    Write-Host "[HIGH] $msg" -ForegroundColor Yellow
    Add-Finding -Level HIGH -Category 'Hardening' -Title 'NTLM hardening' -Message $msg
    $issues++
  }

  $noLm = Get-Int "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\NoLMHash"
  if ($null -ne $noLm -and $noLm -eq 0) {
    $msg = "NoLMHash is 0 (LM hashes may be stored; should be 1)."
    Write-Host "[HIGH] $msg" -ForegroundColor Yellow
    Add-Finding -Level HIGH -Category 'Hardening' -Title 'LM hash storage' -Message $msg
    $issues++
  }

  $wd = Get-Int "MACHINE\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential"
  if ($null -ne $wd -and $wd -eq 1) {
    $msg = "WDigest UseLogonCredential is 1 (cleartext creds may be stored; should be 0)."
    Write-Host "[CRITICAL] $msg" -ForegroundColor Red
    Add-Finding -Level CRITICAL -Category 'Hardening' -Title 'WDigest' -Message $msg
    $issues++
  }

  $ppl = Get-Int "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RunAsPPL"
  if ($null -ne $ppl -and $ppl -eq 0) {
    $msg = "RunAsPPL is 0 (LSA protection off; consider enabling)."
    Write-Host "[HIGH] $msg" -ForegroundColor Yellow
    Add-Finding -Level HIGH -Category 'Hardening' -Title 'LSA protection' -Message $msg
    $issues++
  }

  $ldapSrv = Get-Int "MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\LDAPServerIntegrity"
  if ($null -ne $ldapSrv -and $ldapSrv -lt 2) {
    $msg = "LDAPServerIntegrity is $ldapSrv (recommend 2: require signing)."
    Write-Host "[HIGH] $msg" -ForegroundColor Yellow
    Add-Finding -Level HIGH -Category 'Hardening' -Title 'LDAP server signing' -Message $msg
    $issues++
  }

  $ldapCli = Get-Int "MACHINE\\System\\CurrentControlSet\\Services\\LDAP\\LDAPClientIntegrity"
  if ($null -ne $ldapCli -and $ldapCli -lt 2) {
    $msg = "LDAPClientIntegrity is $ldapCli (recommend 2: require signing)."
    Write-Host "[MED] $msg" -ForegroundColor Yellow
    Add-Finding -Level MED -Category 'Hardening' -Title 'LDAP client signing' -Message $msg
    $issues++
  }

  $cbt = Get-Int "MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\LdapEnforceChannelBinding"
  if ($null -ne $cbt -and $cbt -lt 2) {
    $msg = "LdapEnforceChannelBinding is $cbt (recommend 2: always enforce)."
    Write-Host "[MED] $msg" -ForegroundColor Yellow
    Add-Finding -Level MED -Category 'Hardening' -Title 'LDAP channel binding' -Message $msg
    $issues++
  }

  $disableRt = Get-Int "MACHINE\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring"
  if ($null -ne $disableRt -and $disableRt -eq 1) {
    $msg = "Defender policy disables real-time monitoring (DisableRealtimeMonitoring=1)."
    Write-Host "[CRITICAL] $msg" -ForegroundColor Red
    Add-Finding -Level CRITICAL -Category 'Hardening' -Title 'Defender real-time protection' -Message $msg
    $issues++
  }

  return $issues
}

function Audit-DelegationXml {
  param([xml]$Doc)

  Write-Host ""
  Write-Host "[Step 4] Delegation Audit:" -ForegroundColor White

  $pairs = @()
  $tps = $Doc.SelectNodes("//*[local-name()='TrusteePermissions']")
  foreach ($tp in $tps) {
    $trusteeName = $tp.SelectSingleNode("./*[local-name()='Trustee']/*[local-name()='Name']")?.InnerText
    $trusteeSid = $tp.SelectSingleNode("./*[local-name()='Trustee']/*[local-name()='SID']")?.InnerText
    $access = $tp.SelectSingleNode(".//*[local-name()='GPOGroupedAccessEnum']")?.InnerText
    if ($access) {
      $t = if ($trusteeName) { $trusteeName.Trim() } elseif ($trusteeSid) { $trusteeSid.Trim() } else { $null }
      if ($t) { $pairs += ,@($t, $access.Trim()) }
    }
  }

  if ($pairs.Count -eq 0) {
    Write-Host "[+] No Delegation entries found." -ForegroundColor Green
    Add-Finding -Level INFO -Category 'Delegation' -Title 'Delegation entries' -Message 'No Delegation entries found in the XML.'
    return
  }

  $riskyPrincipals = @('authenticated users','domain users','everyone','users')
  $riskyKeywords = @('edit settings','edit, delete, modify security','edit settings, delete, modify security','full control','modify security','write')

  foreach ($p in $pairs) {
    $trustee = $p[0]
    $perm = $p[1]

    $level = 'INFO'
    $tl = $trustee.ToLower()
    $pl = $perm.ToLower()

    $hasWrite = ($riskyKeywords | Where-Object { $pl.Contains($_) })
    $isSid = $SidRegex.IsMatch($trustee)

    if ($isSid -and $hasWrite) {
      $level = 'CRITICAL'
    } elseif ($isSid -or $tl.Contains('unknown')) {
      $level = 'HIGH'
    }

    if ($riskyPrincipals -contains $tl -and $hasWrite) { $level = 'CRITICAL' }
    elseif ($hasWrite -and $level -eq 'INFO') { $level = 'HIGH' }

    $color = if ($level -eq 'CRITICAL') { 'Red' } elseif ($level -eq 'HIGH') { 'Yellow' } else { 'Green' }
    $prefix = if ($level -eq 'CRITICAL') { '[!]' } elseif ($level -eq 'HIGH') { '[HIGH]' } else { '[+]' }
    $displayMsg = "{0}: {1}" -f $trustee, $perm
    Write-Host ("{0} {1}" -f $prefix, $displayMsg) -ForegroundColor $color

    $title = 'Delegation entry'
    $findingMessage = $displayMsg
    if ($isSid -and $hasWrite) {
      $title = 'Orphaned Security Principal with Administrative Control'
      $findingMessage = ("Unresolved SID {0} is granted administrative delegation permissions." -f $trustee)
    }

    Add-Finding -Level $level -Category 'Delegation' -Title $title -Message $findingMessage -Context $perm
  }
}

function Extract-SidContextsXml {
  param([xml]$Doc)
  $ctx = @{}

  $resolved = New-Object 'System.Collections.Generic.HashSet[string]'

  function AddCtx($Sid, $Text) {
    if (-not $Sid) { return }
    if (-not $ctx.ContainsKey($Sid)) { $ctx[$Sid] = New-Object System.Collections.Generic.List[string] }
    if (-not $ctx[$Sid].Contains($Text)) { $ctx[$Sid].Add($Text) }
  }

  $uras = $Doc.SelectNodes("//*[local-name()='UserRightsAssignment']")
  foreach ($ura in $uras) {
    $right = $ura.SelectSingleNode("./*[local-name()='Name']")?.InnerText
    if (-not $right) { continue }
    foreach ($mem in $ura.SelectNodes("./*[local-name()='Member']")) {
      $sid = $mem.SelectSingleNode("./*[local-name()='SID']")?.InnerText
      $name = $mem.SelectSingleNode("./*[local-name()='Name']")?.InnerText
      if ($sid) {
        $label = if ($name) { $name.Trim() } else { '(no name)' }
        AddCtx ($sid.Trim()) ("UserRightsAssignment {0}: {1} ({2})" -f $right.Trim(), $label, $sid.Trim())
        if ($name -and -not $SidRegex.IsMatch($name)) { [void]$resolved.Add($sid.Trim()) }
      }
    }
  }

  $tps = $Doc.SelectNodes("//*[local-name()='TrusteePermissions']")
  foreach ($tp in $tps) {
    $sid = $tp.SelectSingleNode("./*[local-name()='Trustee']/*[local-name()='SID']")?.InnerText
    $name = $tp.SelectSingleNode("./*[local-name()='Trustee']/*[local-name()='Name']")?.InnerText
    $access = $tp.SelectSingleNode(".//*[local-name()='GPOGroupedAccessEnum']")?.InnerText
    if ($sid -and ($name -or $access)) {
      AddCtx ($sid.Trim()) ("Delegation {0}: {1}" -f ($name ? $name.Trim() : $sid.Trim()), ($access ? $access.Trim() : '(unknown permission)'))
      if ($name -and -not $SidRegex.IsMatch($name)) { [void]$resolved.Add($sid.Trim()) }
    }
  }

  return @{ contexts = $ctx; resolved = $resolved }
}

function Audit-Xml {
  param([string]$Path)

  $raw = Read-TextFile -Path $Path
  [xml]$doc = $raw

  $meta = Extract-MetadataFromXml -Doc $doc
  $gpoName = if ($meta.name) { $meta.name } else { [IO.Path]::GetFileName($Path) }
  Start-Report -Source 'xml' -InputFile $Path -GpoName $gpoName -Metadata $meta

  Write-Banner -Name $gpoName

  $displayText = Get-XmlDisplayText -Doc $doc
  $combined = if ($displayText) { $raw + "`n" + $displayText } else { $raw }

  $sidInfo = Extract-SidContextsXml -Doc $doc
  $sidCtx = $sidInfo.contexts
  $resolved = $sidInfo.resolved
  $allSids = Collect-Sids $combined
  $ghostSids = @($allSids | Where-Object { -not $resolved.Contains($_) })
  Audit-Sids -Content $combined -ContextsBySid $sidCtx -OnlyTheseSids $ghostSids
  Audit-Hardening -Text $combined
  $opts = Extract-SecurityOptionsXml -Doc $doc
  if ($opts.Count -gt 0) {
    Audit-SecurityOptionsXml -Opts $opts | Out-Null
  }
  Audit-DelegationXml -Doc $doc
}

function Audit-Html {
  param([string]$Path)

  $raw = Read-TextFile -Path $Path
  $name = $null
  if ($raw -match '<title>([^<]+)</title>') { $name = $Matches[1].Trim() }
  if (-not $name) { $name = [IO.Path]::GetFileName($Path) }

  $meta = @{ name = $name; guid = $null; domain = $null; created = $null; modified = $null; owner = $null; wmi_filter = $null; security_filtering = @(); links = @(); link_details = @() }
  Start-Report -Source 'html' -InputFile $Path -GpoName $name -Metadata $meta

  Write-Banner -Name $name

  Write-Host ""; Write-Host "[Step 1] Linkage Status:" -ForegroundColor White
  if ($raw -notmatch 'Links') {
    Write-Host "[!] CRITICAL: This GPO is NOT linked to any OU. It is DORMANT." -ForegroundColor Red
    Add-Finding -Level CRITICAL -Category 'Linkage' -Title 'GPO not linked' -Message 'This GPO is NOT linked to any OU (dormant).'
  } else {
    $ous = [regex]::Matches($raw, 'OU=[^<\r\n]+', 'IgnoreCase') | ForEach-Object { $_.Value } | Sort-Object -Unique
    if ($ous.Count -eq 0) {
      Write-Host "[!] CRITICAL: This GPO is NOT linked to any OU. It is DORMANT." -ForegroundColor Red
      Add-Finding -Level CRITICAL -Category 'Linkage' -Title 'GPO not linked' -Message 'This GPO is NOT linked to any OU (dormant).'
    } else {
      foreach ($ou in $ous) {
        Write-Host "[+] Active Link found: $ou" -ForegroundColor Green
        Add-Finding -Level INFO -Category 'Linkage' -Title 'Active link' -Message ("Active link found: {0}" -f $ou) -Context $ou
      }
    }
  }

  Audit-Sids -Content $raw -ContextsBySid @{}
  Audit-Hardening -Text $raw

  Write-Host ""; Write-Host "[Step 4] Delegation Audit:" -ForegroundColor White
  if ($raw -match 'Delegation') {
    Write-Host "[+] Delegation section present (HTML parsing is best-effort)." -ForegroundColor Green
    Add-Finding -Level INFO -Category 'Delegation' -Title 'Delegation section' -Message 'Delegation section present in HTML (best-effort parsing).'
  } else {
    Write-Host "[+] No Delegation section found." -ForegroundColor Green
    Add-Finding -Level INFO -Category 'Delegation' -Title 'Delegation section' -Message 'No Delegation section found in the report.'
  }
}

if ($Help -or ($args -contains '--help')) {
  Get-Help -Detailed $MyInvocation.MyCommand.Path
  exit 0
}

if (-not $Html -and -not $Xml) {
  Get-Help -Detailed $MyInvocation.MyCommand.Path
  exit 2
}

if ($Html) {
  if (-not (Test-Path -LiteralPath $Html -PathType Leaf)) { throw "Input error: $Html" }
  Audit-Html -Path $Html
}
if ($Xml) {
  if (-not (Test-Path -LiteralPath $Xml -PathType Leaf)) { throw "Input error: $Xml" }
  Audit-Xml -Path $Xml
}

Print-Summary

if ($Baseline) {
  try {
    $drift = Compare-WithBaseline -BaselinePath $Baseline
    Write-Host ""; Write-Host "[Drift] Baseline comparison:" -ForegroundColor White
    Write-Host ("  New findings:      {0}" -f $drift.added)
    Write-Host ("  Resolved findings: {0}" -f $drift.resolved)
  } catch {
    Write-Host "[!] Baseline compare error: $($_.Exception.Message)" -ForegroundColor Red
  }
}

if ($JsonOut) {
  try {
    Export-Json -Path $JsonOut
    Write-Host "[+] Wrote JSON: $JsonOut" -ForegroundColor Green
  } catch {
    Write-Host "[!] JSON export error: $($_.Exception.Message)" -ForegroundColor Red
  }
}

if ($CsvOut) {
  try {
    Export-Csv -Path $CsvOut
    Write-Host "[+] Wrote CSV: $CsvOut" -ForegroundColor Green
  } catch {
    Write-Host "[!] CSV export error: $($_.Exception.Message)" -ForegroundColor Red
  }
}
