[CmdletBinding()]
param(
  [string[]]$ComputerName, [string]$TargetsCsv,
  [int[]]$Ports = @(22,80,443,445,3389,5985,5986),
  [string]$Json, [string]$Csv, [int]$TimeoutMs = 1500,
  [int]$ThrottleLimit = 32,
  [string]$Policy
)

# TCP Reachability
function Test-TcpOpen {
  param([string]$Target,[int]$Port,[int]$TimeoutMs=1500)
  $client = [System.Net.Sockets.TcpClient]::new()
  $task = $client.ConnectAsync($Target,$Port)
  if (-not $task.Wait($TimeoutMs)) { $client.Dispose(); return @{Open=$false;Err='timeout'} }
  if (-not $client.Connected)      { $client.Dispose(); return @{Open=$false;Err='connect'} }
  @{ Open=$true; Client=$client }
}

# TLS Probe
function Get-TlsInfo {
  param([string]$Target,[int]$Port=443,[System.Net.Sockets.TcpClient]$Client)
  try {
    $ns = $Client.GetStream()
    $ssl = [System.Net.Security.SslStream]::new($ns,$false,({$true}))
    $ssl.AuthenticateAsClient($Target)  # SNI
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $ssl.RemoteCertificate
    [pscustomobject]@{
      TlsVersion   = $ssl.SslProtocol.ToString()
      CertSubject  = $cert.Subject
      CertIssuer   = $cert.Issuer
      NotAfter     = $cert.NotAfter.ToUniversalTime()
      DaysToExpiry = [int]([datetime]::UtcNow - $cert.NotAfter.ToUniversalTime()).TotalDays * -1
      HostnameOK   = ($cert.GetNameInfo('DnsName',$false) -eq $Target) -or ($cert.Subject -match [regex]::Escape($Target))
    }
  } catch {
    [pscustomobject]@{ TlsVersion=$null; CertSubject=$null; CertIssuer=$null; NotAfter=$null; DaysToExpiry=$null; HostnameOK=$false; Error=$_.Exception.Message }
  } finally { if ($ssl) { $ssl.Dispose() } }
}

# HTTP Banner Grab
function Get-HttpBanner {
  param([string]$Target,[int]$Port)
  try {
    $tcp = Test-TcpOpen $Target $Port 1200
    if (-not $tcp.Open) { return $null }
    $stream = $tcp.Client.GetStream()
    $stream.ReadTimeout = 1200
    $req = "HEAD / HTTP/1.1`r`nHost: $Target`r`nConnection: close`r`n`r`n"
    $buf = [Text.Encoding]::ASCII.GetBytes($req); $stream.Write($buf,0,$buf.Length)
    $r = New-Object IO.StreamReader($stream)
    $head = $r.ReadToEnd()
    $r.Dispose()
    return (($head -split "`r`n") | Where-Object { $_ -match '^(Server:|X-Powered-By:)' } | -join ' ')
  } catch { $null } finally { if ($tcp.Client) { $tcp.Client.Dispose() } }
}

# SSH Banner Grab
function Get-SshBanner {
  param([string]$Target,[int]$Port=22)
  try {
    $tcp = Test-TcpOpen $Target $Port 1200
    if (-not $tcp.Open) { return $null }
    $stream = $tcp.Client.GetStream()
    $buf = New-Object byte[] 256
    $stream.ReadTimeout = 1200
    $read = $stream.Read($buf,0,$buf.Length)
    ([Text.Encoding]::ASCII.GetString($buf,0,$read)).Trim()
  } catch { $null } finally { if ($tcp.Client) { $tcp.Client.Dispose() } }
}

function Get-Policy {
  param([string]$Path)

  # defaults
  $p = @{
    ports = @{ '3389'='High'; '445'='High'; '5985'='Medium'; '5986'='Low' }
    tls   = @{ minVersion='Tls12'; expiryDaysWarn=30; requireHostnameMatch=$true; handshakeFailure='High' }
    overrides = @{}
  }

  if ($Path) {
    if (-not (Test-Path -LiteralPath $Path)) { throw "Policy not found: $Path" }
    $raw = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json -Depth 5
    if ($raw.ports)     { $p.ports     = @{} + $p.ports + $raw.ports }          # merge
    if ($raw.tls)       { $p.tls       = @{} + $p.tls   + $raw.tls }
    if ($raw.overrides) { $p.overrides = @{} + $raw.overrides }
  }
  return $p
}

# Policy Eval
function Evaluate-Exposure {
  param(
    [string]$Target,[int]$Port,[bool]$Open,[string]$Service,[object]$Tls,[string]$Banner,[hashtable]$Policy  
  )
  $sev='Info'; $reasons=@()
  if (-not $Open) { return @{ Compliance='Compliant'; Severity='Info'; Reasons='' } }

  $portKey = [string]$Port
  if ($Policy.ports.ContainsKey($portKey)) {
    $sev = $Policy.ports[$portKey]
    switch ($portKey) {
        '3389' { $reasons += 'RDP exposed' }
        '445'  { $reasons += 'SMB exposed' }
        '5985' { $reasons += 'WinRM HTTP exposed' }
        '5986' { $reasons += 'WinRM HTTPS exposed' }
        default { }
    }
  }

  # TLS policy
  if ($Service -eq 'https') {
    $min = $Policy.tls.minVersion
    $warnDays = [int]$Policy.tls.expiryDaysWarn
    $reqHost  = [bool]$Policy.tls.requireHostnameMatch
    $hsFailSev = $Policy.tls.handshakeFailure

    if (-not $Tls -or -not $Tls.TlsVersion) {
      $sev = $hsFailSev; $reasons += 'TLS handshake failed'
    } else {
      # version compare: treat not-in list as below min
      if ($Tls.TlsVersion -notin 'Tls10','Tls11','Tls12','Tls13') { $verRank = 0 }
      else {
        $rank = @{ Tls10=1; Tls11=2; Tls12=3; Tls13=4 }
        $verRank = $rank[$Tls.TlsVersion]; $minRank = $rank[$min]
        if ($verRank -lt $minRank) { $sev='High'; $reasons+='TLS below minimum' }
      }
      if ($Tls.DaysToExpiry -lt 0) { $sev='High'; $reasons+='Cert expired' }
      elseif ($Tls.DaysToExpiry -le $warnDays -and $sev -ne 'High') {
        $sev='Medium'; $reasons+="Cert expires in $($Tls.DaysToExpiry)d"
      }
      if ($reqHost -and -not $Tls.HostnameOK -and $sev -ne 'High') {
        $sev='Medium'; $reasons+='Hostname mismatch'
      }
    }
  }

  $comp = if ($sev -in 'High','Medium') { 'NonCompliant' } else { 'Compliant' }
  @{ Compliance=$comp; Severity=$sev; Reasons=($reasons -join '; ') }
}

# Host Scan
function Invoke-ScanHost {
  param([string]$Target,[int[]]$Ports,[int]$TimeoutMs=1500,[hashtable]$Policy)
  $eff = $Policy
  if ($Policy.overrides.ContainsKey($Target)) {
    $ov = $Policy.overrides[$Target]
    $ovPorts = if ($ov.ports) { $ov.ports } else { @{} }
    $ovTls   = if ($ov.tls)   { $ov.tls }   else { @{} }
    $eff = @{
        ports = @{} + $Policy.ports + $ovPorts
        tls   = @{} + $Policy.tls   + $ovTls
        overrides = $Policy.overrides
    }
  }

  $rows=@()
  foreach ($p in $Ports) {
    $tcp = Test-TcpOpen $Target $p $TimeoutMs
    $open=$tcp.Open; $banner=$null; $tls=$null; $svc=$null
    if ($open) {
      switch ($p) {
        80   { $svc='http';  $banner = Get-HttpBanner $Target 80 }
        443  { $svc='https'; $tls = Get-TlsInfo -Target $Target -Port 443 -Client $tcp.Client; if ($tcp.Client){ $tcp.Client.Dispose() } }
        22   { $svc='ssh';   $banner = Get-SshBanner $Target 22 }
        445  { $svc='smb' }
        3389 { $svc='rdp' }
        5985 { $svc='winrm-http' }
        5986 { $svc='winrm-https' }
        default { $svc='tcp' }
      }
      if ($p -ne 443 -and $tcp.Client) { $tcp.Client.Dispose() }
    }

    $eval = Evaluate-Exposure -Target $Target -Port $p -Open:$open -Service $svc -Tls $tls -Banner $banner -Policy $eff


    $tlv = if ($tls) { $tls.TlsVersion } else { $null }
    $iss = if ($tls) { $tls.CertIssuer } else { $null }
    $na  = if ($tls) { $tls.NotAfter } else { $null }
    $dte = if ($tls) { $tls.DaysToExpiry } else { $null }
    $hOk = if ($tls) { $tls.HostnameOK } else { $null }

    $rows += [pscustomobject]@{
      Host=$Target; Port=$p; Service=$svc; Open=$open; Banner=$banner
      TlsVersion=$tlv; CertIssuer=$iss; NotAfter=$na; DaysToExpiry=$dte; HostnameOK=$hOk
      Compliance=$eval.Compliance; Severity=$eval.Severity; Reasons=$eval.Reasons; CollectedAt=[datetime]::UtcNow
    }
  }
  $rows
}

# Main
$targets = @()
$policy = Get-Policy -Path $Policy
if ($TargetsCsv) { $targets += (Import-Csv $TargetsCsv).ComputerName }
if ($ComputerName) { $targets += $ComputerName }
$targets = $targets | Sort-Object -Unique
if (-not $targets) { throw "No targets." }

if ($PSVersionTable.PSVersion.Major -ge 7) {
  $all = $targets | ForEach-Object -Parallel {
  & $using:function:Invoke-ScanHost -Target $_ -Ports $using:Ports -TimeoutMs $using:TimeoutMs -Policy $using:policy
  } -ThrottleLimit $ThrottleLimit
  $all = $all | ForEach-Object { $_ } | Where-Object { $_ }

} else {
  $all = foreach ($h in $targets) {
    Invoke-ScanHost -Target $h -Ports $Ports -TimeoutMs $TimeoutMs -Policy $policy
  }
}

$all | Format-Table Host,Port,Service,Open,Severity,Reasons -AutoSize
if ($Json) { $all | ConvertTo-Json -Depth 5 | Out-File -Encoding utf8 $Json }
if ($Csv)  { $all | Export-Csv -NoTypeInformation -Encoding UTF8 $Csv }

if ($all | ? { $_.Severity -in 'High','Medium' }) { exit 1 } else { exit 0 }