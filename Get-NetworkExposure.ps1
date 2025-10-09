[CmdletBinding()]
param(
  [string[]]$ComputerName, [string]$TargetsCsv,
  [int[]]$Ports = @(22,80,443,445,3389,5985,5986),
  [string]$Json, [string]$Csv, [int]$TimeoutMs = 1500
  [int]$ThrottleLimit = 32
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
    $r = New-Object IO.StreamReader($stream); $head = $r.ReadToEnd()
    $head = $r.ReadToEnd()
    $r.Dispose()
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

# Policy Eval
function Evaluate-Exposure {
  param(
    [string]$Target,[int]$Port,[bool]$Open,[string]$Service,[object]$Tls,[string]$Banner
  )
  $sev='Info'; $reasons=@()
  if (-not $Open) { return @{ Compliance='Compliant'; Severity='Info'; Reasons='' } }

  switch ($Port) {
    3389 { $sev='High';   $reasons+='RDP exposed' }
    445  { $sev='High';   $reasons+='SMB exposed' }
    5985 { $sev='Medium'; $reasons+='WinRM HTTP exposed' }
    5986 { $sev='Low';    $reasons+='WinRM HTTPS exposed' }
    default {}
  }

  if ($Service -eq 'https') {
    if (-not $Tls -or -not $Tls.TlsVersion) {
      $sev='High'; $reasons+='TLS handshake failed'
    } else {
      if ($Tls.TlsVersion -notin 'Tls12','Tls13') { $sev='High'; $reasons+='TLS < 1.2' }
      if ($Tls.DaysToExpiry -lt 0)                { $sev='High'; $reasons+='Cert expired' }
      elseif ($Tls.DaysToExpiry -le 30)           { if ($sev -ne 'High'){$sev='Medium'}; $reasons+="Cert expires in $($Tls.DaysToExpiry)d" }
      if (-not $Tls.HostnameOK)                   { if ($sev -ne 'High'){$sev='Medium'}; $reasons+='Hostname mismatch' }
    }
  }

  $comp = if ($sev -in 'High','Medium') { 'NonCompliant' } else { 'Compliant' }
  @{ Compliance=$comp; Severity=$sev; Reasons=($reasons -join '; ') }
}

# Host Scan
function Invoke-ScanHost {
  param([string]$Target,[int[]]$Ports,[int]$TimeoutMs=1500)
  $rows=@()
  foreach ($p in $Ports) {
    $tcp = Test-TcpOpen $Target $p $TimeoutMs
    $open = $tcp.Open
    $banner=$null; $tls=$null; $svc=$null
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
    $eval = Evaluate-Exposure -Target $Target -Port $p -Open:$open -Service $svc -Tls $tls -Banner $banner

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
if ($TargetsCsv) { $targets += (Import-Csv $TargetsCsv).ComputerName }
if ($ComputerName) { $targets += $ComputerName }
$targets = $targets | Sort-Object -Unique
if (-not $targets) { throw "No targets." }

if ($PSVersionTable.PSVersion.Major -ge 7) {
  $all = $targets | ForEach-Object -Parallel {
    & $using:function:Invoke-ScanHost -Target $_ -Ports $using:Ports -TimeoutMs $using:TimeoutMs
  } -ThrottleLimit $ThrottleLimit

  $all = $all | ForEach-Object { $_ }
} else {
  $all = foreach ($h in $targets) {
    Invoke-ScanHost -Target $h -Ports $Ports -TimeoutMs $TimeoutMs
  }
}

$all | Format-Table Host,Port,Service,Open,Severity,Reasons -AutoSize
if ($Json) { $all | ConvertTo-Json -Depth 5 | Out-File -Encoding utf8 $Json }
if ($Csv)  { $all | Export-Csv -NoTypeInformation -Encoding UTF8 $Csv }

if ($all | ? { $_.Severity -in 'High','Medium' }) { exit 1 } else { exit 0 }