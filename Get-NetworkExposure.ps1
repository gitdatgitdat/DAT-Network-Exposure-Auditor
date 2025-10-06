function Test-TcpOpen {
  param([string]$Host,[int]$Port,[int]$TimeoutMs=1500)
  $client = [System.Net.Sockets.TcpClient]::new()
  $task = $client.ConnectAsync($Host,$Port)
  if (-not $task.Wait($TimeoutMs)) { $client.Dispose(); return @{Open=$false;Err='timeout'} }
  if (-not $client.Connected)      { $client.Dispose(); return @{Open=$false;Err='connect'} }
  @{ Open=$true; Client=$client }
}

function Get-TlsInfo {
  param([string]$Host,[int]$Port=443,[System.Net.Sockets.TcpClient]$Client)
  try {
    $ns = $Client.GetStream()
    $ssl = [System.Net.Security.SslStream]::new($ns,$false,({$true}))
    $ssl.AuthenticateAsClient($Host)  # SNI
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $ssl.RemoteCertificate
    [pscustomobject]@{
      TlsVersion   = $ssl.SslProtocol.ToString()
      CertSubject  = $cert.Subject
      CertIssuer   = $cert.Issuer
      NotAfter     = $cert.NotAfter.ToUniversalTime()
      DaysToExpiry = [int]([datetime]::UtcNow - $cert.NotAfter.ToUniversalTime()).TotalDays * -1
      HostnameOK   = ($cert.GetNameInfo('DnsName',$false) -eq $Host) -or ($cert.Subject -match [regex]::Escape($Host))
    }
  } catch {
    [pscustomobject]@{ TlsVersion=$null; CertSubject=$null; CertIssuer=$null; NotAfter=$null; DaysToExpiry=$null; HostnameOK=$false; Error=$_.Exception.Message }
  } finally { if ($ssl) { $ssl.Dispose() } }
}

function Get-HttpBanner {
  param([string]$Host,[int]$Port)
  try {
    $tcp = Test-TcpOpen $Host $Port 1200
    if (-not $tcp.Open) { return $null }
    $stream = $tcp.Client.GetStream()
    $req = "HEAD / HTTP/1.1`r`nHost: $Host`r`nConnection: close`r`n`r`n"
    $buf = [Text.Encoding]::ASCII.GetBytes($req); $stream.Write($buf,0,$buf.Length)
    $r = New-Object IO.StreamReader($stream); $head = $r.ReadToEnd()
    ($head -split "`r`n") | Where-Object {$_ -match '^(Server:|X-Powered-By:)'} | -join ' '
  } catch { $null } finally { if ($tcp.Client) { $tcp.Client.Dispose() } }
}

function Get-SshBanner {
  param([string]$Host,[int]$Port=22)
  try {
    $tcp = Test-TcpOpen $Host $Port 1200
    if (-not $tcp.Open) { return $null }
    $stream = $tcp.Client.GetStream()
    $buf = New-Object byte[] 256
    $stream.ReadTimeout = 1200
    $read = $stream.Read($buf,0,$buf.Length)
    ([Text.Encoding]::ASCII.GetString($buf,0,$read)).Trim()
  } catch { $null } finally { if ($tcp.Client) { $tcp.Client.Dispose() } }
}

function Evaluate-Exposure {
  param(
    [string]$Host,[int]$Port,[bool]$Open,[string]$Service,[object]$Tls,[string]$Banner
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

  if ($Service -eq 'https' -and $Tls) {
    if ($Tls.TlsVersion -notin 'Tls12','Tls13') { $sev='High';   $reasons+='TLS < 1.2' }
    if ($Tls.DaysToExpiry -lt 0)                { $sev='High';   $reasons+='Cert expired' }
    elseif ($Tls.DaysToExpiry -le 30)           { if ($sev -ne 'High'){$sev='Medium'}; $reasons+="Cert expires in $($Tls.DaysToExpiry)d" }
    if (-not $Tls.HostnameOK)                   { if ($sev -ne 'High'){$sev='Medium'}; $reasons+='Hostname mismatch' }
  }

  $comp = if ($sev -in 'High','Medium') { 'NonCompliant' } else { 'Compliant' }
  @{ Compliance=$comp; Severity=$sev; Reasons=($reasons -join '; ') }
}

function Invoke-ScanHost {
  param([string]$Host,[int[]]$Ports,[int]$TimeoutMs=1500)
  $rows=@()
  foreach ($p in $Ports) {
    $tcp = Test-TcpOpen $Host $p $TimeoutMs
    $open = $tcp.Open
    $banner=$null; $tls=$null; $svc=$null
    if ($open) {
      switch ($p) {
        80   { $svc='http';  $banner = Get-HttpBanner $Host 80 }
        443  { $svc='https'; $banner = Get-HttpBanner $Host 443; $tls = Get-TlsInfo -Host $Host -Port 443 -Client $tcp.Client }
        22   { $svc='ssh';   $banner = Get-SshBanner $Host 22 }
        default { $svc='tcp' }
      }
      if ($p -ne 443 -and $tcp.Client) { $tcp.Client.Dispose() }
    }
    $eval = Evaluate-Exposure -Host $Host -Port $p -Open:$open -Service $svc -Tls $tls -Banner $banner
    $rows += [pscustomobject]@{
      Host=$Host; Port=$p; Service=$svc; Open=$open; Banner=$banner
      TlsVersion=$tls?.TlsVersion; CertIssuer=$tls?.CertIssuer; NotAfter=$tls?.NotAfter; DaysToExpiry=$tls?.DaysToExpiry; HostnameOK=$tls?.HostnameOK
      Compliance=$eval.Compliance; Severity=$eval.Severity; Reasons=$eval.Reasons; CollectedAt=[datetime]::UtcNow
    }
  }
  $rows
}
