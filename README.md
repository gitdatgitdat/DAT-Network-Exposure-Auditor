# Network Exposure Auditor

PowerShell scanner that checks hosts for risky exposed services and weak TLS.  

---

# What it does

- Scans a host list or explicit names for ports (default: `22,80,443,445,3389,5985,5986`)  
- Enrichment  
  - **HTTP/HTTPS**: banner (Server/X-Powered-By), TLS version, cert issuer/expiry, hostname match  
  - **SSH**: server banner  
- Policy (built-in)  
  - RDP **3389** → High (NonCompliant)  
  - SMB **445** → High (NonCompliant)  
  - WinRM **5985** → Medium (NonCompliant)  
  - WinRM **5986** → Low (Warn)  
  - HTTPS: **TLS < 1.2**, **expired cert**, **≤30d to expiry**, **hostname mismatch** → flagged  
- Outputs: **table preview + JSON/CSV**, with exit codes for CI  

---

# Quick start  

Set-ExecutionPolicy -Scope Process RemoteSigned  

# Single host  

.\Get-NetworkExposure.ps1 -ComputerName example.com -Ports 80,443 -Json out.json -Csv out.csv  

From CSV  
samples\targets.csv  
ComputerName  
web1.contoso.com  
192.168.1.10  

.\Get-NetworkExposure.ps1 -TargetsCsv .\samples\targets.csv -Json fleet.json -Csv fleet.csv  

---

# Parameters

-ComputerName <string[]>   | One or more targets  
-TargetsCsv <path>         | CSV with a column named ComputerName (or your own; import yourself for now)  
-Ports <int[]>             | Defaults: 22,80,443,445,3389,5985,5986  
-Json <path>               | Write JSON  
-Csv <path>                | Write CSV  
-TimeoutMs <int>           | TCP/TLS timeouts (default 1500)  
-ThrottleLimit <int>       | Parallel target scans on PowerShell 7+ (default 32)
-Policy <path>             | JSON policy file (ports/TLS/overrides)

---

# Output Schema (per row)

Host, Port, Service (http|https|ssh|smb|rdp|winrm-http|winrm-https|tcp)

Open (True/False)

Banner (HTTP/SSH when present)

TlsVersion, CertIssuer, NotAfter, DaysToExpiry, HostnameOK (for HTTPS)

Compliance (Compliant|NonCompliant)

Severity (Info|Low|Medium|High)

Reasons (semicolon-separated)

CollectedAt (UTC)

---

# Custom Policy File

You can tune severities and TLS rules globally, and override per host with a policy.json file. For example:

{
  "ports": { "3389": "High", "445": "High", "5985": "Medium", "5986": "Low" },
  "tls":   { "minVersion": "Tls12", "expiryDaysWarn": 30, "requireHostnameMatch": true, "handshakeFailure": "High" },
  "overrides": {
    "intranet-gw": { "ports": { "3389": "Medium" } },
    "legacy.example.com": { "tls": { "minVersion": "Tls11" } }
  }
}

Use: .\Get-NetworkExposure.ps1 -ComputerName web1,web2 -Policy .\policy.json -Json out.json

---

# Parallel scanning (PS7+)

On PowerShell 7+, targets are scanned in parallel (controlled by -ThrottleLimit).
Windows PowerShell 5.1 runs sequentially.

For example:

Two hosts, custom policy, CSV too:  
.\Get-NetworkExposure.ps1 -ComputerName example.com,10.0.0.5 -Policy .\policy.json -Json out.json -Csv out.csv

From CSV:  
.\Get-NetworkExposure.ps1 -TargetsCsv .\samples\targets.csv -Json fleet.json

---

# Exit codes

0 – No Medium/High findings

1 – Any Medium/High finding (NonCompliant)

2 – Reserved for future hard errors

---

# Examples

Scan default ports for two hosts

.\Get-NetworkExposure.ps1 -ComputerName web1,web2

Scan just 80/443 with longer timeouts

.\Get-NetworkExposure.ps1 -TargetsCsv .\targets.csv -Ports 80,443 -TimeoutMs 3000 -Json web.json

---

# Notes & tips

Run from a network location that can reach the targets (no special privileges required).

If a TLS handshake fails on 443, it is flagged as High (“TLS handshake failed”).

CSV import is minimal by design (expects ComputerName). Adjust as needed for your environment.
