[CmdletBinding()]
param(
  [Parameter(Mandatory)][string[]]$InputPath,
  [string]$OutHtml = ".\reports\NetworkExposure.html",
  [switch]$Open
)

function Read-Rows {
  $files = foreach ($p in $InputPath) { Get-ChildItem -Path $p -File -ErrorAction Stop }
  $rows = @()
  foreach ($f in $files) {
    if ($f.Extension -match 'json') { $rows += @(Get-Content -Raw $f.FullName | ConvertFrom-Json) }
    elseif ($f.Extension -match 'csv') { $rows += @(Import-Csv $f.FullName) }
  }
  # normalize CollectedAt
  foreach ($r in $rows) {
    if ($r.CollectedAt -and -not ($r.CollectedAt -is [datetime])) { $r.CollectedAt = [datetime]$r.CollectedAt }
  }
  # latest per Host+Port
  $rows | Group-Object { "$($_.Host)|$($_.Port)" } | ForEach-Object {
    $_.Group | Sort-Object CollectedAt -Descending | Select-Object -First 1
  }
}

function H([string]$s){ if($null -eq $s){''}else{$s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;'} }

$data = Read-Rows
$rows = foreach ($r in ($data | Sort-Object Host,Port)) {
  $sevClass = switch ($r.Severity) { 'High'{'sev-high'} 'Medium'{'sev-med'} 'Low'{'sev-low'} default{'sev-info'} }
@"
<tr class="$sevClass">
  <td>$(H $r.Host)</td>
  <td class="t-right">$(H $r.Port)</td>
  <td>$(H $r.Service)</td>
  <td class="status"><span class="dot"></span>$(H $r.Severity)</td>
  <td>$(H $r.Compliance)</td>
  <td>$(H $r.Banner)</td>
  <td>$(H $r.TlsVersion)</td>
  <td>$(H $r.CertIssuer)</td>
  <td>$(H $r.NotAfter)</td>
  <td>$(H $r.DaysToExpiry)</td>
  <td>$(H $r.Reasons)</td>
  <td>$(H ($r.CollectedAt))</td>
</tr>
"@
}

$html = @"
<!doctype html><meta charset="utf-8"><title>Network Exposure</title>
<style>
:root{--hi:#ef4444;--md:#f59e0b;--lo:#10b981;--info:#94a3b8;--muted:#6b7280}
body{font-family:ui-sans-serif,Segoe UI,Roboto,Arial;margin:24px}
h1{margin:0 0 6px;font-size:22px} .sub{color:var(--muted);margin-bottom:12px}
table{width:100%;border-collapse:collapse} th,td{padding:10px 8px;border-bottom:1px solid #e5e7eb}
tr:nth-child(even){background:#f9fafb} th{cursor:pointer;user-select:none}
.status{font-weight:600}.t-right{text-align:right}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px;vertical-align:middle}
.sev-high .dot{background:var(--hi)} .sev-med .dot{background:var(--md)}
.sev-low .dot{background:var(--lo)} .sev-info .dot{background:var(--info)}
#legend span{display:inline-flex;align-items:center;margin-right:14px}
#legend .chip{width:10px;height:10px;border-radius:50%;display:inline-block;margin-right:6px}
#legend .hi{background:var(--hi)} .md{background:var(--md)} .lo{background:var(--lo)} .info{background:var(--info)}
</style>
<h1>Network Exposure</h1>
<div class="sub">Generated $(Get-Date) · Click table headers to sort</div>
<div id="legend"><span><i class="chip hi"></i>High</span><span><i class="chip md"></i>Medium</span><span><i class="chip lo"></i>Low</span><span><i class="chip info"></i>Info</span></div>
<table id="t"><thead>
<tr>
  <th>Host</th><th>Port</th><th>Service</th><th>Severity</th><th>Compliance</th>
  <th>Banner</th><th>TLS</th><th>Issuer</th><th>NotAfter</th><th>Days</th><th>Reasons</th><th>Collected</th>
</tr></thead><tbody>
$($rows -join "")
</tbody></table>
<script>
(function(){
  const table=document.getElementById('t');
  const getVal=(td)=>td.innerText||td.textContent;
  const cmp=(a,b,dir,idx,isNum)=>{const va=getVal(a.children[idx]), vb=getVal(b.children[idx]);
    const na=isNum?parseFloat(va)||-1:va.toLowerCase(), nb=isNum?parseFloat(vb)||-1:vb.toLowerCase();
    return (na>nb?1:na<nb?-1:0)*(dir?1:-1);};
  table.querySelectorAll('th').forEach((th,idx)=>{
    th.addEventListener('click',()=>{
      const tbody=table.tBodies[0], rows=[...tbody.rows];
      const isNum = ['Port','Days'].includes(th.textContent.trim());
      const dir = !th._dir; th._dir=dir;
      rows.sort((r1,r2)=>cmp(r1,r2,dir,idx,isNum));
      rows.forEach(r=>tbody.appendChild(r));
    });
  });
})();
</script>
"@
$dir = Split-Path -Parent $OutHtml
if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
$html | Out-File -Encoding utf8 $OutHtml
Write-Host "[OK] Wrote HTML -> $OutHtml"
if ($Open){ Start-Process $OutHtml | Out-Null }
