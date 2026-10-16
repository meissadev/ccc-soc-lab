# DC01 (lab Splunk) : Universal Forwarder vers SPLUNK-01 (Sysmon, Securite, surveillance de fichiers, YARA).
$ErrorActionPreference = "Stop"
$Splunk = "10.20.40.11:9997"
$V = "10.6.0.5"; $B = "86587d4e3b27"

# 1. L'agent Wazuh n'a pas de gestionnaire dans ce lab
Stop-Service WazuhSvc -ErrorAction SilentlyContinue
Set-Service WazuhSvc -StartupType Disabled -ErrorAction SilentlyContinue

# 2. Universal Forwarder
$msi = "C:\ccc\splunkforwarder.msi"
if (-not (Test-Path $msi)) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Invoke-WebRequest -UseBasicParsing -Uri "https://download.splunk.com/products/universalforwarder/releases/$V/windows/splunkforwarder-$V-$B-windows-x64.msi" -OutFile $msi
}
if (-not (Get-Service SplunkForwarder -ErrorAction SilentlyContinue)) {
  $pw = "Uf-" + -join ((48..57) + (97..102) | Get-Random -Count 20 | ForEach-Object { [char]$_ })
  Add-Content -Path C:\ccc\credentials.txt -Value "Splunk Universal Forwarder (local) : admin / $pw"
  $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/i `"$msi`" AGREETOLICENSE=Yes RECEIVING_INDEXER=`"$Splunk`" SPLUNKUSERNAME=admin SPLUNKPASSWORD=$pw LAUNCHSPLUNK=0 /quiet"
  "installation UF : code $($p.ExitCode)"
}
$uf = "C:\Program Files\SplunkUniversalForwarder"
@"
[default]
host = DC01
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = eq13
renderXml = false
[WinEventLog://Security]
index = eq13
[monitor://C:\ccc\eq13-fim.log]
index = eq13
sourcetype = eq13:fim
[monitor://C:\ccc\eq13-yara.log]
index = eq13
sourcetype = eq13:yara
"@ | Set-Content -Encoding ASCII "$uf\etc\system\local\inputs.conf"

# 3. Surveillance des dossiers sensibles + YARA (remplace la surveillance de fichiers de l'agent Wazuh)
$watch = @'
$yara  = "C:\Program Files (x86)\ossec-agent\yara\yara64.exe"
$rules = "C:\Program Files (x86)\ossec-agent\yara\eq13.yar"
foreach ($f in "C:\ccc\eq13-fim.log","C:\ccc\eq13-yara.log") { if (-not (Test-Path $f)) { New-Item -ItemType File $f | Out-Null } }
$enc = New-Object System.Text.UTF8Encoding($false)
$action = {
  $p = $Event.SourceEventArgs.FullPath; $t = $Event.SourceEventArgs.ChangeType
  $now = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  $j = @{ time = $now; host = "DC01"; event = "$t"; file = $p } | ConvertTo-Json -Compress
  [IO.File]::AppendAllText("C:\ccc\eq13-fim.log", $j + "`n", $Event.MessageData)
  if (Test-Path $p -PathType Leaf) {
    $out = $null
    foreach ($try in 1..3) {
      Start-Sleep -Milliseconds 300
      $out = & "C:\Program Files (x86)\ossec-agent\yara\yara64.exe" "C:\Program Files (x86)\ossec-agent\yara\eq13.yar" $p 2>$null
      if ($LASTEXITCODE -eq 0) { break }
    }
    foreach ($line in $out) {
      $rule = ($line -split " ", 2)[0]
      $h = (Get-FileHash $p -Algorithm SHA256).Hash.ToLower()
      $y = @{ time = $now; host = "DC01"; yara_rule = $rule; file = $p; sha256 = $h } | ConvertTo-Json -Compress
      [IO.File]::AppendAllText("C:\ccc\eq13-yara.log", $y + "`n", $Event.MessageData)
    }
  }
}
foreach ($dir in "C:\EQ13-Simu", "C:\Users\Public\Downloads") {
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory $dir | Out-Null }
  $w = New-Object IO.FileSystemWatcher $dir
  $w.IncludeSubdirectories = $true; $w.InternalBufferSize = 65536; $w.EnableRaisingEvents = $true
  foreach ($e in "Created", "Renamed", "Changed") { Register-ObjectEvent $w $e -Action $action -MessageData $enc | Out-Null }
}
while ($true) { Start-Sleep -Milliseconds 200 }
'@
Set-Content -Encoding ASCII C:\ccc\eq13-watch.ps1 $watch
$act = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\ccc\eq13-watch.ps1"
$trg = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName "eq13-watch" -Action $act -Trigger $trg -User "SYSTEM" -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName "eq13-watch"

Restart-Service SplunkForwarder -ErrorAction SilentlyContinue
if (-not (Get-Service SplunkForwarder -ErrorAction SilentlyContinue)) { "service UF absent" } else { Start-Service SplunkForwarder -ErrorAction SilentlyContinue }
Start-Sleep 10
Get-Service SplunkForwarder, WazuhSvc, Sysmon64 | Select-Object Name, Status | Format-Table -HideTableHeaders
(Get-ScheduledTask -TaskName eq13-watch).State
