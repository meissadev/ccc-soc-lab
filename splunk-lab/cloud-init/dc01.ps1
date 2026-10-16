<powershell>
# DC01 - Windows Server 2022 : AD DS + DNS (forêt ${domain}), comptes de test,
# Sysmon (config SwiftOnSecurity) et agent Wazuh -> SOC-01 (${wazuh_manager_ip}).
#
# Le user data ne s'exécute qu'une fois : il dépose C:\ccc\setup.ps1 et l'enregistre
# en tâche planifiée "ccc-setup" (SYSTEM, à chaque démarrage). Le script enchaîne
# les étapes (C:\ccc\stage.txt) à travers les redémarrages, puis supprime la tâche.
# Journal : C:\ccc\setup.log - Secrets générés : C:\ccc\credentials.txt (Administrateurs uniquement)

New-Item -ItemType Directory -Force -Path 'C:\ccc' | Out-Null
Set-Content -Path 'C:\ccc\setup.ps1' -Encoding UTF8 -Value @'
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Base  = 'C:\ccc'
$Stage = Join-Path $Base 'stage.txt'
$Creds = Join-Path $Base 'credentials.txt'
Start-Transcript -Path (Join-Path $Base 'setup.log') -Append | Out-Null

function Get-Stage { if (Test-Path $Stage) { [int](Get-Content $Stage) } else { 0 } }
function Set-Stage([int]$n) { Set-Content -Path $Stage -Value $n }
function New-Pw {
  $chars = [char[]]'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
  (-join (1..14 | ForEach-Object { $chars | Get-Random })) + '#7aZ'
}
function Read-Secret([string]$key) {
  (Get-Content $Creds | Where-Object { $_ -like "$key=*" } | Select-Object -First 1).Split('=', 2)[1]
}
function Get-File([string]$url, [string]$out) {
  for ($i = 1; $i -le 10; $i++) {
    try { Invoke-WebRequest $url -OutFile $out -UseBasicParsing; return }
    catch { if ($i -eq 10) { throw }; Start-Sleep -Seconds 30 }
  }
}

try {
  switch (Get-Stage) {

    0 {
      # Secrets : Administrator (= KURGER\Administrator après promotion) + DSRM
      if (-not (Test-Path $Creds)) {
        "Administrator=$(New-Pw)" | Set-Content $Creds
        "DSRM=$(New-Pw)"          | Add-Content $Creds
        icacls $Base /inheritance:r /grant:r 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' | Out-Null
      }
      net user Administrator (Read-Secret 'Administrator') /active:yes | Out-Null

      Install-WindowsFeature AD-Domain-Services, DNS -IncludeManagementTools | Out-Null

      # Sysmon + configuration SwiftOnSecurity
      $sys = Join-Path $Base 'sysmon'
      New-Item -ItemType Directory -Force -Path $sys | Out-Null
      Get-File 'https://download.sysinternals.com/files/Sysmon.zip' "$sys\Sysmon.zip"
      Expand-Archive "$sys\Sysmon.zip" -DestinationPath $sys -Force
      Get-File 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml' "$sys\sysmonconfig.xml"
      if (-not (Get-Service Sysmon64 -ErrorAction SilentlyContinue)) {
        & "$sys\Sysmon64.exe" -accepteula -i "$sys\sysmonconfig.xml"
      }

      Set-Stage 1
      if ($env:COMPUTERNAME -ne 'DC01') { Rename-Computer -NewName 'DC01' -Force }
      Restart-Computer -Force
      break
    }

    1 {
      # Promotion en premier contrôleur de la forêt (redémarrage automatique)
      Set-Stage 2
      $dsrm = ConvertTo-SecureString (Read-Secret 'DSRM') -AsPlainText -Force
      Install-ADDSForest -DomainName '${domain}' -DomainNetbiosName 'KURGER' `
        -InstallDns -SafeModeAdministratorPassword $dsrm -Force -NoRebootOnCompletion:$false
      break
    }

    2 {
      # Attente des services AD (ADWS) après le redémarrage
      Import-Module ActiveDirectory
      for ($i = 0; $i -lt 60; $i++) {
        try { Get-ADDomain | Out-Null; break } catch { Start-Sleep -Seconds 10 }
      }
      # Résolution Internet via le resolver Amazon (SSM, téléchargements)
      Set-DnsServerForwarder -IPAddress 169.254.169.253

      # Comptes de test
      $dn = (Get-ADDomain).DistinguishedName
      if (-not (Get-ADOrganizationalUnit -Filter "Name -eq 'Lab'")) {
        New-ADOrganizationalUnit -Name 'Lab' -Path $dn
      }
      $ou = "OU=Lab,$dn"
      $users = @(
        @{ Sam = 'alice.martin'; Name = 'Alice Martin';   Groups = @() },
        @{ Sam = 'bob.durand';   Name = 'Bob Durand';     Groups = @() },
        @{ Sam = 'svc.backup';   Name = 'Service Backup'; Groups = @('Backup Operators') },
        @{ Sam = 'it.admin';     Name = 'IT Admin';       Groups = @('Domain Admins') }
      )
      foreach ($u in $users) {
        if (-not (Get-ADUser -Filter "SamAccountName -eq '$($u.Sam)'")) {
          $pw = New-Pw
          New-ADUser -Name $u.Name -SamAccountName $u.Sam -UserPrincipalName "$($u.Sam)@${domain}" `
            -Path $ou -AccountPassword (ConvertTo-SecureString $pw -AsPlainText -Force) `
            -Enabled $true -PasswordNeverExpires $true
          foreach ($g in $u.Groups) { Add-ADGroupMember -Identity $g -Members $u.Sam }
          "$($u.Sam)=$pw" | Add-Content $Creds
        }
      }

      # Agent Wazuh ${wazuh_version} -> SOC-01
      $msi = Join-Path $Base 'wazuh-agent.msi'
      Get-File 'https://packages.wazuh.com/4.x/windows/wazuh-agent-${wazuh_version}-1.msi' $msi
      Start-Process msiexec.exe -Wait -ArgumentList "/i `"$msi`" /q WAZUH_MANAGER=${wazuh_manager_ip} WAZUH_AGENT_NAME=DC01"
      $conf = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
      if (-not (Select-String -Path $conf -Pattern 'Sysmon/Operational' -Quiet)) {
        Add-Content -Path $conf -Value @(
          '',
          '<ossec_config>',
          '  <localfile>',
          '    <location>Microsoft-Windows-Sysmon/Operational</location>',
          '    <log_format>eventchannel</log_format>',
          '  </localfile>',
          '</ossec_config>'
        )
      }
      Set-Service WazuhSvc -StartupType Automatic
      Restart-Service WazuhSvc

      Set-Stage 3
      Unregister-ScheduledTask -TaskName 'ccc-setup' -Confirm:$false
      break
    }

    default { Write-Output 'DC01 déjà configuré, rien à faire.' }
  }
}
catch {
  # La tâche planifiée relancera l'étape en cours au prochain démarrage.
  Write-Output "ERREUR : $_"
}
finally {
  Stop-Transcript | Out-Null
}
'@

if (-not (Get-ScheduledTask -TaskName 'ccc-setup' -ErrorAction SilentlyContinue)) {
  $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\ccc\setup.ps1'
  $trigger   = New-ScheduledTaskTrigger -AtStartup
  $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  Register-ScheduledTask -TaskName 'ccc-setup' -Action $action -Trigger $trigger -Principal $principal | Out-Null
}
Start-ScheduledTask -TaskName 'ccc-setup'
</powershell>
