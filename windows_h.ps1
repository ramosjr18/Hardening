<#
.SYNOPSIS
  Hardening preventivo para Windows 10/11 (cliente). Requiere PowerShell como Administrador.

.PARAMETER BlockOutbound
  Cambia acción por defecto del Firewall a BLOQUEAR tráfico saliente (crea reglas base mínimas). Puede romper apps.

.PARAMETER EnableRDP
  Habilita Escritorio Remoto y fuerza NLA. Por defecto, RDP queda DESHABILITADO.

.PARAMETER DisableLegacyServices
  Deshabilita servicios heredados: RemoteRegistry, SSDP (SSDPSRV), UPnP (upnphost) si existen.

.PARAMETER NoRestorePoint
  Omite la creación de punto de restauración.

.PARAMETER EnableControlledFolderAccess
  Habilita Controlled Folder Access en Defender (puede bloquear apps no confiables).

.EXAMPLE
  .\hardening-windows.ps1 -Verbose
  .\hardening-windows.ps1 -BlockOutbound -DisableLegacyServices -Verbose
#>

[CmdletBinding()]
param(
  [switch]$BlockOutbound,
  [switch]$EnableRDP,
  [switch]$DisableLegacyServices,
  [switch]$NoRestorePoint,
  [switch]$EnableControlledFolderAccess
)

# --- Comprobación de privilegios ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
  Write-Error "Ejecuta este script en una consola de PowerShell iniciada como Administrador."
  exit 1
}

# --- Preparación de logs y utilidades ---
$ErrorActionPreference = 'Stop'
$logRoot = 'C:\HardeningLogs'
$psTransDir = 'C:\PowerShellTranscripts'
New-Item -ItemType Directory -Force -Path $logRoot,$psTransDir | Out-Null
$transcript = Join-Path $logRoot ("hardening-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
Start-Transcript -Path $transcript -NoClobber | Out-Null

$RebootReasons = New-Object System.Collections.Generic.List[string]

function Export-RegistryKey {
  param([Parameter(Mandatory)] [string]$Path, [Parameter(Mandatory)] [string]$OutFile)
  try { reg.exe export $Path $OutFile /y | Out-Null } catch { Write-Verbose "No se pudo exportar $Path: $($_.Exception.Message)" }
}

function Set-Reg {
  param(
    [Parameter(Mandatory)] [ValidateSet('HKLM:','HKCU:')] [string]$Hive,
    [Parameter(Mandatory)] [string]$Path,
    [Parameter(Mandatory)] [string]$Name,
    [Parameter(Mandatory)] $Value,
    [ValidateSet('String','ExpandString','DWord','QWord','Binary','MultiString')] [string]$Type = 'DWord'
  )
  $full = "$Hive$Path"
  if (-not (Test-Path $full)) { New-Item -Path $full -Force | Out-Null }
  New-ItemProperty -Path $full -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}

Write-Host "== Hardening preventivo: inicio ==" -ForegroundColor Cyan

# --- Punto de restauración (si procede) ---
if (-not $NoRestorePoint) {
  try {
    Write-Verbose "Creando punto de restauración del sistema..."
    Checkpoint-Computer -Description ("Hardening-{0}" -f (Get-Date -Format 'yyyy-MM-ddTHH:mm')) -RestorePointType "MODIFY_SETTINGS"
  } catch {
    Write-Warning "No fue posible crear el punto de restauración (puede estar deshabilitado en este equipo)."
  }
}

# --- Firewall (perfiles y logging) ---
Write-Verbose "Configurando Windows Firewall..."
$defaultOutbound = if ($BlockOutbound) { 'Block' } else { 'Allow' }
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True `
  -DefaultInboundAction Block -DefaultOutboundAction $defaultOutbound `
  -NotifyOnListen True

Set-NetFirewallProfile -Profile Domain,Private,Public `
  -LogAllowed True -LogBlocked True `
  -LogFileName "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" `
  -LogMaxSizeKilobytes 16384

if ($BlockOutbound) {
  Write-Verbose "Creando reglas básicas para salida (DNS, DHCP, NTP, HTTP/HTTPS)..."
  $rules = @(
    @{Name='Allow Out DNS UDP 53'; Protocol='UDP'; RemotePort=53},
    @{Name='Allow Out DNS TCP 53'; Protocol='TCP'; RemotePort=53},
    @{Name='Allow Out DHCP UDP 67-68'; Protocol='UDP'; RemotePort='67-68'},
    @{Name='Allow Out NTP UDP 123'; Protocol='UDP'; RemotePort=123},
    @{Name='Allow Out HTTP TCP 80'; Protocol='TCP'; RemotePort=80},
    @{Name='Allow Out HTTPS TCP 443'; Protocol='TCP'; RemotePort=443}
  )
  foreach ($r in $rules) {
    if (-not (Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue)) {
      New-NetFirewallRule -DisplayName $r.Name -Direction Outbound -Action Allow -Enabled True `
        -Profile Any -Protocol $r.Protocol -RemotePort $r.RemotePort | Out-Null
    }
  }
}

# --- Microsoft Defender ---
Write-Verbose "Configurando Microsoft Defender..."
try {
  Set-MpPreference -DisableRealtimeMonitoring $false `
                   -PUAProtection Enabled `
                   -SubmitSamplesConsent SendSafeSamples `
                   -MAPSReporting Advanced `
                   -CheckForSignaturesBeforeRunningScan $true `
                   -DisableIOAVProtection $false `
                   -SignatureUpdateInterval 8

  if ($EnableControlledFolderAccess) {
    # Puede bloquear apps no confiables; úsalo si sabes las implicaciones
    Set-MpPreference -EnableControlledFolderAccess Enabled
  } else {
    Set-MpPreference -EnableControlledFolderAccess Disabled
  }
} catch {
  Write-Warning "No se pudo configurar Defender con Set-MpPreference: $($_.Exception.Message)"
}

# --- SmartScreen (Explorador/Edge) ---
Write-Verbose "Habilitando SmartScreen..."
Export-RegistryKey -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" -OutFile (Join-Path $logRoot 'pol-win-system.reg')
Set-Reg -Hive 'HKLM:' -Path '\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableSmartScreen' -Value 1 -Type DWord
Set-Reg -Hive 'HKLM:' -Path '\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'ShellSmartScreenLevel' -Value 'Block' -Type String
Set-Reg -Hive 'HKLM:' -Path '\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'SmartScreenEnabled' -Value 'RequireAdmin' -Type String
# Edge (Chromium) políticas
Export-RegistryKey -Path "HKLM\SOFTWARE\Policies\Microsoft\Edge" -OutFile (Join-Path $logRoot 'pol-edge.reg')
Set-Reg -Hive 'HKLM:' -Path '\SOFTWARE\Policies\Microsoft\Edge' -Name 'SmartScreenEnabled' -Value 1 -Type DWord
Set-Reg -Hive 'HKLM:' -Path '\SOFTWARE\Policies\Microsoft\Edge' -Name 'SmartScreenPuaEnabled' -Value 1 -Type DWord

# --- SMBv1 deshabilitado (cliente y servidor) ---
Write-Verbose "Deshabilitando SMBv1..."
try { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force | Out-Null } catch {}
try { Set-SmbClientConfiguration -EnableSMB1Protocol $false | Out-Null } catch {}
try { Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null } catch {}

# --- LSA Protection (RunAsPPL) y No LM Hash ---
Write-Verbose "Endureciendo LSA y LM Hash..."
Export-RegistryKey -Path "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -OutFile (Join-Path $logRoot 'lsa-before.reg')
Set-Reg -Hive 'HKLM:' -Path '\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Value 1 -Type DWord
Set-Reg -Hive 'HKLM:' -Path '\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -Value 1 -Type DWord
$RebootReasons.Add("LSA Protection (RunAsPPL) activado") | Out-Null

# --- WDigest: evitar cacheo de credenciales ---
Write-Verbose "Deshabilitando WDigest UseLogonCredential..."
Export-RegistryKey -Path "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -OutFile (Join-Path $logRoot 'wdigest-before.reg')
Set-Reg -Hive 'HKLM:' -Path '\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value 0 -Type DWord
$RebootReasons.Add("Cambio WDigest (UseLogonCredential=0)") | Out-Null

# --- Logging de PowerShell (script block, módulo, transcripción) ---
Write-Verbose "Habilitando logging de PowerShell..."
# Transcription
Set-Reg -Hive 'HKLM:' -Path '\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableTranscripting' -Value 1 -Type DWord
Set-Reg -Hive 'HKLM:' -Path '\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'IncludeInvocationHeader' -Value 1 -Type DWord
Set-Reg -Hive 'HKLM:' -Path '\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'OutputDirectory' -Value $psTransDir -Type String
# Script Block Logging
Set-Reg -Hive 'HKLM:' -Path '\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord
# Module Logging
Set-Reg -Hive 'HKLM:' -Path '\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'EnableModuleLogging' -Value 1 -Type DWord
if (-not (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames')) {
  New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -Force | Out-Null
}
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -Name '*' -Value '*' -PropertyType String -Force | Out-Null

# --- Auditoría avanzada (auditpol) ---
Write-Verbose "Aplicando auditoría avanzada..."
$audits = @(
  @{Name='Credential Validation'; S=$true; F=$true}
  @{Name='Logon';                 S=$true; F=$true}
  @{Name='Logoff';                S=$true; F=$false}
  @{Name='Special Logon';         S=$true; F=$true}
  @{Name='Account Lockout';       S=$true; F=$true}
  @{Name='User Account Management'; S=$true; F=$true}
  @{Name='Security Group Management'; S=$true; F=$true}
  @{Name='Computer Account Management'; S=$true; F=$true}
  @{Name='Other Account Management Events'; S=$true; F=$true}
  @{Name='Audit Policy Change';   S=$true; F=$true}
  @{Name='Authentication Policy Change'; S=$true; F=$true}
  @{Name='Authorization Policy Change';  S=$true; F=$true}
  @{Name='Sensitive Privilege Use'; S=$true; F=$true}
  @{Name='Security State Change'; S=$true; F=$true}
  @{Name='Security System Extension'; S=$true; F=$true}
  @{Name='System Integrity';      S=$true; F=$true}
  # Object Access (ruidoso si no hay SACLs; úsalo si lo necesitas)
  @{Name='File System';           S=$false; F=$true}
  @{Name='Registry';              S=$false; F=$true}
)
foreach ($a in $audits) {
  & auditpol /set /subcategory:"$($a.Name)" /success:($(if($a.S){'enable'}else{'disable'})) /failure:($(if($a.F){'enable'}else{'disable'})) | Out-Null
}

# --- Políticas básicas de cuenta (contraseñas y bloqueo) ---
Write-Verbose "Estableciendo políticas de contraseñas y bloqueo..."
# Estas afectan PasswordLength, MaxPasswordAge, Lockout, etc.
& net accounts /minpwlen:12 /maxpwage:60 /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15 /uniquepw:5 | Out-Null

# Activar complejidad de contraseñas vía secedit (INF)
$inf = @"
[Version]
signature="\$CHICAGO$"
Revision=1
[System Access]
PasswordComplexity = 1
MinimumPasswordAge = 1
MaximumPasswordAge = 60
MinimumPasswordLength = 12
PasswordHistorySize = 5
LockoutBadCount = 5
ResetLockoutCount = 15
LockoutDuration = 15
"@
$tempInf = Join-Path $env:TEMP "sec-hardening.inf"
$inf | Set-Content -Path $tempInf -Encoding ASCII
secedit /configure /db (Join-Path $env:TEMP 'sec-hardening.sdb') /cfg $tempInf /areas SECURITYPOLICY | Out-Null

# --- Cuenta Invitado deshabilitada ---
Write-Verbose "Deshabilitando cuenta Invitado (Guest) si existe..."
try {
  $guest = Get-LocalUser -Name 'Guest' -ErrorAction Stop
  if ($guest.Enabled) { Disable-LocalUser -Name 'Guest' }
} catch { Write-Verbose "Cuenta Guest no presente o ya deshabilitada." }

# --- RDP (por defecto deshabilitado; con NLA si se habilita) ---
Write-Verbose "Configurando RDP..."
if ($EnableRDP) {
  Set-Reg -Hive 'HKLM:' -Path '\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0 -Type DWord
  Set-Reg -Hive 'HKLM:' -Path '\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1 -Type DWord
  Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' | Out-Null
} else {
  Set-Reg -Hive 'HKLM:' -Path '\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 1 -Type DWord
  Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' | Out-Null
}

# --- Firma SMB requerida (cliente/servidor) ---
Write-Verbose "Exigiendo firma SMB..."
Set-Reg -Hive 'HKLM:' -Path '\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -Value 1 -Type DWord
Set-Reg -Hive 'HKLM:' -Path '\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'EnableSecuritySignature' -Value 1 -Type DWord
Set-Reg -Hive 'HKLM:' -Path '\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature' -Value 1 -Type DWord

# --- AutoRun/AutoPlay deshabilitado ---
Write-Verbose "Deshabilitando AutoRun/AutoPlay..."
Set-Reg -Hive 'HKLM:' -Path '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255 -Type DWord

# --- Servicios heredados opcionales ---
if ($DisableLegacyServices) {
  Write-Verbose "Deshabilitando servicios heredados (si existen)..."
  $svcList = @('RemoteRegistry','SSDPSRV','upnphost')
  foreach ($svc in $svcList) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($service) {
      if ($service.Status -ne 'Stopped') { Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue }
      Set-Service -Name $svc -StartupType Disabled
    }
  }
}

# --- Resumen ---
Write-Host "`n== Resumen ==" -ForegroundColor Cyan
Write-Host "• Firewall: Inbound=Block, Outbound=$defaultOutbound"
Write-Host "• Defender: Realtime ON, PUA ON, Cloud ON, ControlledFolderAccess=" + ($(if($EnableControlledFolderAccess){'ON'}else{'OFF'}))
Write-Host "• SMBv1: Deshabilitado"
Write-Host "• SmartScreen: Habilitado"
Write-Host "• LSA Protection (RunAsPPL): ACTIVADO (requiere reinicio)"
Write-Host "• WDigest UseLogonCredential=0 (requiere reinicio)"
Write-Host "• Logging PowerShell: Transcripción + ScriptBlock ON"
Write-Host "• Auditoría avanzada: categorías críticas habilitadas"
Write-Host "• Políticas contraseña/bloqueo: endurecidas"
Write-Host "• RDP: " + ($(if($EnableRDP){'HABILITADO con NLA'}else{'DESHABILITADO'}))
Write-Host "• AutoRun: Deshabilitado"
if ($DisableLegacyServices) { Write-Host "• Servicios heredados: deshabilitados (si presentes)" }

if ($RebootReasons.Count -gt 0) {
  Write-Warning ("Se recomienda REINICIAR para aplicar completamente: {0}" -f ($RebootReasons -join '; '))
}

Write-Host "`nLogs:" -ForegroundColor Yellow
Write-Host "• Transcript: $transcript"
Write-Host "• PowerShell transcripts: $psTransDir"

Stop-Transcript | Out-Null
Write-Host "== Hardening preventivo: completado ==" -ForegroundColor Cyan

# powershell -ExecutionPolicy Bypass -File .\windows_h.ps1 -Verbose