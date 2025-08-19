# powershell -ExecutionPolicy Bypass -File .\check_hardening.ps1 -Verbose

<#
.SYNOPSIS
  Auditoría de hardening para Windows 10/11 (NO aplica cambios).
  Genera un reporte TXT con estados de: Firewall, Defender, SMBv1, SmartScreen,
  LSA PPL, WDigest, logging de PowerShell, auditoría avanzada, políticas de contraseña,
  cuenta Invitado, RDP, firma SMB, AutoRun, servicios heredados, UAC, Windows Update,
  BitLocker (si disponible), parches recientes y versión del SO.

.NOTES
  Ejecutar como Administrador para obtener toda la información posible.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'SilentlyContinue'

# --- Utilidades ---
$reportDir = 'C:\HardeningReports'
New-Item -ItemType Directory -Force -Path $reportDir | Out-Null
$report = Join-Path $reportDir ("reporte_hardening_status-{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

function Write-Report {
  param([Parameter(Mandatory)][string]$Text)
  $Text | Tee-Object -FilePath $report -Append | Out-Null
}

function RegGet {
  param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$Name)
  try {
    $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
    return $item.$Name
  } catch { return $null }
}

Write-Report "======== AUDITORÍA HARDENING WINDOWS ========"
Write-Report ("Fecha: {0}" -f (Get-Date))
Write-Report "Reporte: $report"
Write-Report ""

# --- Info del sistema ---
Write-Report "== Sistema =="
try {
  $ci = Get-ComputerInfo
  Write-Report ("OS: {0} {1} (Build {2})" -f $ci.OsName,$ci.OsVersion,$ci.OsBuildNumber)
  Write-Report ("Host: {0}  Uptime(días): {1:N1}" -f $env:COMPUTERNAME, ((Get-Date) - $ci.OsInstallDate).TotalDays )
} catch {
  Write-Report "No se pudo obtener Get-ComputerInfo."
}
Write-Report ""

# --- Firewall ---
Write-Report "== Firewall (Windows Defender Firewall) =="
try {
  Get-NetFirewallProfile | ForEach-Object {
    Write-Report ("Perfil: {0}" -f $_.Name)
    Write-Report ("  Enabled: {0}" -f $_.Enabled)
    Write-Report ("  Inbound: {0}  Outbound: {1}" -f $_.DefaultInboundAction, $_.DefaultOutboundAction)
    Write-Report ("  LogAllowed: {0}  LogBlocked: {1}" -f $_.LogAllowed, $_.LogBlocked)
    Write-Report ("  LogFile: {0}  MaxKB: {1}" -f $_.LogFileName, $_.LogMaxSizeKilobytes)
  }
} catch { Write-Report "No fue posible leer perfiles de firewall." }
Write-Report ""

# --- Microsoft Defender ---
Write-Report "== Microsoft Defender (preferencias) =="
try {
  $mp = Get-MpPreference
  Write-Report ("Realtime: {0}  PUA: {1}  MAPS: {2}  SubmitSamples: {3}" -f `
    (-not $mp.DisableRealtimeMonitoring), $mp.PUAProtection, $mp.MAPSReporting, $mp.SubmitSamplesConsent)
  Write-Report ("IOAV: {0}  SignatureUpdateInterval(h): {1}" -f (-not $mp.DisableIOAVProtection), $mp.SignatureUpdateInterval)
  Write-Report ("ControlledFolderAccess: {0}" -f $mp.EnableControlledFolderAccess)
} catch { Write-Report "Get-MpPreference no disponible o acceso denegado." }
Write-Report ""

# --- SmartScreen ---
Write-Report "== SmartScreen =="
$ss1 = RegGet 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen'
$ss2 = RegGet 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'ShellSmartScreenLevel'
$ss3 = RegGet 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled'
$edge1 = RegGet 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'SmartScreenEnabled'
$edge2 = RegGet 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'SmartScreenPuaEnabled'
Write-Report ("Windows SmartScreen: EnableSmartScreen={0} ShellLevel={1} Explorer={2}" -f $ss1,$ss2,$ss3)
Write-Report ("Edge SmartScreen: Enabled={0} PUA={1}" -f $edge1,$edge2)
Write-Report ""

# --- SMBv1 ---
Write-Report "== SMBv1 =="
try {
  $srv = Get-SmbServerConfiguration
  $cli = Get-SmbClientConfiguration
  Write-Report ("Server SMB1 Enabled: {0}" -f $srv.EnableSMB1Protocol)
  Write-Report ("Client SMB1 Enabled: {0}" -f $cli.EnableSMB1Protocol)
} catch { Write-Report "No se pudieron leer configuraciones SMB Server/Client." }
try {
  $feat = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
  Write-Report ("Feature SMB1Protocol State: {0}" -f $feat.State)
} catch { Write-Report "No se pudo leer WindowsOptionalFeature SMB1Protocol." }
Write-Report ""

# --- LSA Protection (RunAsPPL) y WDigest ---
Write-Report "== LSA / WDigest =="
$runAsPpl = RegGet 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
$noLM     = RegGet 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'NoLMHash'
$wdigest  = RegGet 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
Write-Report ("RunAsPPL: {0}  NoLMHash: {1}  WDigest UseLogonCredential: {2}" -f $runAsPpl,$noLM,$wdigest)
if ($runAsPpl -ne 1) { Write-Report "  * Atención: LSA Protection (RunAsPPL) NO está activado." }
if ($wdigest -ne 0 -and $null -ne $wdigest) { Write-Report "  * Atención: WDigest UseLogonCredential distinto de 0." }
Write-Report ""

# --- Logging de PowerShell ---
Write-Report "== Logging de PowerShell =="
$tr1 = RegGet 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting'
$tr2 = RegGet 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'IncludeInvocationHeader'
$tr3 = RegGet 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'OutputDirectory'
$sb  = RegGet 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
$ml  = RegGet 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging'
Write-Report ("Transcription: Enabled={0} IncludeHeader={1} Dir={2}" -f $tr1,$tr2,$tr3)
Write-Report ("ScriptBlockLogging: {0}  ModuleLogging: {1}" -f $sb,$ml)
Write-Report ""

# --- Auditoría avanzada (auditpol) ---
Write-Report "== Auditoría avanzada (auditpol) =="
try {
  $auditOut = & auditpol /get /category:* 2>$null
  if ($auditOut) {
    $auditOut | ForEach-Object { Write-Report $_ }
  } else {
    Write-Report "No se pudo obtener auditpol."
  }
} catch { Write-Report "Error ejecutando auditpol." }
Write-Report ""

# --- Políticas de contraseña/bloqueo (net accounts) ---
Write-Report "== Política de contraseña/bloqueo (net accounts) =="
try {
  $netOut = & net accounts
  if ($netOut) { $netOut | ForEach-Object { Write-Report $_ } }
} catch { Write-Report "No se pudo ejecutar 'net accounts'." }
Write-Report ""

# --- Cuenta Invitado ---
Write-Report "== Cuenta 'Guest' =="
try {
  $guest = Get-LocalUser -Name 'Guest' -ErrorAction Stop
  Write-Report ("Guest Enabled: {0}" -f $guest.Enabled)
} catch { Write-Report "Cuenta 'Guest' no presente o sin acceso." }
Write-Report ""

# --- RDP ---
Write-Report "== Escritorio Remoto (RDP) =="
$rdpDenied = RegGet 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
Write-Report ("fDenyTSConnections: {0} (0=Permitido, 1=Denegado)" -f $rdpDenied)
try {
  $rdpFw = Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
  if ($rdpFw) {
    $enabled = ($rdpFw | Where-Object {$_.Enabled -eq 'True'}).Count
    Write-Report ("Firewall reglas 'Remote Desktop' habilitadas: {0}" -f $enabled)
  } else {
    Write-Report "No se encontraron reglas de firewall del grupo 'Remote Desktop'."
  }
} catch { Write-Report "Error consultando reglas de firewall para RDP." }
Write-Report ""

# --- Firma SMB requerida ---
Write-Report "== Firma SMB =="
$wsReq = RegGet 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature'
$wsEn  = RegGet 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'EnableSecuritySignature'
$svReq = RegGet 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature'
Write-Report ("Workstation Require={0} Enable={1} ; Server Require={2}" -f $wsReq,$wsEn,$svReq)
Write-Report ""

# --- AutoRun/AutoPlay ---
Write-Report "== AutoRun / AutoPlay =="
$autorun = RegGet 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
Write-Report ("NoDriveTypeAutoRun: {0} (255=Deshabilitado en todos)" -f $autorun)
Write-Report ""

# --- Servicios heredados ---
Write-Report "== Servicios heredados (si existen) =="
foreach ($svc in @('RemoteRegistry','SSDPSRV','upnphost')) {
  try {
    $s = Get-Service -Name $svc -ErrorAction Stop
    Write-Report ("{0}: Status={1} StartType={2}" -f $svc,$s.Status,$s.StartType)
  } catch {
    Write-Report ("{0}: no presente" -f $svc)
  }
}
Write-Report ""

# --- UAC ---
Write-Report "== UAC (Control de cuentas de usuario) =="
$enableLUA = RegGet 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
$consent   = RegGet 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin'
Write-Report ("EnableLUA={0}  ConsentPromptBehaviorAdmin={1}" -f $enableLUA,$consent)
Write-Report "  (ConsentPrompt: 2=Prompt credenciales, 5=Prompt consentimiento, 0=sin prompt)"
Write-Report ""

# --- Windows Update (servicio) ---
Write-Report "== Windows Update (servicio wuauserv) =="
try {
  $wu = Get-Service -Name wuauserv -ErrorAction Stop
  Write-Report ("wuauserv: Status={0} StartType={1}" -f $wu.Status,$wu.StartType)
} catch { Write-Report "No se pudo leer servicio wuauserv." }
Write-Report ""

# --- BitLocker (si disponible) ---
Write-Report "== BitLocker (si disponible) =="
try {
  $bl = Get-BitLockerVolume
  if ($bl) {
    foreach ($v in $bl) {
      Write-Report ("Unidad {0}: ProtectionStatus={1}  EncryptionMethod={2}" -f $v.MountPoint,$v.ProtectionStatus,$v.EncryptionMethod)
    }
  } else {
    Write-Report "BitLocker no devuelve volúmenes."
  }
} catch { Write-Report "Get-BitLockerVolume no disponible en esta edición o módulo no cargado." }
Write-Report ""

# --- Parches instalados últimos 30 días (opcional) ---
Write-Report "== Parches instalados (últimos 30 días) =="
try {
  $since = (Get-Date).AddDays(-30)
  Get-HotFix | Where-Object {$_.InstalledOn -ge $since} | Sort-Object InstalledOn | ForEach-Object {
    Write-Report ("{0}  {1}  {2}" -f $_.InstalledOn.ToString('yyyy-MM-dd'), $_.HotFixID, $_.Description)
  }
} catch { Write-Report "No se pudo consultar Get-HotFix (requiere servicio WMI)." }
Write-Report ""

Write-Report "======== FIN DEL REPORTE ========"
Write-Host "Reporte generado en: $report"
