<#
============================================================================
 dhcp.ps1 - Reservations DHCP (Windows Server / Active Directory)
 Complement de l'application "Surveillance IP".

 - LISTE les reservations existantes -> produit un JSON a importer dans l'app
   (badge "reservee" / "dynamique" sur chaque appareil).
 - RESERVE l'adresse IP actuelle d'un equipement (la MAC est lue automatiquement
   depuis le bail DHCP) pour qu'elle ne change plus.

 Le serveur DHCP est interroge A DISTANCE avec un COMPTE que tu saisis
 (fenetre securisee ; le mot de passe n'apparait jamais en clair). Le compte
 doit etre administrateur DHCP (ou delegue). Utilise PowerShell Remoting
 (WinRM) vers le serveur DHCP.

 100 % PowerShell (deja dans Windows). AUCUNE installation cote client.

 ---------------------------------------------------------------------------
 EXEMPLES (depuis PowerShell, dans le dossier du script)
 ---------------------------------------------------------------------------
   # 1) LISTER / verifier (lecture seule, sans risque) a partir de l'export de l'app :
   powershell -ExecutionPolicy Bypass -File .\dhcp.ps1 -In surveillance-ip.json -Out dhcp.json -User MONDOMAINE\admdhcp

   # 2) RESERVER (SIMULATION par defaut : montre ce qui serait fait) :
   powershell -ExecutionPolicy Bypass -File .\dhcp.ps1 -In surveillance-ip.json -Reserve -User MONDOMAINE\admdhcp

   # 3) RESERVER pour de vrai (ajoute -Apply) :
   powershell -ExecutionPolicy Bypass -File .\dhcp.ps1 -In surveillance-ip.json -Reserve -Apply -User MONDOMAINE\admdhcp

   # Reserver quelques IP precises :
   powershell -ExecutionPolicy Bypass -File .\dhcp.ps1 -Ips 10.122.103.101,10.122.103.103 -Reserve -Apply -User MONDOMAINE\admdhcp

 Options : -Server <ip/nom du DHCP> (sinon auto-detecte via ipconfig).
           -User <DOMAINE\compte>   (sinon demande aussi l'identifiant).
 ---------------------------------------------------------------------------
 PRE-REQUIS : PowerShell Remoting (WinRM) autorise vers le serveur DHCP
 (standard en domaine : "Enable-PSRemoting" cote serveur / GPO). Sinon le
 script le signalera clairement.
============================================================================
#>

[CmdletBinding()]
param(
    [string]$Server,
    [string]$User,
    [string]$In,
    [string[]]$Ips,
    [string]$Out = "dhcp.json",
    [switch]$Reserve,
    [switch]$Apply,
    [string]$Description = "Reserve via script (Surveillance IP)"
)

$ErrorActionPreference = "Stop"

function IpToUInt([string]$ip){
    $o = $ip.Split('.'); if($o.Count -ne 4){ return $null }
    $n = [uint64]0
    foreach($x in $o){ $v=[int]$x; if($v -lt 0 -or $v -gt 255){ return $null }; $n=($n*256)+$v }
    return [uint32]$n
}

function Get-DhcpServerFromIpconfig {
    try{
        $out = ipconfig /all
        foreach($line in $out){
            if($line -match '(DHCP\s*Server|Serveur\s*DHCP)[ .]*:\s*([0-9]{1,3}(\.[0-9]{1,3}){3})'){
                return $matches[2]
            }
        }
    }catch{}
    return $null
}

function Load-TargetIps {
    $ips = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    function Add-Ip($ip){
        $ip = ([string]$ip).Trim() -replace ':\d+$',''
        if($ip -and -not $seen.ContainsKey($ip)){ $seen[$ip]=$true; [void]$ips.Add($ip) }
    }
    if($In){
        $data = Get-Content -Raw -Path $In | ConvertFrom-Json
        foreach($x in $data){ if($x.addr){ Add-Ip $x.addr } }
    }
    foreach($ip in $Ips){ Add-Ip $ip }
    return ,$ips
}

# ---------------------------------------------------------------------------
Write-Host "== dhcp.ps1 - Reservations DHCP ==" -ForegroundColor Cyan

if(-not $Server){
    $Server = Get-DhcpServerFromIpconfig
    if($Server){ Write-Host ("Serveur DHCP auto-detecte : {0}" -f $Server) -ForegroundColor Green }
}
if(-not $Server){
    $Server = Read-Host "Adresse (IP ou nom) du serveur DHCP"
}
if(-not $Server){ Write-Host "Aucun serveur DHCP. Utilise -Server." -ForegroundColor Yellow; return }

# Compte a utiliser (fenetre securisee)
if($User){ $cred = Get-Credential -UserName $User -Message ("Mot de passe pour {0} (gestion DHCP)" -f $User) }
else     { $cred = Get-Credential -Message "Compte autorise a gerer le DHCP (DOMAINE\utilisateur)" }
if(-not $cred){ Write-Host "Annule (pas d'identifiants)." -ForegroundColor Yellow; return }

$targets = Load-TargetIps
Write-Host ("{0} adresse(s) a traiter. Serveur DHCP : {1}" -f $targets.Count, $Server)

# ---- Lecture des scopes / reservations / baux (a distance, avec le compte) --
Write-Host "[DHCP] Lecture des scopes, reservations et baux..." -ForegroundColor Cyan
try{
    $snap = Invoke-Command -ComputerName $Server -Credential $cred -ScriptBlock {
        Import-Module DhcpServer -ErrorAction Stop
        $scopes = Get-DhcpServerv4Scope
        $res = @(); $leases = @()
        foreach($s in $scopes){
            $res += Get-DhcpServerv4Reservation -ScopeId $s.ScopeId |
                    Select-Object @{n='ScopeId';e={$s.ScopeId.ToString()}}, @{n='IPAddress';e={$_.IPAddress.ToString()}}, ClientId, Name, Description
            $leases += Get-DhcpServerv4Lease -ScopeId $s.ScopeId |
                    Select-Object @{n='ScopeId';e={$s.ScopeId.ToString()}}, @{n='IPAddress';e={$_.IPAddress.ToString()}}, ClientId, AddressState, HostName
        }
        [pscustomobject]@{
            Scopes = $scopes | Select-Object @{n='ScopeId';e={$_.ScopeId.ToString()}}, @{n='SubnetMask';e={$_.SubnetMask.ToString()}}, Name
            Reservations = $res
            Leases = $leases
        }
    }
}catch{
    Write-Host ("[DHCP] Echec de la connexion au serveur ({0})." -f $_.Exception.Message) -ForegroundColor Red
    Write-Host "  -> Verifie : le nom/IP du serveur, tes identifiants, et que PowerShell Remoting" -ForegroundColor Yellow
    Write-Host "     (WinRM) est autorise vers le serveur DHCP (Enable-PSRemoting cote serveur)." -ForegroundColor Yellow
    return
}

# Index locaux
$reservedByIp = @{}
foreach($r in $snap.Reservations){ $reservedByIp[$r.IPAddress] = $r }
$leaseByIp = @{}
foreach($l in $snap.Leases){ if(-not $leaseByIp.ContainsKey($l.IPAddress)){ $leaseByIp[$l.IPAddress] = $l } }

function Find-Scope([string]$ip){
    $ipn = IpToUInt $ip; if($null -eq $ipn){ return $null }
    foreach($s in $snap.Scopes){
        $net = IpToUInt $s.ScopeId; $mask = IpToUInt $s.SubnetMask
        if($null -ne $net -and $null -ne $mask -and (($ipn -band $mask) -eq ($net -band $mask))){ return $s.ScopeId }
    }
    return $null
}

Write-Host ("[DHCP] {0} reservation(s) et {1} bail/baux lus sur {2} scope(s)." -f `
    $snap.Reservations.Count, $snap.Leases.Count, ($snap.Scopes | Measure-Object).Count)

# ---- Action : RESERVER --------------------------------------------------------
if($Reserve){
    if(-not $Apply){ Write-Host "MODE SIMULATION (rien n'est modifie). Ajoute -Apply pour executer." -ForegroundColor Yellow }
    foreach($ip in $targets){
        if($reservedByIp.ContainsKey($ip)){
            Write-Host ("  [=] {0} deja reservee (MAC {1})." -f $ip, $reservedByIp[$ip].ClientId) -ForegroundColor DarkGray
            continue
        }
        $lease = $leaseByIp[$ip]
        if(-not $lease -or -not $lease.ClientId){
            Write-Host ("  [!] {0} : aucun bail DHCP trouve -> MAC inconnue, impossible de reserver." -f $ip) -ForegroundColor Yellow
            Write-Host "        (l'equipement a peut-etre une IP fixe manuelle, ou n'a pas de bail actif.)" -ForegroundColor DarkGray
            continue
        }
        $scope = Find-Scope $ip
        if(-not $scope){ Write-Host ("  [!] {0} : aucun scope correspondant." -f $ip) -ForegroundColor Yellow; continue }
        $mac = $lease.ClientId
        if($Apply){
            try{
                Invoke-Command -ComputerName $Server -Credential $cred -ScriptBlock {
                    param($scope,$ip,$mac,$desc,$name)
                    Import-Module DhcpServer -ErrorAction Stop
                    Add-DhcpServerv4Reservation -ScopeId $scope -IPAddress $ip -ClientId $mac -Description $desc -Name $name -ErrorAction Stop
                } -ArgumentList $scope, $ip, $mac, $Description, ($lease.HostName) | Out-Null
                $reservedByIp[$ip] = [pscustomobject]@{ IPAddress=$ip; ClientId=$mac; Name=$lease.HostName }
                Write-Host ("  [OK] {0} reservee -> MAC {1} (scope {2})." -f $ip, $mac, $scope) -ForegroundColor Green
            }catch{
                Write-Host ("  [ERR] {0} : {1}" -f $ip, $_.Exception.Message) -ForegroundColor Red
            }
        }else{
            Write-Host ("  [SIMU] Reserverait {0} -> MAC {1} (scope {2})." -f $ip, $mac, $scope) -ForegroundColor Cyan
        }
    }
}

# ---- Sortie JSON pour l'application (badge reservee/dynamique) ---------------
$rows = @()
foreach($ip in $targets){
    $isRes = $reservedByIp.ContainsKey($ip)
    $mac = if($isRes){ $reservedByIp[$ip].ClientId } elseif($leaseByIp.ContainsKey($ip)){ $leaseByIp[$ip].ClientId } else { $null }
    $o = [ordered]@{ addr = $ip; reserved = [bool]$isRes }
    if($mac){ $o.reservedMac = [string]$mac }
    $rows += [pscustomobject]$o
}
if($rows.Count -eq 0){ $text = "[]" }
elseif($rows.Count -eq 1){ $text = "[" + ($rows[0] | ConvertTo-Json -Depth 5) + "]" }
else { $text = $rows | ConvertTo-Json -Depth 5 }
$full = if([System.IO.Path]::IsPathRooted($Out)){ $Out } else { Join-Path (Get-Location).Path $Out }
[System.IO.File]::WriteAllText($full, $text, [System.Text.UTF8Encoding]::new($false))

# ---- Recapitulatif ------------------------------------------------------------
Write-Host ""
Write-Host "=== Etat des adresses ===" -ForegroundColor Cyan
foreach($ip in $targets){
    if($reservedByIp.ContainsKey($ip)){ Write-Host ("  {0,-16} RESERVEE   (MAC {1})" -f $ip, $reservedByIp[$ip].ClientId) -ForegroundColor Green }
    else { Write-Host ("  {0,-16} dynamique  (peut changer)" -f $ip) -ForegroundColor Yellow }
}
Write-Host ""
Write-Host ("Fichier ecrit : {0}" -f $full)
Write-Host "-> Dans l'application : bouton `"Importer`" pour afficher les badges reservee/dynamique."
