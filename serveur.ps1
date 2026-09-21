<#
============================================================================
 serveur.ps1 - Moteur local pour "Surveillance IP"
 Sert l'interface (index.html) sur http://127.0.0.1 et fait le travail reseau
 EN LOCAL (donc plus de limite CORS du navigateur) :
   - ping ICMP reel
   - lecture du titre de page et de l'en-tete HTTP "Server"
   - adresse MAC (via la table ARP locale)
   - ports/services web ouverts

 100 % PowerShell (deja dans Windows). AUCUNE installation.
 Lancement simple : double-clic sur "Lancer.bat" (ou la commande ci-dessous).

   powershell -ExecutionPolicy Bypass -File .\serveur.ps1

 Le navigateur s'ouvre tout seul sur l'interface. Pour arreter : ferme la
 fenetre PowerShell (ou Ctrl+C).

 Verifier que les briques marchent sans rien lancer d'autre :
   powershell -ExecutionPolicy Bypass -File .\serveur.ps1 -SelfTest
============================================================================
#>

[CmdletBinding()]
param(
    [int]$Port = 8899,
    [string]$HtmlFile,
    [switch]$NoBrowser,
    [switch]$SelfTest
)

$ErrorActionPreference = "Stop"
# $PSScriptRoot est vide quand on lance le code sans fichier .ps1 (contournement
# de la strategie d'execution) : on retombe alors sur le dossier courant.
if(-not $HtmlFile){
    $root = if($PSScriptRoot){ $PSScriptRoot } else { (Get-Location).Path }
    $HtmlFile = Join-Path $root "index.html"
}

$SERVER_SIGNATURES = @(
    @('goahead|embedthis','GoAhead (serveur web embarque)'),
    @('\bboa\b','Boa (embarque)'),
    @('mongoose|cesanta','Mongoose (embarque)'),
    @('lwip','lwIP HTTPD (embarque)'),
    @('rompager|allegro','Allegro RomPager (embarque)'),
    @('uc-httpd','uc-httpd (camera/embarque)'),
    @('mini_httpd','mini_httpd (embarque)'),
    @('thttpd','thttpd (embarque)'),
    @('webs\b','GoAhead/Webs (embarque)'),
    @('lighttpd','lighttpd'),
    @('nginx','nginx'),
    @('apache','Apache httpd'),
    @('microsoft-iis|\biis\b','Microsoft IIS'),
    @('werkzeug|flask','Python Werkzeug/Flask'),
    @('jetty','Jetty (Java)'),
    @('coyote|tomcat','Apache Tomcat (Java)'),
    @('express|node','Node.js'),
    @('espressif|esp8266|esp-idf|esphttpd','Espressif ESP (IoT)'),
    @('shelly','Shelly (IoT)'),
    @('httpd','httpd embarque (generique)')
)
$COMMON_PORTS = @(80,443,8080,8443,8000,8008,8888,81,88,7547,9000,10000,5000)
$HTTPS_PORTS = @{443=$true;8443=$true;10000=$true}

# ---------------------------------------------------------------------------
#  Briques reseau
# ---------------------------------------------------------------------------
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { param($s,$c,$ch,$e) $true }
try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls } catch {}

function Detect-Server([string]$server,[string]$realm,[string]$title){
    $hay = ("{0} {1} {2}" -f $server,$realm,$title).ToLower()
    foreach($s in $SERVER_SIGNATURES){ if($hay -match $s[0]){ return $s[1] } }
    return ""
}

function Do-Ping([string]$hostname,[int]$timeoutMs=1200){
    try{
        $p = [System.Net.NetworkInformation.Ping]::new()
        $r = $p.Send($hostname, $timeoutMs)
        if($r.Status -eq 'Success'){ return @{ up=$true; ms=[int]$r.RoundtripTime } }
    }catch{}
    return @{ up=$false; ms=$null }
}

function Do-Http([string]$hostname,[int]$port,[string]$proto,[int]$timeoutMs=4000){
    if(-not $proto){ $proto = 'http' }
    $url = "$proto`://$hostname" + $(if($port -gt 0){ ":$port" } else { "" }) + "/"
    $server=""; $realm=""; $title=""; $status=$null; $ok=$false
    try{
        $req = [System.Net.HttpWebRequest]::Create($url)
        $req.Method="GET"; $req.Timeout=$timeoutMs; $req.ReadWriteTimeout=$timeoutMs
        $req.UserAgent="SurveillanceIP-Engine/1.0"; $req.AllowAutoRedirect=$true
        $resp=$null
        try{ $resp=$req.GetResponse() }
        catch [System.Net.WebException]{ $resp=$_.Exception.Response; if($null -eq $resp){ return @{ up=$false } } }
        $ok=$true
        try{ $status=[int]$resp.StatusCode }catch{}
        $server=[string]$resp.Headers["Server"]
        $wa=[string]$resp.Headers["WWW-Authenticate"]
        if($wa -match 'realm\s*=\s*"([^"]*)"'){ $realm=$matches[1] }
        $stream=$resp.GetResponseStream()
        $ms=[System.IO.MemoryStream]::new(); $buf=[byte[]]::new(4096); $tot=0
        while($tot -lt 20000){ $rd=$stream.Read($buf,0,$buf.Length); if($rd -le 0){break}; $ms.Write($buf,0,$rd); $tot+=$rd }
        $resp.Close()
        $body=[System.Text.Encoding]::UTF8.GetString($ms.ToArray())
        if($body -match '(?is)<title[^>]*>(.*?)</title>'){ $title=($matches[1] -replace '\s+',' ').Trim(); if($title.Length -gt 90){ $title=$title.Substring(0,90) } }
    }catch{ return @{ up=$false } }
    return @{ up=$ok; status=$status; server=$server.Trim(); realm=$realm; title=$title; detected=(Detect-Server $server.Trim() $realm $title) }
}

function Do-Mac([string]$hostname){
    try{ [void](Do-Ping $hostname 700) }catch{}   # amorce l'ARP
    try{
        $out = & arp -a 2>$null
        foreach($line in $out){
            if($line -match ('\b' + [regex]::Escape($hostname) + '\b')){
                $m=[regex]::Match($line,'([0-9A-Fa-f]{2}([-:][0-9A-Fa-f]{2}){5})')
                if($m.Success){ return ($m.Value -replace '-',':').ToLower() }
            }
        }
    }catch{}
    return $null
}

function Do-Ports([string]$hostname,[int]$timeoutMs=700){
    $found=@()
    foreach($p in $COMMON_PORTS){
        $c=[System.Net.Sockets.TcpClient]::new()
        try{
            $iar=$c.BeginConnect($hostname,$p,$null,$null)
            if($iar.AsyncWaitHandle.WaitOne($timeoutMs)){ try{ $c.EndConnect($iar); $found += ($(if($HTTPS_PORTS[$p]){'https'}else{'http'})+":"+$p) }catch{} }
        }catch{} finally{ $c.Close() }
    }
    return $found
}

# ---------------------------------------------------------------------------
#  Auto-test
# ---------------------------------------------------------------------------
function Invoke-SelfTest {
    $ok=$true
    function Chk($n,$c){ if($c){ Write-Host "  [OK] $n" -ForegroundColor Green } else { Write-Host "  [FAIL] $n" -ForegroundColor Red; $script:ok=$false } }
    Write-Host "Auto-test serveur.ps1" -ForegroundColor Cyan
    Chk "detection GoAhead" ((Detect-Server "GoAhead-Webs" "" "WAGO") -match "GoAhead")
    Chk "index.html present" (Test-Path $HtmlFile)
    $r = Do-Ping "127.0.0.1" 1000
    Chk "ping loopback" ($r.up -eq $true)
    $j = @{ up=$true; ms=5 } | ConvertTo-Json -Compress
    Chk "JSON ok" ($j -match '"up":true')
    Write-Host ""
    if($script:ok){ Write-Host "TOUS LES TESTS PASSENT." -ForegroundColor Green } else { Write-Host "DES TESTS ECHOUENT - previens-moi." -ForegroundColor Red }
}
if($SelfTest){ Invoke-SelfTest; return }

# ---------------------------------------------------------------------------
#  Petit serveur HTTP (127.0.0.1) via TcpListener
# ---------------------------------------------------------------------------
function Parse-Query([string]$qs){
    $h=@{}
    if($qs){ foreach($pair in $qs.Split('&')){ $kv=$pair.Split('=',2); $k=[uri]::UnescapeDataString($kv[0]); $v=if($kv.Count -gt 1){[uri]::UnescapeDataString($kv[1])}else{''}; $h[$k]=$v } }
    return $h
}
function Send-Bytes($stream,[int]$code,[string]$ctype,[byte[]]$body){
    $reason = switch($code){ 200 {"OK"} 404 {"Not Found"} 500 {"Server Error"} default {"OK"} }
    $head = "HTTP/1.1 $code $reason`r`nContent-Type: $ctype`r`nContent-Length: $($body.Length)`r`nConnection: close`r`nCache-Control: no-store`r`nAccess-Control-Allow-Origin: *`r`n`r`n"
    $hb=[System.Text.Encoding]::ASCII.GetBytes($head)
    $stream.Write($hb,0,$hb.Length)
    if($body.Length){ $stream.Write($body,0,$body.Length) }
    $stream.Flush()
}
function Send-Json($stream,$obj){
    $json = $obj | ConvertTo-Json -Compress -Depth 6
    Send-Bytes $stream 200 "application/json; charset=utf-8" ([System.Text.Encoding]::UTF8.GetBytes($json))
}

# choisit un port libre a partir de $Port
$listener=$null
for($try=0; $try -lt 15; $try++){
    try{
        $listener=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
        $listener.Start(); break
    }catch{ $listener=$null; $Port++ }
}
if(-not $listener){ Write-Host "Impossible d'ouvrir un port local." -ForegroundColor Red; return }

$baseUrl = "http://127.0.0.1:$Port/"
Write-Host ("== Surveillance IP - moteur local ==") -ForegroundColor Cyan
Write-Host ("Interface : {0}" -f $baseUrl) -ForegroundColor Green
Write-Host  "Pour arreter : ferme cette fenetre (ou Ctrl+C)." -ForegroundColor DarkGray
if(-not $NoBrowser){ try{ Start-Process $baseUrl }catch{} }

while($true){
    $client=$null
    try{ $client=$listener.AcceptTcpClient() }catch{ break }
    try{
        $stream=$client.GetStream()
        $reader=[System.IO.StreamReader]::new($stream,[System.Text.Encoding]::ASCII)
        $requestLine=$reader.ReadLine()
        if(-not $requestLine){ $client.Close(); continue }
        while($true){ $h=$reader.ReadLine(); if($null -eq $h -or $h -eq ''){ break } }   # consomme les en-tetes
        $parts=$requestLine.Split(' ')
        $target=if($parts.Count -ge 2){ $parts[1] } else { "/" }
        $path=$target; $qs=""
        $qi=$target.IndexOf('?'); if($qi -ge 0){ $path=$target.Substring(0,$qi); $qs=$target.Substring($qi+1) }
        $q=Parse-Query $qs

        if($path -eq "/" -or $path -eq "/index.html"){
            if(Test-Path $HtmlFile){
                $bytes=[System.IO.File]::ReadAllBytes($HtmlFile)
                Send-Bytes $stream 200 "text/html; charset=utf-8" $bytes
            }else{
                Send-Bytes $stream 404 "text/plain; charset=utf-8" ([System.Text.Encoding]::UTF8.GetBytes("index.html introuvable a cote de serveur.ps1"))
            }
        }
        elseif($path -eq "/api/health"){ Send-Json $stream @{ engine=$true; version="1.0" } }
        elseif($path -eq "/api/ping"){ Send-Json $stream (Do-Ping ([string]$q['host']) 1200) }
        elseif($path -eq "/api/http"){
            $port=0; [int]::TryParse([string]$q['port'],[ref]$port) | Out-Null
            Send-Json $stream (Do-Http ([string]$q['host']) $port ([string]$q['proto']) 4000)
        }
        elseif($path -eq "/api/mac"){ Send-Json $stream @{ mac=(Do-Mac ([string]$q['host'])) } }
        elseif($path -eq "/api/ports"){ Send-Json $stream @{ services=(Do-Ports ([string]$q['host'])) } }
        else{ Send-Bytes $stream 404 "application/json" ([System.Text.Encoding]::UTF8.GetBytes('{"error":"not found"}')) }
    }catch{
        try{ Send-Bytes $client.GetStream() 500 "application/json" ([System.Text.Encoding]::UTF8.GetBytes('{"error":"server"}')) }catch{}
    }finally{
        try{ $client.Close() }catch{}
    }
}
