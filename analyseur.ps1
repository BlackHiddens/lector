<#
============================================================================
 analyseur.ps1 - Analyse locale des serveurs web + port de switch (SNMP)
 Complement de l'application "Surveillance IP" (index.html).
 100 % PowerShell (deja present dans Windows). AUCUNE installation.

 Ce qu'il fait pour chaque adresse :
   - ouvre http(s)://IP et lit : titre de la page (<title>), en-tete "Server",
     realm d'authentification -> en deduit le TYPE de serveur embarque
   - propose un LIBELLE (titre en priorite)
   - (option) demande au SWITCH, en SNMP, sur quel PORT est branchee l'adresse

 Produit un JSON a reimporter dans l'application (bouton "Importer").

 ---------------------------------------------------------------------------
 UTILISATION (dans PowerShell, depuis le dossier du script)
 ---------------------------------------------------------------------------
   # Verifier d'abord que tout est OK (encodage SNMP, plages, detection) :
   powershell -ExecutionPolicy Bypass -File .\analyseur.ps1 -SelfTest

   # A partir de l'export JSON de l'application :
   powershell -ExecutionPolicy Bypass -File .\analyseur.ps1 -In surveillance-ip.json -Out analyse.json

   # A partir d'une plage / d'IP :
   powershell -ExecutionPolicy Bypass -File .\analyseur.ps1 -Range 192.168.1.0/24 -Out analyse.json
   powershell -ExecutionPolicy Bypass -File .\analyseur.ps1 -Ips 192.168.1.10,192.168.1.20 -Out analyse.json

   # En ajoutant le port de switch via SNMP :
   powershell -ExecutionPolicy Bypass -File .\analyseur.ps1 -In surveillance-ip.json -Out analyse.json -Switch 192.168.1.2 -Community public

 Le "-ExecutionPolicy Bypass" ne modifie rien sur ta machine : il autorise
 juste ce lancement.
 ---------------------------------------------------------------------------
 NOTE port de switch : lu SUR LE SWITCH (SNMP en lecture requise), croise avec
 la table ARP de cette machine. A lancer depuis le meme sous-reseau que les
 modules. Un module en cascade apparait sur le port de liaison (uplink).
============================================================================
#>

[CmdletBinding()]
param(
    [string]$In,
    [string[]]$Range,
    [string[]]$Ips,
    [string]$Out = "analyse.json",
    [int]$Port = 0,
    [ValidateSet("http","https")][string]$Proto = "http",
    [double]$Timeout = 4,
    [string]$Switch,
    [string]$Community = "public",
    [ValidateSet("1","2c")][string]$SnmpVersion = "2c",
    [double]$SnmpTimeout = 2,
    [switch]$SelfTest
)

$ErrorActionPreference = "Stop"

# ---- OID SNMP --------------------------------------------------------------
$OID_Q_FDB           = "1.3.6.1.2.1.17.7.1.2.2.1.2"   # dot1qTpFdbPort
$OID_D_FDB           = "1.3.6.1.2.1.17.4.3.1.2"       # dot1dTpFdbPort
$OID_BASEPORT_IFINDEX= "1.3.6.1.2.1.17.1.4.1.2"       # dot1dBasePortIfIndex
$OID_IFNAME          = "1.3.6.1.2.1.31.1.1.1.1"       # ifName
$OID_IFDESCR         = "1.3.6.1.2.1.2.2.1.2"          # ifDescr
$OID_ARP             = "1.3.6.1.2.1.4.22.1.2"         # ipNetToMediaPhysAddress

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
    @('gunicorn','Gunicorn (Python)'),
    @('jetty','Jetty (Java)'),
    @('coyote|tomcat','Apache Tomcat (Java)'),
    @('express|node','Node.js'),
    @('espressif|esp8266|esp-idf|esphttpd','Espressif ESP (IoT)'),
    @('shelly','Shelly (IoT)'),
    @('httpd','httpd embarque (generique)')
)

# ===========================================================================
#  BER / ASN.1 - encodage (renvoient un byte[] unique via l'operateur ,)
# ===========================================================================
function Cat {
    param([byte[]]$a,[byte[]]$b)
    if ($null -eq $a) { $a = [byte[]]@() }
    if ($null -eq $b) { $b = [byte[]]@() }
    $r = [byte[]]::new($a.Length + $b.Length)
    if ($a.Length) { [System.Array]::Copy($a,0,$r,0,$a.Length) }
    if ($b.Length) { [System.Array]::Copy($b,0,$r,$a.Length,$b.Length) }
    ,$r
}
function BerLen {
    param([int]$n)
    if ($n -lt 0x80) { return ,([byte[]]@([byte]$n)) }
    $tmp = [System.Collections.Generic.List[byte]]::new()
    while ($n -gt 0) { $tmp.Insert(0,[byte]($n -band 0xff)); $n = $n -shr 8 }
    $arr = [System.Collections.Generic.List[byte]]::new()
    [void]$arr.Add([byte](0x80 -bor $tmp.Count))
    [void]$arr.AddRange($tmp)
    ,([byte[]]$arr.ToArray())
}
function Tlv {
    param([byte]$tag,[byte[]]$val)
    if ($null -eq $val) { $val = [byte[]]@() }
    [byte[]]$len = BerLen $val.Length
    [byte[]]$out = Cat (Cat ([byte[]]@($tag)) $len) $val
    ,$out
}
function EncInt {
    param([long]$n)
    if ($n -eq 0) { [byte[]]$body = @([byte]0) }
    else {
        $bytes = [System.BitConverter]::GetBytes([int64]$n)
        [array]::Reverse($bytes)                       # big-endian, 8 octets
        $i = 0
        while ($i -lt $bytes.Length-1 -and $bytes[$i] -eq 0    -and (($bytes[$i+1] -band 0x80) -eq 0)) { $i++ }
        while ($i -lt $bytes.Length-1 -and $bytes[$i] -eq 0xff -and (($bytes[$i+1] -band 0x80) -ne 0)) { $i++ }
        [byte[]]$body = $bytes[$i..($bytes.Length-1)]
    }
    Tlv 0x02 $body
}
function EncOid {
    param([string]$oid)
    $parts = @($oid.Split('.') | ForEach-Object { [int]$_ })
    $body = [System.Collections.Generic.List[byte]]::new()
    [void]$body.Add([byte](40*$parts[0] + $parts[1]))
    for ($k=2; $k -lt $parts.Count; $k++) {
        $p = [int]$parts[$k]
        if ($p -lt 0x80) { [void]$body.Add([byte]$p) }
        else {
            $stack = [System.Collections.Generic.List[byte]]::new()
            [void]$stack.Add([byte]($p -band 0x7f)); $p = $p -shr 7
            while ($p -gt 0) { [void]$stack.Add([byte](($p -band 0x7f) -bor 0x80)); $p = $p -shr 7 }
            for ($z=$stack.Count-1; $z -ge 0; $z--) { [void]$body.Add($stack[$z]) }
        }
    }
    Tlv 0x06 ([byte[]]$body.ToArray())
}
function EncOctStr {
    param($s)
    if ($s -is [string]) { $b = [System.Text.Encoding]::ASCII.GetBytes($s) } else { $b = [byte[]]$s }
    Tlv 0x04 $b
}
function EncNull { ,([byte[]]@(0x05,0x00)) }

function Build-GetNext {
    param([string]$community,[string]$oid,[long]$reqid,[int]$version)
    [byte[]]$vb      = Tlv 0x30 (Cat (EncOid $oid) (EncNull))
    [byte[]]$vblist  = Tlv 0x30 $vb
    [byte[]]$pdubody = Cat (Cat (Cat (EncInt $reqid) (EncInt 0)) (EncInt 0)) $vblist
    [byte[]]$pdu     = Tlv 0xA1 $pdubody
    [byte[]]$msgbody = Cat (Cat (EncInt $version) (EncOctStr $community)) $pdu
    [byte[]]$msg     = Tlv 0x30 $msgbody
    ,$msg
}

# ===========================================================================
#  BER / ASN.1 - decodage
# ===========================================================================
function Read-Len {
    param([byte[]]$d,[int]$i)
    $b = $d[$i]; $i++
    if ($b -lt 0x80) { $r = New-Object object[] 2; $r[0]=[int]$b; $r[1]=$i; return $r }
    $n = $b -band 0x7f; $len = 0
    for ($k=0; $k -lt $n; $k++) { $len = ($len -shl 8) -bor [int]$d[$i]; $i++ }
    $r = New-Object object[] 2; $r[0]=$len; $r[1]=$i; return $r
}
function Read-Tlv {
    param([byte[]]$d,[int]$i)
    $tag = [int]$d[$i]; $i++
    $lp = Read-Len $d $i; $len = [int]$lp[0]; $i = [int]$lp[1]
    if ($len -eq 0) { $val = [byte[]]@() } else { $val = [byte[]]($d[$i..($i+$len-1)]) }
    $i = $i + $len
    $r = New-Object object[] 3; $r[0]=$tag; $r[1]=$val; $r[2]=$i; return $r
}
function Dec-Oid {
    param([byte[]]$b)
    if ($b.Length -eq 0) { return "" }
    $parts = [System.Collections.Generic.List[string]]::new()
    [void]$parts.Add([string]([int][math]::Floor([int]$b[0] / 40)))
    [void]$parts.Add([string]([int]$b[0] % 40))
    $n = 0
    for ($k=1; $k -lt $b.Length; $k++) {
        $c = $b[$k]
        $n = ($n -shl 7) -bor ($c -band 0x7f)
        if (($c -band 0x80) -eq 0) { [void]$parts.Add([string]$n); $n = 0 }
    }
    return ($parts -join '.')
}
function ConvertTo-UInt {
    param([byte[]]$b)
    $n = 0
    foreach ($x in $b) { $n = ($n -shl 8) -bor [int]$x }
    return $n
}
function Parse-SnmpResponse {
    param([byte[]]$data)
    $binds = [System.Collections.Generic.List[object]]::new()
    $m = Read-Tlv $data 0; $msg = $m[1]
    $i = 0
    $t = Read-Tlv $msg $i; $i = $t[2]                 # version
    $t = Read-Tlv $msg $i; $i = $t[2]                 # community
    $t = Read-Tlv $msg $i; $pdu = $t[1]               # PDU
    $j = 0
    $t = Read-Tlv $pdu $j; $j = $t[2]                 # request-id
    $t = Read-Tlv $pdu $j; $j = $t[2]                 # error-status
    $t = Read-Tlv $pdu $j; $j = $t[2]                 # error-index
    $t = Read-Tlv $pdu $j; $vbl = $t[1]               # varbind list
    $k = 0
    while ($k -lt $vbl.Length) {
        $t = Read-Tlv $vbl $k; $vb = $t[1]; $k = $t[2]
        $mm = 0
        $o = Read-Tlv $vb $mm; $oidb = $o[1]; $mm = $o[2]
        $v = Read-Tlv $vb $mm; $vtag = $v[0]; $vval = $v[1]
        [void]$binds.Add([pscustomobject]@{ Oid = (Dec-Oid $oidb); Tag = [int]$vtag; Val = $vval })
    }
    ,$binds
}

# ===========================================================================
#  SNMP GET-NEXT / WALK (UDP 161)
# ===========================================================================
function Invoke-SnmpGetNext {
    param($udp,[string]$community,[string]$oid,[int]$version)
    $reqid = Get-Random -Minimum 1 -Maximum 2000000000
    [byte[]]$pkt = Build-GetNext $community $oid $reqid $version
    for ($try=0; $try -lt 3; $try++) {
        try {
            [void]$udp.Send($pkt,$pkt.Length)
            $ep = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any,0)
            [byte[]]$data = $udp.Receive([ref]$ep)
            $binds = Parse-SnmpResponse $data
            if ($binds.Count -gt 0) { return $binds[0] }
            return $null
        }
        catch [System.Net.Sockets.SocketException] { continue }
        catch { return $null }
    }
    return $null
}
function Invoke-SnmpWalk {
    param([string]$switchIp,[string]$community,[int]$version,[double]$timeout,[string]$base)
    $udp = [System.Net.Sockets.UdpClient]::new()
    $udp.Client.ReceiveTimeout = [int]($timeout*1000)
    $udp.Connect($switchIp,161)
    $res = [System.Collections.Generic.List[object]]::new()
    $cur = $base
    try {
        while ($true) {
            $vb = Invoke-SnmpGetNext $udp $community $cur $version
            if ($null -eq $vb) { break }
            if ($vb.Tag -eq 0x80 -or $vb.Tag -eq 0x81 -or $vb.Tag -eq 0x82) { break }
            if (-not ($vb.Oid -eq $base -or $vb.Oid.StartsWith($base + "."))) { break }
            [void]$res.Add($vb)
            $cur = $vb.Oid
            if ($res.Count -ge 60000) { break }
        }
    } finally { $udp.Close() }
    ,$res
}

# ===========================================================================
#  Construction des tables SNMP -> hashtables
# ===========================================================================
function Get-FdbMap {
    param($walk,[string]$base,[bool]$q)
    $d = @{}; $blen = $base.Length; $need = if ($q) { 7 } else { 6 }
    foreach ($vb in $walk) {
        $nums = $vb.Oid.Substring($blen+1).Split('.')
        if ($nums.Count -lt $need) { continue }
        $mac = ""
        for ($z=$nums.Count-6; $z -lt $nums.Count; $z++) { $mac += ('{0:x2}' -f ([int]$nums[$z] -band 0xff)) }
        $port = ConvertTo-UInt $vb.Val
        if ($port -eq 0) { continue }
        if (-not $d.ContainsKey($mac)) { $d[$mac] = $port }
    }
    ,$d
}
function Get-IntMap {
    param($walk,[string]$base)
    $d = @{}; $blen = $base.Length
    foreach ($vb in $walk) {
        $key = [int]($vb.Oid.Substring($blen+1).Split('.')[0])
        $d[$key] = ConvertTo-UInt $vb.Val
    }
    ,$d
}
function Get-NameMap {
    param($walk,[string]$base)
    $d = @{}; $blen = $base.Length
    foreach ($vb in $walk) {
        $key = [int]($vb.Oid.Substring($blen+1).Split('.')[0])
        $name = ([System.Text.Encoding]::ASCII.GetString($vb.Val)).Trim([char]0).Trim()
        if ($name) { $d[$key] = $name }
    }
    ,$d
}
function Get-SwitchArp {
    param($walk,[string]$base)
    $d = @{}; $blen = $base.Length
    foreach ($vb in $walk) {
        $nums = $vb.Oid.Substring($blen+1).Split('.')
        if ($nums.Count -lt 5 -or $vb.Val.Length -ne 6) { continue }
        $ip = ($nums[($nums.Count-4)..($nums.Count-1)] -join '.')
        $mac = ""; foreach ($x in $vb.Val) { $mac += ('{0:x2}' -f [int]$x) }
        if ($mac -ne '000000000000') { $d[$ip] = $mac }
    }
    ,$d
}
function Resolve-SwitchPort {
    param($mac,$qfdb,$dfdb,$bp2if,$if2name,$switchIp)
    $port = $null
    if ($qfdb.ContainsKey($mac)) { $port = $qfdb[$mac] }
    elseif ($dfdb.ContainsKey($mac)) { $port = $dfdb[$mac] }
    if ($null -eq $port) { return $null }
    $ifidx = if ($bp2if.ContainsKey($port)) { $bp2if[$port] } else { $port }
    $name  = if ($if2name.ContainsKey($ifidx)) { $if2name[$ifidx] } else { "port $port" }
    $sep = [string][char]0x00B7   # point median, compatible PowerShell 5.1 et 7
    return ("{0} {1} {2}" -f $switchIp,$sep,$name)
}

# ===========================================================================
#  Table ARP locale
# ===========================================================================
function Get-LocalArp {
    $t = @{}
    try {
        $out = & arp -a 2>$null
        foreach ($line in $out) {
            $ipm  = [regex]::Match($line,'(\d{1,3}(\.\d{1,3}){3})')
            $macm = [regex]::Match($line,'([0-9A-Fa-f]{2}([-:][0-9A-Fa-f]{2}){5})')
            if ($ipm.Success -and $macm.Success) {
                $mac = ($macm.Value -replace '[-:]','').ToLower()
                if ($mac -ne '000000000000' -and -not $t.ContainsKey($ipm.Value)) { $t[$ipm.Value] = $mac }
            }
        }
    } catch { }
    ,$t
}

# ===========================================================================
#  Analyse HTTP
# ===========================================================================
function Test-Tcp {
    param([string]$ip,[int]$port,[int]$ms)
    $c = [System.Net.Sockets.TcpClient]::new()
    try {
        $iar = $c.BeginConnect($ip,$port,$null,$null)
        if ($iar.AsyncWaitHandle.WaitOne($ms)) { try { $c.EndConnect($iar); return $true } catch { return $false } }
        return $false
    } catch { return $false } finally { $c.Close() }
}
function Invoke-Probe {
    param([string]$ip,[int]$port,[string]$proto,[double]$timeout)
    $url = "$proto`://$ip" + $(if ($port -gt 0) { ":$port" } else { "" }) + "/"
    $server = ""; $realm = ""; $title = ""
    try {
        $req = [System.Net.HttpWebRequest]::Create($url)
        $req.Method = "GET"; $req.Timeout = [int]($timeout*1000); $req.ReadWriteTimeout = [int]($timeout*1000)
        $req.UserAgent = "IPWatch-Analyzer/1.0"; $req.AllowAutoRedirect = $true
        $resp = $null
        try { $resp = $req.GetResponse() }
        catch [System.Net.WebException] {
            $resp = $_.Exception.Response
            if ($null -eq $resp) { return $null }
        }
        $server = [string]$resp.Headers["Server"]
        $wa = [string]$resp.Headers["WWW-Authenticate"]
        if ($wa -match 'realm\s*=\s*"([^"]*)"') { $realm = $matches[1] }
        $stream = $resp.GetResponseStream()
        $ms = [System.IO.MemoryStream]::new(); $buf = [byte[]]::new(4096); $tot = 0
        while ($tot -lt 20000) { $rd = $stream.Read($buf,0,$buf.Length); if ($rd -le 0) { break }; $ms.Write($buf,0,$rd); $tot += $rd }
        $resp.Close()
        $body = [System.Text.Encoding]::UTF8.GetString($ms.ToArray())
        if ($body -match '(?is)<title[^>]*>(.*?)</title>') {
            $title = ($matches[1] -replace '\s+',' ').Trim()
            if ($title.Length -gt 90) { $title = $title.Substring(0,90) }
        }
    } catch { return $null }
    return [pscustomobject]@{ server = $server.Trim(); realm = $realm; title = $title }
}
function Detect-Server {
    param($server,$realm,$title)
    $hay = ("{0} {1} {2}" -f $server,$realm,$title).ToLower()
    foreach ($s in $SERVER_SIGNATURES) { if ($hay -match $s[0]) { return $s[1] } }
    return ""
}
function Make-Label {
    param($title,$realm,$detected)
    if ($title)    { return $title }
    if ($realm)    { return $realm }
    if ($detected) { return ($detected -split ' \(')[0] }
    return "Serveur web"
}
function Analyze-Target {
    param($t,[double]$timeout)
    $ip = $t.addr
    if ($t.port) { $cands = @(@{proto = $(if ($t.proto) { $t.proto } else { 'http' }); port = [int]$t.port}) }
    else { $cands = @(@{proto='http';port=0}, @{proto='https';port=0}, @{proto='http';port=8080}, @{proto='https';port=8443}) }

    $info = $null
    $usedProto = if ($t.proto) { $t.proto } else { 'http' }
    $usedPort  = $t.port
    foreach ($c in $cands) {
        $p = if ($c.port -eq 0) { if ($c.proto -eq 'https') { 443 } else { 80 } } else { [int]$c.port }
        if (-not (Test-Tcp $ip $p 700)) { continue }
        $r = Invoke-Probe $ip ([int]$c.port) $c.proto $timeout
        if ($null -ne $r) { $info = $r; $usedProto = $c.proto; $usedPort = $c.port; break }
    }
    if ($null -eq $info) { return $null }

    $detected = Detect-Server $info.server $info.realm $info.title
    $rec = [ordered]@{ addr = $ip }
    if ($t.from_file) {
        $rec.port  = $(if ($t.port) { [int]$t.port } else { $null })
        $rec.proto = $(if ($t.proto) { $t.proto } else { 'http' })
    } else {
        $rec.port  = $(if ($usedPort) { [int]$usedPort } else { $null })
        $rec.proto = $usedProto
    }
    if ($info.server)  { $rec.server   = $info.server }
    if ($info.title)   { $rec.title    = $info.title }
    if ($detected)     { $rec.detected = $detected }
    $rec.label = Make-Label $info.title $info.realm $detected
    return $rec
}

# ===========================================================================
#  Plages d'adresses
# ===========================================================================
function IpToUInt {
    param([string]$ip)
    $o = $ip.Split('.')
    if ($o.Count -ne 4) { return $null }
    $n = [uint64]0
    foreach ($x in $o) { $v = [int]$x; if ($v -lt 0 -or $v -gt 255) { return $null }; $n = ($n*256) + $v }
    return [uint32]$n
}
function UIntToIp {
    param([uint32]$n)
    return ("{0}.{1}.{2}.{3}" -f (($n -shr 24) -band 255), (($n -shr 16) -band 255), (($n -shr 8) -band 255), ($n -band 255))
}
function Expand-Range {
    param([string]$s)
    $s = $s.Trim()
    $res = [System.Collections.Generic.List[string]]::new()
    if ($s -match '^(\d+\.\d+\.\d+\.\d+)/(\d+)$') {
        $base = IpToUInt $matches[1]; $bits = [int]$matches[2]
        if ($null -ne $base -and $bits -ge 0 -and $bits -le 32) {
            $size = [uint64][math]::Pow(2, 32-$bits)
            $mask = if ($bits -eq 0) { [uint32]0 } else { [uint32](((0xFFFFFFFFL -shl (32-$bits)) -band 0xFFFFFFFFL)) }
            $net = [uint64]([uint32]$base -band $mask)
            $start = $net; $end = $net + $size - 1
            if ($bits -lt 31) { $start = $net + 1; $end = $net + $size - 2 }
            if (($end - $start + 1) -le 512) { for ($x=$start; $x -le $end; $x++) { [void]$res.Add((UIntToIp ([uint32]$x))) } }
        }
    }
    elseif ($s -match '^(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+\.\d+\.\d+\.\d+)$') {
        $a = [uint64](IpToUInt $matches[1]); $b = [uint64](IpToUInt $matches[2])
        if ($b -lt $a) { $tmp=$a; $a=$b; $b=$tmp }
        if (($b - $a + 1) -le 512) { for ($x=$a; $x -le $b; $x++) { [void]$res.Add((UIntToIp ([uint32]$x))) } }
    }
    elseif ($s -match '^(\d+\.\d+\.\d+)\.(\d+)\s*-\s*(\d+)$') {
        $pre = $matches[1]; $lo = [int]$matches[2]; $hi = [int]$matches[3]
        if ($hi -lt $lo) { $tmp=$lo; $lo=$hi; $hi=$tmp }
        if (($hi - $lo + 1) -le 512 -and $hi -le 255) { for ($k=$lo; $k -le $hi; $k++) { [void]$res.Add("$pre.$k") } }
    }
    else { [void]$res.Add($s) }
    ,$res
}

# ===========================================================================
#  Auto-test (verifie l'encodage SNMP, les plages, la detection)
# ===========================================================================
function Invoke-SelfTest {
    $ok = $true
    function Check($name,$cond) {
        if ($cond) { Write-Host ("  [OK] " + $name) -ForegroundColor Green }
        else { Write-Host ("  [FAIL] " + $name) -ForegroundColor Red; $script:ok = $false }
    }
    Write-Host "Auto-test analyseur.ps1" -ForegroundColor Cyan

    # 1) BER round-trip : encoder un GetNext, basculer le tag PDU 0xA1 -> 0xA2, reparser
    $oid = "1.3.6.1.2.1.17.4.3.1.2"
    [byte[]]$pkt = Build-GetNext "public" $oid 12345 1
    $idx = [array]::IndexOf($pkt, [byte]0xA1)
    Check "0xA1 present dans le paquet" ($idx -ge 0)
    $pkt[$idx] = 0xA2
    $binds = Parse-SnmpResponse $pkt
    Check "BER round-trip : 1 varbind" ($binds.Count -eq 1)
    Check "BER round-trip : OID conserve" ($binds[0].Oid -eq $oid)

    # 2) OID enc/dec
    foreach ($o in @("1.3.6.1.2.1.31.1.1.1.1","1.3.6.1.2.1.4.22.1.2.10.192.168.1.20","1.3.6.1.2.1.17.7.1.2.2.1.2.0.0.28.171.205.239.18")) {
        [byte[]]$enc = EncOid $o
        $tv = Read-Tlv $enc 0
        Check ("OID enc/dec " + $o) ((Dec-Oid $tv[1]) -eq $o)
    }

    # 3) FDB -> port -> ifName
    $base = $OID_D_FDB
    $walk = @([pscustomobject]@{ Oid = ($base + ".0.28.171.205.239.18"); Tag = 2; Val = [byte[]]@(24) })
    $fdb = Get-FdbMap $walk $base $false
    Check "FDB MAC->port" ($fdb["001cabcdef12"] -eq 24)
    $bp = Get-IntMap @([pscustomobject]@{ Oid = ($OID_BASEPORT_IFINDEX + ".24"); Tag=2; Val=[byte[]]@(0x27,0x28) }) $OID_BASEPORT_IFINDEX
    Check "basePort->ifIndex" ($bp[24] -eq 10024)
    $nm = Get-NameMap @([pscustomobject]@{ Oid = ($OID_IFNAME + ".10024"); Tag=4; Val=[System.Text.Encoding]::ASCII.GetBytes("Gi1/0/12") }) $OID_IFNAME
    Check "ifIndex->ifName" ($nm[10024] -eq "Gi1/0/12")
    $sp = Resolve-SwitchPort "001cabcdef12" @{} $fdb $bp $nm "192.168.1.2"
    Check "resolution port switch" ($sp -match "Gi1/0/12" -and $sp -match "192.168.1.2")

    # 4) ARP switch
    $sa = Get-SwitchArp @([pscustomobject]@{ Oid = ($OID_ARP + ".10.192.168.1.20"); Tag=4; Val=[byte[]]@(0,0x1c,0xab,0xcd,0xef,0x12) }) $OID_ARP
    Check "ARP switch IP->MAC" ($sa["192.168.1.20"] -eq "001cabcdef12")

    # 5) Plages
    Check "plage /30" (((Expand-Range "10.0.0.0/30") -join ',') -eq "10.0.0.1,10.0.0.2")
    Check "plage dernier octet" (((Expand-Range "192.168.1.10-12") -join ',') -eq "192.168.1.10,192.168.1.11,192.168.1.12")

    # 6) Detection + libelle
    $det = Detect-Server "GoAhead-Webs" "" "WAGO 750-8202"
    Check "detection GoAhead" ($det -match "GoAhead")
    Check "libelle = titre" ((Make-Label "WAGO 750-8202" "" $det) -eq "WAGO 750-8202")

    Write-Host ""
    if ($script:ok) { Write-Host "TOUS LES TESTS PASSENT - l'encodage SNMP et le reste sont bons." -ForegroundColor Green }
    else { Write-Host "DES TESTS ECHOUENT - ne pas se fier au resultat, previens-moi." -ForegroundColor Red }
}

# ===========================================================================
#  Programme principal
# ===========================================================================
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { param($s,$c,$ch,$e) $true }
try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls } catch { }

if ($SelfTest) { Invoke-SelfTest; return }

if (-not $In -and -not $Range -and -not $Ips) {
    Write-Host "Rien a analyser. Utilise -In, -Range ou -Ips (ou -SelfTest)." -ForegroundColor Yellow
    Write-Host "Aide : Get-Help .\analyseur.ps1  ou lis l'entete du fichier."
    return
}

# ---- chargement des cibles -------------------------------------------------
$targets = [System.Collections.Generic.List[object]]::new()
$seen = @{}
function Add-Target {
    param($addr,$port,$proto,$fromFile)
    $addr = [string]$addr
    if (-not $addr) { return }
    $key = "$addr|$port"
    if ($seen.ContainsKey($key)) { return }
    $seen[$key] = $true
    [void]$targets.Add([pscustomobject]@{ addr=$addr; port=$port; proto=$proto; from_file=$fromFile })
}
if ($In) {
    $data = Get-Content -Raw -Path $In | ConvertFrom-Json
    foreach ($x in $data) { if ($x.addr) { Add-Target $x.addr $x.port $x.proto $true } }
}
foreach ($r in $Range) { foreach ($ip in (Expand-Range $r)) { Add-Target $ip $(if ($Port) { $Port } else { $null }) $Proto $false } }
foreach ($ip in $Ips)  { Add-Target $ip $(if ($Port) { $Port } else { $null }) $Proto $false }

Write-Host ("[HTTP] Analyse de {0} adresse(s)..." -f $targets.Count) -ForegroundColor Cyan

# ---- analyse HTTP ----------------------------------------------------------
$records = [System.Collections.Generic.List[object]]::new()
foreach ($t in $targets) {
    $rec = Analyze-Target $t $Timeout
    if ($rec) { [void]$records.Add($rec) }
}
Write-Host ("[HTTP] {0} serveur(s) web ont repondu." -f $records.Count)

# ---- SNMP : port de switch -------------------------------------------------
if ($Switch) {
    Write-Host ("[SNMP] Interrogation du switch {0} ..." -f $Switch) -ForegroundColor Cyan
    $version = if ($SnmpVersion -eq '2c') { 1 } else { 0 }
    $arp = Get-LocalArp
    try {
        $qfdb   = Get-FdbMap  (Invoke-SnmpWalk $Switch $Community $version $SnmpTimeout $OID_Q_FDB) $OID_Q_FDB $true
        $dfdb   = Get-FdbMap  (Invoke-SnmpWalk $Switch $Community $version $SnmpTimeout $OID_D_FDB) $OID_D_FDB $false
        $bp2if  = Get-IntMap  (Invoke-SnmpWalk $Switch $Community $version $SnmpTimeout $OID_BASEPORT_IFINDEX) $OID_BASEPORT_IFINDEX
        $if2name= Get-NameMap (Invoke-SnmpWalk $Switch $Community $version $SnmpTimeout $OID_IFNAME) $OID_IFNAME
        if ($if2name.Count -eq 0) { $if2name = Get-NameMap (Invoke-SnmpWalk $Switch $Community $version $SnmpTimeout $OID_IFDESCR) $OID_IFDESCR }
        $sarp   = Get-SwitchArp (Invoke-SnmpWalk $Switch $Community $version $SnmpTimeout $OID_ARP) $OID_ARP
    } catch {
        Write-Host ("[SNMP] Erreur : {0} (port de switch ignore)." -f $_.Exception.Message) -ForegroundColor Yellow
        $qfdb = @{}; $dfdb = @{}
    }
    foreach ($ip in $sarp.Keys) { if (-not $arp.ContainsKey($ip)) { $arp[$ip] = $sarp[$ip] } }

    if (($qfdb.Count -eq 0) -and ($dfdb.Count -eq 0)) {
        Write-Host "[SNMP] Aucune table de commutation lue (communaute erronee, SNMP desactive, ou pas de bridge-MIB). Port de switch ignore." -ForegroundColor Yellow
    } else {
        $found = 0
        foreach ($rec in $records) {
            $mac = $arp[$rec['addr']]
            if (-not $mac) { continue }
            $sp = Resolve-SwitchPort $mac $qfdb $dfdb $bp2if $if2name $Switch
            if ($sp) { $rec['switchport'] = $sp; $found++ }
        }
        Write-Host ("[SNMP] Port de switch trouve pour {0} appareil(s)." -f $found)
    }
}

# ---- tri par IP ------------------------------------------------------------
$sorted = $records | Sort-Object { if ($_['addr'] -match '^\d+\.\d+\.\d+\.\d+$') { [version]$_['addr'] } else { $_['addr'] } }
$records = @($sorted)

# ---- ecriture JSON (sans BOM, format tableau) ------------------------------
if ($records.Count -eq 0)      { $text = "[]" }
elseif ($records.Count -eq 1)  { $text = "[" + ($records[0] | ConvertTo-Json -Depth 6) + "]" }
else                           { $text = $records | ConvertTo-Json -Depth 6 }

$full = if ([System.IO.Path]::IsPathRooted($Out)) { $Out } else { Join-Path (Get-Location).Path $Out }
[System.IO.File]::WriteAllText($full, $text, [System.Text.UTF8Encoding]::new($false))

# ---- recapitulatif ---------------------------------------------------------
Write-Host ""
Write-Host ("=== Resultat ({0} appareil(s)) ===" -f $records.Count)
foreach ($rec in $records) {
    $line = ("  {0,-16} {1}" -f $rec['addr'], $rec['label'])
    $extra = @()
    if ($rec['detected'])   { $extra += $rec['detected'] }
    if ($rec['server'])     { $extra += ("Server: " + $rec['server']) }
    if ($rec['switchport']) { $extra += ("Switch: " + $rec['switchport']) }
    if ($extra.Count) { $line += "  [" + ($extra -join " | ") + "]" }
    Write-Host $line
}
Write-Host ""
Write-Host ("Fichier ecrit : {0}" -f $full)
Write-Host "-> Dans l'application : bouton `"Importer`" puis choisis ce fichier."
