#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analyseur.py — Analyse locale des serveurs web + port de switch (SNMP).

Complement de l'application "Surveillance IP" (index.html). Le navigateur ne
peut PAS lire le titre d'une page ni l'en-tete Server d'un autre appareil
(regle CORS) : ce petit outil le fait a sa place, en local, puis produit un
fichier JSON que tu reimportes dans l'application (bouton "Importer").

100 % bibliotheque standard Python 3 — AUCUN paquet a installer (pas de pip).
Fonctionne sous Windows, macOS et Linux.

Ce qu'il fait pour chaque adresse :
  - ouvre http(s)://IP et lit :
      * le titre de la page  (<title>)
      * l'en-tete HTTP "Server"
      * le "realm" d'authentification (si l'appareil demande un mot de passe)
  - en deduit un TYPE de serveur embarque (GoAhead, Boa, lwIP, RomPager...)
  - propose un LIBELLE (titre de la page en priorite)
  - (option) demande au SWITCH, en SNMP, sur quel PORT physique est branchee
    l'adresse (table de commutation MAC croisee avec la table ARP).

------------------------------------------------------------------------------
EXEMPLES
------------------------------------------------------------------------------
  # A partir de l'export JSON de l'application :
  python analyseur.py --in surveillance-ip.json --out analyse.json

  # A partir d'une plage / d'IP directement :
  python analyseur.py --range 192.168.1.0/24 --out analyse.json
  python analyseur.py --ips 192.168.1.10 192.168.1.20 --out analyse.json

  # En ajoutant le port de switch via SNMP (communaute lecture "public") :
  python analyseur.py --in surveillance-ip.json --out analyse.json \\
         --switch 192.168.1.2 --community public

  # SANS connaitre l'IP du switch : on scanne le reseau, l'outil trouve les
  # switches SNMP tout seul et donne switch + port pour chaque module :
  python analyseur.py --in surveillance-ip.json --out analyse.json \\
         --discover 192.168.1.0/24 --community public

Ensuite : dans l'app -> "Importer" -> choisis analyse.json.
Les libelles vides se remplissent, sans doublon ; le type/serveur/titre et le
port de switch s'affichent sur chaque carte.

------------------------------------------------------------------------------
NOTES IMPORTANTES
------------------------------------------------------------------------------
  * Le port de switch est lu SUR LE SWITCH (c'est lui qui sait), pas sur le
    module. Il faut donc l'IP du switch et sa communaute SNMP en LECTURE.
  * La correspondance IP <-> MAC vient de la table ARP de cette machine (donc
    lance l'outil depuis une machine du meme reseau/sous-reseau que les
    modules) et, en complement, de la table ARP du switch s'il est routeur L3.
  * Si un module est derriere un autre switch en cascade, son MAC apparaitra
    sur le port de liaison (uplink) — c'est le fonctionnement normal du L2.
"""

import argparse
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


# ============================================================================
#  Partie 1 — Analyse HTTP (titre, Server, type de module)
# ============================================================================

SERVER_SIGNATURES = [
    (r"goahead|embedthis", "GoAhead (serveur web embarque)"),
    (r"\bboa\b", "Boa (embarque)"),
    (r"mongoose|cesanta", "Mongoose (embarque)"),
    (r"lwip", "lwIP HTTPD (embarque)"),
    (r"rompager|allegro", "Allegro RomPager (embarque)"),
    (r"uc-httpd", "uc-httpd (camera/embarque)"),
    (r"mini_httpd", "mini_httpd (embarque)"),
    (r"thttpd", "thttpd (embarque)"),
    (r"webs\b", "GoAhead/Webs (embarque)"),
    (r"lighttpd", "lighttpd"),
    (r"nginx", "nginx"),
    (r"apache", "Apache httpd"),
    (r"microsoft-iis|\biis\b", "Microsoft IIS"),
    (r"werkzeug|flask", "Python Werkzeug/Flask"),
    (r"gunicorn", "Gunicorn (Python)"),
    (r"tornado", "Tornado (Python)"),
    (r"jetty", "Jetty (Java)"),
    (r"coyote|tomcat", "Apache Tomcat (Java)"),
    (r"express|node", "Node.js"),
    (r"espressif|esp8266|esp-idf|esphttpd", "Espressif ESP (IoT)"),
    (r"shelly", "Shelly (IoT)"),
    (r"httpd", "httpd embarque (generique)"),
]

TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
REALM_RE = re.compile(r'realm\s*=\s*"([^"]*)"', re.IGNORECASE)


def parse_title(body):
    if not body:
        return ""
    m = TITLE_RE.search(body)
    if not m:
        return ""
    raw = m.group(1)
    for enc in ("utf-8", "latin-1"):
        try:
            txt = raw.decode(enc)
            break
        except Exception:
            txt = raw.decode("utf-8", "replace")
    txt = re.sub(r"\s+", " ", txt).strip()
    return txt[:90]


def parse_realm(www_auth):
    if not www_auth:
        return ""
    m = REALM_RE.search(www_auth)
    return (m.group(1).strip()[:90]) if m else ""


def detect_server(server, realm, title):
    hay = " ".join([server or "", realm or "", title or ""]).lower()
    for pat, label in SERVER_SIGNATURES:
        if re.search(pat, hay):
            return label
    return ""


def http_probe(ip, port, proto, timeout):
    """Retourne un dict {status, server, realm, title} ou None si aucune reponse."""
    url = "%s://%s%s/" % (proto, ip, (":%d" % port) if port else "")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = Request(url, headers={"User-Agent": "IPWatch-Analyzer/1.0", "Accept": "*/*"})
    server = realm = title = ""
    status = None
    body = b""
    try:
        resp = urlopen(req, timeout=timeout, context=ctx)
        status = getattr(resp, "status", None) or resp.getcode()
        server = resp.headers.get("Server", "") or ""
        realm = parse_realm(resp.headers.get("WWW-Authenticate", ""))
        body = resp.read(20000)
    except HTTPError as e:  # 401/403/500... : on garde quand meme les en-tetes
        status = e.code
        if e.headers:
            server = e.headers.get("Server", "") or ""
            realm = parse_realm(e.headers.get("WWW-Authenticate", ""))
        try:
            body = e.read(20000)
        except Exception:
            body = b""
    except (URLError, socket.timeout, ConnectionError, OSError):
        return None
    except Exception:
        return None
    title = parse_title(body)
    return {"status": status, "server": server.strip(), "realm": realm, "title": title}


def make_label(info):
    title = info.get("title") or ""
    if title:
        return title
    realm = info.get("realm") or ""
    if realm:
        return realm
    det = info.get("detected") or ""
    if det:
        return det.split(" (")[0]
    return "Serveur web"


def analyze_target(t, timeout):
    """t = {addr, port, proto, from_file}. Renvoie un enregistrement ou None."""
    ip = t["addr"]
    if t.get("port"):
        candidates = [(t.get("proto") or "http", t["port"])]
    else:
        candidates = [("http", None), ("https", None), ("http", 8080), ("https", 8443)]

    info = None
    used_proto, used_port = t.get("proto") or "http", t.get("port")
    for proto, port in candidates:
        r = http_probe(ip, port, proto, timeout)
        if r is not None:
            info = r
            used_proto, used_port = proto, port
            break
    if info is None:
        return None

    info["detected"] = detect_server(info["server"], info["realm"], info["title"])
    rec = {"addr": ip}
    # On preserve port/proto d'origine pour les entrees issues de l'app (evite
    # de creer un doublon a l'import) ; sinon on met ce qui a repondu.
    if t.get("from_file"):
        rec["port"] = t.get("port")
        rec["proto"] = t.get("proto") or "http"
    else:
        rec["port"] = used_port
        rec["proto"] = used_proto
    if info["server"]:
        rec["server"] = info["server"]
    if info["title"]:
        rec["title"] = info["title"]
    if info["detected"]:
        rec["detected"] = info["detected"]
    rec["label"] = make_label(info)
    return rec


# ============================================================================
#  Partie 2 — SNMP v2c minimal (pur Python) pour le port de switch
# ============================================================================

OID_Q_FDB = "1.3.6.1.2.1.17.7.1.2.2.1.2"    # dot1qTpFdbPort  (bridge VLAN)
OID_D_FDB = "1.3.6.1.2.1.17.4.3.1.2"        # dot1dTpFdbPort  (bridge simple)
OID_BASEPORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"  # dot1dBasePortIfIndex
OID_IFNAME = "1.3.6.1.2.1.31.1.1.1.1"       # ifName
OID_IFDESCR = "1.3.6.1.2.1.2.2.1.2"         # ifDescr
OID_ARP = "1.3.6.1.2.1.4.22.1.2"            # ipNetToMediaPhysAddress
OID_SYSNAME = "1.3.6.1.2.1.1.5"             # sysName
OID_IFADMIN = "1.3.6.1.2.1.2.2.1.7"         # ifAdminStatus (1=up/active, 2=down/desactive)
OID_IFOPER = "1.3.6.1.2.1.2.2.1.8"          # ifOperStatus  (1=up/lien present, 2=down)
OID_IFTYPE = "1.3.6.1.2.1.2.2.1.3"          # ifType        (6 = ethernet)


def _ber_len(n):
    if n < 0x80:
        return bytes([n])
    out = bytearray()
    while n > 0:
        out.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(out)]) + bytes(out)


def _tlv(tag, val):
    return bytes([tag]) + _ber_len(len(val)) + val


def _enc_int(n):
    if n == 0:
        body = b"\x00"
    else:
        length = (n.bit_length() + 8) // 8
        body = n.to_bytes(length, "big", signed=True)
        while len(body) > 1 and body[0] == 0x00 and not (body[1] & 0x80):
            body = body[1:]
        while len(body) > 1 and body[0] == 0xFF and (body[1] & 0x80):
            body = body[1:]
    return _tlv(0x02, body)


def _enc_oid(oid):
    parts = [int(x) for x in oid.split(".") if x != ""]
    body = bytearray([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        if p < 0x80:
            body.append(p)
        else:
            stack = [p & 0x7F]
            p >>= 7
            while p > 0:
                stack.append((p & 0x7F) | 0x80)
                p >>= 7
            body.extend(reversed(stack))
    return _tlv(0x06, bytes(body))


def _enc_octstr(s):
    if isinstance(s, str):
        s = s.encode()
    return _tlv(0x04, s)


def _enc_null():
    return b"\x05\x00"


def _build_getnext(community, oid, reqid, version=1):
    vb = _tlv(0x30, _enc_oid(oid) + _enc_null())
    vblist = _tlv(0x30, vb)
    pdu = _tlv(0xA1, _enc_int(reqid) + _enc_int(0) + _enc_int(0) + vblist)
    return _tlv(0x30, _enc_int(version) + _enc_octstr(community) + pdu)


def _read_len(d, i):
    b = d[i]
    i += 1
    if b < 0x80:
        return b, i
    n = b & 0x7F
    length = int.from_bytes(d[i:i + n], "big")
    return length, i + n


def _read_tlv(d, i):
    tag = d[i]
    i += 1
    length, i = _read_len(d, i)
    return tag, d[i:i + length], i + length


def _dec_oid(b):
    if not b:
        return ""
    parts = [b[0] // 40, b[0] % 40]
    n = 0
    for c in b[1:]:
        n = (n << 7) | (c & 0x7F)
        if not (c & 0x80):
            parts.append(n)
            n = 0
    return ".".join(str(x) for x in parts)


def _parse_response(data):
    """Renvoie la liste des varbinds [(oid_str, tag, value_bytes)]."""
    _, msg, _ = _read_tlv(data, 0)
    i = 0
    _, _ver, i = _read_tlv(msg, i)
    _, _comm, i = _read_tlv(msg, i)
    _ptag, pdu, i = _read_tlv(msg, i)
    j = 0
    _, _rid, j = _read_tlv(pdu, j)
    _, _est, j = _read_tlv(pdu, j)
    _, _eidx, j = _read_tlv(pdu, j)
    _, vbl, j = _read_tlv(pdu, j)
    binds = []
    k = 0
    while k < len(vbl):
        _, vb, k = _read_tlv(vbl, k)
        m = 0
        _, oidb, m = _read_tlv(vb, m)
        vtag, vval, m = _read_tlv(vb, m)
        binds.append((_dec_oid(oidb), vtag, vval))
    return binds


def _snmp_getnext(sock, target, community, oid, version=1, retries=2):
    reqid = random.randint(1, 0x7FFFFFFF)
    pkt = _build_getnext(community, oid, reqid, version)
    for _ in range(retries + 1):
        try:
            sock.sendto(pkt, target)
            data, _ = sock.recvfrom(65535)
            binds = _parse_response(data)
            return binds[0] if binds else None
        except socket.timeout:
            continue
        except Exception:
            return None
    return None


def snmp_walk(sock, target, community, base, version=1, limit=60000, retries=2):
    res = []
    cur = base
    while True:
        r = _snmp_getnext(sock, target, community, cur, version, retries=retries)
        if r is None:
            break
        oid, tag, val = r
        if tag in (0x80, 0x81, 0x82):  # noSuchObject / noSuchInstance / endOfMibView
            break
        if not (oid == base or oid.startswith(base + ".")):
            break
        res.append((oid, tag, val))
        cur = oid
        if len(res) >= limit:
            break
    return res


# ---- Construction des tables a partir des walks -----------------------------

def _fdb_map(walkres, base, qbridge):
    d = {}
    blen = len(base)
    for oid, tag, val in walkres:
        suffix = oid[blen + 1:]
        nums = [int(x) for x in suffix.split(".") if x != ""]
        if len(nums) < (7 if qbridge else 6):
            continue
        macnums = nums[-6:]
        port = int.from_bytes(val, "big") if val else 0
        if port == 0:
            continue
        mac = "".join("%02x" % (n & 0xFF) for n in macnums)
        d.setdefault(mac, port)
    return d


def _baseport_ifindex_map(walkres, base):
    d = {}
    blen = len(base)
    for oid, tag, val in walkres:
        try:
            key = int(oid[blen + 1:].split(".")[0])
        except Exception:
            continue
        d[key] = int.from_bytes(val, "big") if val else key
    return d


def _ifname_map(walkres, base):
    d = {}
    blen = len(base)
    for oid, tag, val in walkres:
        try:
            key = int(oid[blen + 1:].split(".")[0])
        except Exception:
            continue
        name = val.decode("utf-8", "replace").replace("\x00", "").strip()
        if name:
            d[key] = name
    return d


def _switch_arp_map(walkres, base):
    d = {}
    blen = len(base)
    for oid, tag, val in walkres:
        nums = [int(x) for x in oid[blen + 1:].split(".") if x != ""]
        if len(nums) < 5 or len(val) != 6:
            continue
        ip = ".".join(str(x) for x in nums[-4:])
        mac = "".join("%02x" % b for b in val)
        if mac != "000000000000":
            d[ip] = mac
    return d


# ============================================================================
#  Partie 3 — Table ARP locale (IP <-> MAC)
# ============================================================================

MAC_RE = re.compile(r"([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})")
IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")


def mac_canon(token):
    hexs = re.findall(r"[0-9a-fA-F]{2}", token)
    if len(hexs) != 6:
        return None
    return "".join(h.lower() for h in hexs)


def prime_arp(ips, timeout=0.4):
    """Provoque une resolution ARP en tentant une connexion TCP breve."""
    def _touch(ip):
        for p in (80, 443):
            try:
                s = socket.create_connection((ip, p), timeout)
                s.close()
                return
            except Exception:
                pass
    with ThreadPoolExecutor(max_workers=40) as ex:
        list(ex.map(_touch, ips))


def local_arp():
    table = {}
    if os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp") as f:
                next(f, None)
                for line in f:
                    cols = line.split()
                    if len(cols) >= 4:
                        cm = mac_canon(cols[3])
                        if cm and cm != "000000000000":
                            table[cols[0]] = cm
        except Exception:
            pass
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                             timeout=12).stdout
        for line in out.splitlines():
            ipm = IP_RE.search(line)
            macm = MAC_RE.search(line)
            if ipm and macm:
                cm = mac_canon(macm.group(1))
                if cm and cm != "000000000000":
                    table.setdefault(ipm.group(1), cm)
    except Exception:
        pass
    return table


def resolve_switchport(devmac, q_fdb, d_fdb, bp2if, if2name, switch_ip):
    port = q_fdb.get(devmac) or d_fdb.get(devmac)
    if not port:
        return None
    ifidx = bp2if.get(port, port)
    name = if2name.get(ifidx) or ("port %d" % port)
    return "%s \u00b7 %s" % (switch_ip, name)


# ============================================================================
#  Partie 4 — Entrees / sorties, orchestration
# ============================================================================

def load_targets(args):
    targets = []
    seen = set()

    def add(addr, port=None, proto=None, from_file=False):
        addr = str(addr).strip()
        if not addr:
            return
        key = "%s|%s" % (addr, port or "")
        if key in seen:
            return
        seen.add(key)
        targets.append({"addr": addr, "port": port, "proto": proto, "from_file": from_file})

    if args.infile:
        with open(args.infile, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise SystemExit("Le fichier --in doit contenir une liste JSON.")
        for x in data:
            if isinstance(x, dict) and x.get("addr"):
                add(x["addr"], x.get("port"), x.get("proto"), from_file=True)

    for r in (args.ranges or []):
        for ip in expand_range(r):
            add(ip, args.port, args.proto, from_file=False)

    for ip in (args.ips or []):
        add(ip, args.port, args.proto, from_file=False)

    return targets


def expand_range(s):
    s = s.strip()
    # CIDR
    if "/" in s:
        net = ipaddress.ip_network(s, strict=False)
        hosts = list(net.hosts())
        return [str(h) for h in hosts] if hosts else [str(net.network_address)]
    # a.b.c.d-e.f.g.h
    m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+\.\d+\.\d+\.\d+)$", s)
    if m:
        a = int(ipaddress.ip_address(m.group(1)))
        b = int(ipaddress.ip_address(m.group(2)))
        if b < a:
            a, b = b, a
        return [str(ipaddress.ip_address(i)) for i in range(a, b + 1)]
    # a.b.c.d-e (dernier octet)
    m = re.match(r"^(\d+\.\d+\.\d+)\.(\d+)\s*-\s*(\d+)$", s)
    if m:
        pre, lo, hi = m.group(1), int(m.group(2)), int(m.group(3))
        if hi < lo:
            lo, hi = hi, lo
        return ["%s.%d" % (pre, k) for k in range(lo, hi + 1)]
    return [s]


def read_switch(ip, community, version, timeout):
    """Lit un switch en SNMP. Renvoie un dict, ou None si ce n'est pas un bridge."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    target = (ip, 161)
    try:
        q = _fdb_map(snmp_walk(sock, target, community, OID_Q_FDB, version), OID_Q_FDB, True)
        d = _fdb_map(snmp_walk(sock, target, community, OID_D_FDB, version), OID_D_FDB, False)
        if not (q or d):
            return None
        bp = _baseport_ifindex_map(snmp_walk(sock, target, community, OID_BASEPORT_IFINDEX, version), OID_BASEPORT_IFINDEX)
        nm = _ifname_map(snmp_walk(sock, target, community, OID_IFNAME, version), OID_IFNAME)
        if not nm:
            nm = _ifname_map(snmp_walk(sock, target, community, OID_IFDESCR, version), OID_IFDESCR)
        sarp = _switch_arp_map(snmp_walk(sock, target, community, OID_ARP, version), OID_ARP)
        name = None
        vb = snmp_walk(sock, target, community, OID_SYSNAME, version, limit=1)
        if vb:
            try:
                name = vb[0][2].decode("utf-8", "replace").strip() or None
            except Exception:
                name = None
    finally:
        sock.close()

    fdb = dict(d)
    fdb.update(q)                    # q-bridge prioritaire sur d-bridge
    portcount = {}
    for p in fdb.values():
        portcount[p] = portcount.get(p, 0) + 1
    return {"ip": ip, "fdb": fdb, "bp": bp, "nm": nm, "arp": sarp,
            "name": name, "portcount": portcount}


def port_state(admin, oper):
    """Interprete admin/oper -> etat lisible du port."""
    if admin == 2:
        return "Desactive (ferme)"
    if admin == 1 and oper == 1:
        return "Actif (lien up)"
    if admin == 1:
        return "Libre (active mais rien branche / lien down)"
    return "Inconnu"


def ports_for_switch(ip, community, version, timeout, data):
    """Liste l'etat de chaque port ethernet d'un switch (ferme / libre / actif)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    target = (ip, 161)
    try:
        admin = _baseport_ifindex_map(snmp_walk(sock, target, community, OID_IFADMIN, version), OID_IFADMIN)
        oper = _baseport_ifindex_map(snmp_walk(sock, target, community, OID_IFOPER, version), OID_IFOPER)
        iftype = _baseport_ifindex_map(snmp_walk(sock, target, community, OID_IFTYPE, version), OID_IFTYPE)
    finally:
        sock.close()

    nm, fdb, bp = data["nm"], data["fdb"], data["bp"]
    maccount = {}
    for mac, port in fdb.items():
        ii = bp.get(port, port)
        maccount[ii] = maccount.get(ii, 0) + 1

    rows = []
    for ii in sorted(set(list(admin) + list(oper) + list(nm))):
        t = iftype.get(ii)
        if t is not None and t != 6:      # garde uniquement les ports ethernet
            continue
        rows.append({
            "switch": ip,
            "switch_nom": data.get("name") or "",
            "port": nm.get(ii, "ifIndex %d" % ii),
            "etat": port_state(admin.get(ii), oper.get(ii)),
            "appareils_appris": maccount.get(ii, 0),
        })
    return rows


def discover_switches(candidates, community, version, timeout, workers=40):
    """Trouve les IP qui repondent en SNMP ET exposent une bridge-MIB (= switches)."""
    def probe(ip):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            if snmp_walk(sock, (ip, 161), community, OID_BASEPORT_IFINDEX, version, limit=1, retries=0):
                return ip
            if snmp_walk(sock, (ip, 161), community, OID_Q_FDB, version, limit=1, retries=0):
                return ip
        except Exception:
            return None
        finally:
            sock.close()
        return None

    found = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for res in ex.map(probe, candidates):
            if res:
                found.append(res)
    return found


def do_snmp(switch_ips, discover_ranges, community, version, timeout, records, ports_out=None):
    prime_arp([r["addr"] for r in records])
    arp = local_arp()

    switches = list(dict.fromkeys(switch_ips or []))
    if discover_ranges:
        cand = []
        for r in discover_ranges:
            cand += expand_range(r)
        cand = list(dict.fromkeys(cand))
        print("[SNMP] Decouverte de switches sur %d adresse(s)..." % len(cand), file=sys.stderr)
        disc = discover_switches(cand, community, version, min(timeout, 1.0))
        print("[SNMP] Switch(es) SNMP trouve(s): %s"
              % (", ".join(disc) if disc else "aucun"), file=sys.stderr)
        for ip in disc:
            if ip not in switches:
                switches.append(ip)

    if not switches:
        print("[SNMP] Aucun switch a interroger (ni --switch ni --discover concluant).", file=sys.stderr)
        return

    swdata = []
    for ip in switches:
        print("[SNMP] Lecture du switch %s ..." % ip, file=sys.stderr)
        try:
            data = read_switch(ip, community, version, timeout)
        except Exception as e:
            print("[SNMP]   erreur sur %s: %s" % (ip, e), file=sys.stderr)
            data = None
        if data:
            swdata.append(data)
            for k, v in data["arp"].items():
                arp.setdefault(k, v)
        else:
            print("[SNMP]   %s ne fournit pas de table de commutation (ignore)." % ip, file=sys.stderr)

    if not swdata:
        print("[SNMP] Aucune table de commutation exploitable. Port de switch ignore.", file=sys.stderr)
        return

    found = 0
    for r in records:
        mac = arp.get(r["addr"])
        if not mac:
            continue
        # Cherche la MAC sur tous les switches ; retient le port "d'acces" =
        # celui qui porte le MOINS de MAC (les liaisons/uplinks en agregent beaucoup).
        best = None  # (portcount, data, port)
        for data in swdata:
            port = data["fdb"].get(mac)
            if not port:
                continue
            cnt = data["portcount"].get(port, 1)
            if best is None or cnt < best[0]:
                best = (cnt, data, port)
        if best:
            _, data, port = best
            ifidx = data["bp"].get(port, port)
            name = data["nm"].get(ifidx) or ("port %d" % port)
            label = ("%s (%s)" % (data["name"], data["ip"])) if data["name"] else data["ip"]
            r["switchport"] = "%s · %s" % (label, name)
            found += 1
    print("[SNMP] Port de switch trouve pour %d/%d appareil(s)." % (found, len(records)), file=sys.stderr)

    # ---- Diagnostic : explique ce qui manque -------------------------------
    no_mac = [r["addr"] for r in records if not arp.get(r["addr"])]
    no_port = [r["addr"] for r in records if arp.get(r["addr"]) and "switchport" not in r]
    if no_mac:
        print("[SNMP] MAC introuvable (table ARP) pour %d adresse(s) : %s"
              % (len(no_mac), ", ".join(no_mac[:8]) + (" ..." if len(no_mac) > 8 else "")),
              file=sys.stderr)
        print("[SNMP]   -> Lance le script depuis une machine du MEME sous-reseau que ces "
              "modules, OU assure-toi qu'un switch L3 (routeur) est interroge/decouvert "
              "(il fournit la table ARP).", file=sys.stderr)
    if no_port:
        print("[SNMP] MAC connue mais absente des tables de commutation pour %d adresse(s) : %s"
              % (len(no_port), ", ".join(no_port[:8]) + (" ..." if len(no_port) > 8 else "")),
              file=sys.stderr)
        print("[SNMP]   -> Le switch d'acces de ces modules n'a pas ete interroge. Ajoute-le "
              "avec --switch, ou elargis --discover a leur sous-reseau (ex: --discover "
              "10.122.103.0/24).", file=sys.stderr)

    # ---- Rapport d'etat des ports du/des switch(es) ------------------------
    if ports_out:
        allrows = []
        for data in swdata:
            try:
                allrows += ports_for_switch(data["ip"], community, version, timeout, data)
            except Exception as e:
                print("[SNMP]   rapport ports impossible sur %s: %s" % (data["ip"], e), file=sys.stderr)
        if allrows:
            with open(ports_out, "w", encoding="utf-8") as f:
                json.dump(allrows, f, ensure_ascii=False, indent=2)
            print("\n=== Etat des ports de switch (%d port(s)) ===" % len(allrows))
            print("  %-22s %-14s %-38s %s" % ("SWITCH", "PORT", "ETAT", "APPAREILS"))
            for row in allrows:
                sw = row["switch_nom"] and ("%s (%s)" % (row["switch_nom"], row["switch"])) or row["switch"]
                print("  %-22s %-14s %-38s %s" % (sw[:22], str(row["port"])[:14], row["etat"], row["appareils_appris"]))
            print("Rapport ecrit : %s" % ports_out)


def parse_args():
    p = argparse.ArgumentParser(
        description="Analyse locale des serveurs web + port de switch (SNMP). "
                    "Produit un JSON a importer dans l'application Surveillance IP.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exemple: python analyseur.py --in surveillance-ip.json "
               "--out analyse.json --switch 192.168.1.2 --community public")
    p.add_argument("--in", dest="infile", help="Fichier JSON exporte par l'application.")
    p.add_argument("--range", dest="ranges", action="append",
                   help="Plage a analyser (192.168.1.0/24, 192.168.1.1-254...). Repetable.")
    p.add_argument("--ips", nargs="+", help="Adresses IP a analyser (separees par des espaces).")
    p.add_argument("--out", default="analyse.json", help="Fichier JSON de sortie (defaut: analyse.json).")
    p.add_argument("--port", type=int, default=None, help="Port force pour --range/--ips.")
    p.add_argument("--proto", choices=["http", "https"], default="http",
                   help="Protocole pour --range/--ips (defaut: http).")
    p.add_argument("--timeout", type=float, default=4.0, help="Delai HTTP en secondes (defaut: 4).")
    p.add_argument("--workers", type=int, default=20, help="Analyses HTTP en parallele (defaut: 20).")
    # SNMP
    p.add_argument("--switch", action="append",
                   help="IP d'un switch a interroger en SNMP (repetable pour plusieurs switches).")
    p.add_argument("--discover", action="append",
                   help="Plage a scanner pour trouver AUTOMATIQUEMENT les switches SNMP "
                        "(192.168.1.0/24...). Repetable. Evite d'avoir a connaitre l'IP du switch.")
    p.add_argument("--community", default="public", help="Communaute SNMP en lecture (defaut: public).")
    p.add_argument("--snmp-version", choices=["1", "2c"], default="2c", help="Version SNMP (defaut: 2c).")
    p.add_argument("--snmp-timeout", type=float, default=2.0, help="Delai SNMP en secondes (defaut: 2).")
    p.add_argument("--ports", nargs="?", const="ports.json", default=None,
                   help="Produit aussi l'ETAT DE CHAQUE PORT du/des switch(es) : ferme (desactive), "
                        "libre (rien branche) ou actif. Ecrit dans le fichier indique (defaut: ports.json).")
    return p.parse_args()


def main():
    args = parse_args()
    if not (args.infile or args.ranges or args.ips):
        raise SystemExit("Rien a analyser. Utilise --in, --range ou --ips. "
                         "(python analyseur.py -h pour l'aide)")

    targets = load_targets(args)
    print("[HTTP] Analyse de %d adresse(s)..." % len(targets), file=sys.stderr)

    records = []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(analyze_target, t, args.timeout): t for t in targets}
        for f in as_completed(futs):
            try:
                rec = f.result()
            except Exception:
                rec = None
            if rec:
                records.append(rec)

    records.sort(key=lambda r: tuple(int(x) for x in r["addr"].split(".")) if
                 re.match(r"^\d+\.\d+\.\d+\.\d+$", r["addr"]) else (r["addr"],))
    print("[HTTP] %d serveur(s) web ont repondu." % len(records), file=sys.stderr)

    if args.switch or args.discover:
        version = 1 if args.snmp_version == "2c" else 0
        try:
            do_snmp(args.switch, args.discover, args.community, version, args.snmp_timeout,
                    records, ports_out=args.ports)
        except Exception as e:
            print("[SNMP] Erreur: %s (port de switch ignore)." % e, file=sys.stderr)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)

    # Recapitulatif lisible
    print("\n=== Resultat (%d appareil(s)) ===" % len(records))
    for r in records:
        line = "  %-16s %s" % (r["addr"], r.get("label", ""))
        extra = []
        if r.get("detected"):
            extra.append(r["detected"])
        if r.get("server"):
            extra.append("Server: " + r["server"])
        if r.get("switchport"):
            extra.append("Switch: " + r["switchport"])
        if extra:
            line += "  [" + " | ".join(extra) + "]"
        print(line)
    print("\nFichier ecrit : %s" % args.out)
    print("-> Dans l'application : bouton \"Importer\" puis choisis ce fichier.")


if __name__ == "__main__":
    main()
