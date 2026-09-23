#!/usr/bin/env python3
"""
Whitelist Filter for Russia — VLESS + Hysteria2
Создаёт два файла:
  - working_strict.txt   (IP + SNI)
  - working_relaxed.txt  (только SNI + формат)
"""

from __future__ import annotations
import re
import sys
import json
import time
import base64
import hashlib
import logging
import ipaddress
import urllib.parse
import socket
from pathlib import Path
from typing import Optional, Dict, List, Set, Tuple
from collections import Counter
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor

import requests
import maxminddb

# ──────────────────────────────────────────────
CACHE_DIR = Path("cache")
RESULTS_DIR = Path("results")
CACHE_DIR.mkdir(exist_ok=True)
RESULTS_DIR.mkdir(exist_ok=True)

WHITE_SNI_URL  = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/whitelist.txt"
WHITE_CIDR_URL = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/cidrwhitelist.txt"
WHITE_IP_URL   = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/ipwhitelist.txt"
RKN_MMDB_URL   = "https://cdn.jsdelivr.net/gh/runetfreedom/russia-blocked-geoip@release/Country-ru-only.mmdb"

EMPIRIC_GOOD_SNI = {
    "vk.com", "ok.ru", "mail.ru", "yandex.ru", "ya.ru", "dzen.ru",
    "ozon.ru", "wildberries.ru", "avito.ru", "rutube.ru", "mts.ru",
    "userapi.com", "yastatic.net", "vk.ru", "max.ru", "tbank.ru",
    "sberbank.ru", "alfabank.ru", "2gis.ru", "2gis.com", "rzd.ru",
}

BAD_SNI_HINTS = (
    "gosuslugi", "gov.ru", "kremlin", "wikipedia", "github",
    "stackoverflow", "twitter", "facebook", "instagram",
    "youtube", "googlevideo", "cloudflare", "cf-", "fastly",
)

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
PBK_RE  = re.compile(r"^[A-Za-z0-9_\-]{42,44}={0,2}$")
SID_RE  = re.compile(r"^([0-9a-fA-F]{2}){0,8}$")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("filter")

# ──────────────────────────────────────────────
@dataclass
class Config:
    type: str
    id: str
    hostname: str
    port: int
    security: str = "none"
    sni: str = ""
    flow: str = ""
    net: str = "tcp"
    path: str = ""
    host_header: str = ""
    service_name: str = ""
    pbk: str = ""
    sid: str = ""
    fp: str = ""
    alpn: str = ""
    hop: str = ""
    insecure: bool = False
    pin_sha256: str = ""
    obfs: str = ""
    obfs_password: str = ""
    source: str = ""
    original: str = ""
    resolved_ip: str = ""
    score: int = 0
    ip_white: bool = False

    def dedup_key(self) -> str:
        return f"{self.type}:{self.id}@{self.hostname}:{self.port}"

# ──────────────────────────────────────────────
_dns_cache: Dict[str, Optional[str]] = {}
_session = requests.Session()
_session.headers["User-Agent"] = "WhitelistFilter/2.2"

def resolve(host: str) -> Optional[str]:
    if host in _dns_cache:
        return _dns_cache[host]
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        if infos:
            ip = infos[0][4][0]
            _dns_cache[host] = ip
            return ip
    except Exception:
        pass
    _dns_cache[host] = None
    return None

def fetch(url: str, max_age_h: float = 3) -> str:
    key = hashlib.sha256(url.encode()).hexdigest()
    path = CACHE_DIR / key
    if path.exists() and (time.time() - path.stat().st_mtime) < max_age_h * 3600:
        return path.read_text(encoding="utf-8", errors="ignore")
    try:
        r = _session.get(url, timeout=20)
        r.raise_for_status()
        text = r.text
        path.write_text(text, encoding="utf-8")
        return text
    except Exception as e:
        if path.exists():
            log.warning(f"fetch fail {url[:60]}... → cache")
            return path.read_text(encoding="utf-8", errors="ignore")
        log.warning(f"fetch fail {url[:60]}... → empty")
        return ""

def fetch_mmdb(url: str) -> Optional[maxminddb.Reader]:
    path = CACHE_DIR / "rkn.mmdb"
    try:
        if not path.exists() or (time.time() - path.stat().st_mtime) > 6 * 3600:
            r = _session.get(url, timeout=40)
            r.raise_for_status()
            path.write_bytes(r.content)
        return maxminddb.open_database(str(path))
    except Exception as e:
        log.warning(f"RKN MMDB error: {e}")
        return None

# ──────────────────────────────────────────────
def parse_vless(link: str, source: str) -> Optional[Config]:
    try:
        if not link.startswith("vless://"):
            return None
        body = link[8:].split("#")[0]
        userinfo, _, rest = body.rpartition("@")
        hostport, _, query = rest.partition("?")
        host, _, port_s = hostport.partition(":")
        port = int(port_s) if port_s.isdigit() else 443
        q = urllib.parse.parse_qs(query, keep_blank_values=True)
        g = lambda k, d="": urllib.parse.unquote(q.get(k, [d])[0])

        return Config(
            type="vless",
            id=userinfo,
            hostname=host.strip(),
            port=port,
            security=g("security", "none"),
            sni=g("sni", host),
            flow=g("flow"),
            net=g("type", "tcp"),
            path=g("path"),
            host_header=g("host"),
            service_name=g("serviceName"),
            pbk=g("pbk"),
            sid=g("sid"),
            fp=g("fp"),
            alpn=g("alpn"),
            source=source,
            original=link,
        )
    except Exception:
        return None

def parse_hy2(link: str, source: str) -> Optional[Config]:
    try:
        for pfx in ("hysteria2://", "hy2://"):
            if link.startswith(pfx):
                link = link[len(pfx):]
                break
        else:
            return None

        body = link.split("#")[0]
        main, _, qs = body.partition("?")
        auth, _, hostport = main.rpartition("@")
        host, _, port_raw = hostport.partition(":")
        if not host:
            return None

        port = 443
        hop = ""
        if port_raw:
            first = port_raw.split(",")[0]
            if first.isdigit():
                port = int(first)
            hop = port_raw

        q = urllib.parse.parse_qs(qs, keep_blank_values=True)
        g = lambda k, d="": urllib.parse.unquote(q.get(k, [d])[0])

        auth = urllib.parse.unquote(auth) or g("auth")
        return Config(
            type="hy2",
            id=auth,
            hostname=host.strip(),
            port=port,
            security="tls",
            sni=g("sni", host),
            hop=hop,
            insecure=g("insecure").lower() in ("1", "true", "yes"),
            pin_sha256=g("pinSHA256"),
            obfs=g("obfs"),
            obfs_password=g("obfs-password"),
            source=source,
            original=link,
        )
    except Exception:
        return None

def parse_line(line: str, source: str) -> Optional[Config]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith("vless://"):
        return parse_vless(line, source)
    if line.startswith(("hysteria2://", "hy2://")):
        return parse_hy2(line, source)
    try:
        dec = base64.urlsafe_b64decode(line + "==").decode(errors="ignore")
        if dec.startswith("vless://"):
            return parse_vless(dec, source)
        if dec.startswith(("hysteria2://", "hy2://")):
            return parse_hy2(dec, source)
    except Exception:
        pass
    return None

# ──────────────────────────────────────────────
def vless_ok(c: Config, white_sni: Set[str]) -> Tuple[bool, str]:
    if not UUID_RE.match(c.id or ""):
        return False, "bad_uuid"
    if c.security == "reality":
        if not PBK_RE.match(c.pbk or ""):
            return False, "bad_pbk"
        if c.sid and not SID_RE.match(c.sid):
            return False, "bad_sid"
        if not c.sni:
            return False, "no_sni"
        if c.flow and c.net not in ("tcp", "raw"):
            return False, "flow_net_mismatch"
        if not c.flow and c.net in ("tcp", "raw"):
            return False, "no_vision"
    if c.security == "tls" and not c.sni:
        return False, "tls_no_sni"
    if c.net == "ws" and not (c.path or c.host_header):
        return False, "ws_no_path"
    if c.net == "grpc" and not c.service_name:
        return False, "grpc_no_svc"
    if c.net == "xhttp" and not c.path:
        return False, "xhttp_no_path"

    sni = (c.sni or "").lower().strip()
    if not sni:
        return False, "empty_sni"
    if any(b in sni for b in BAD_SNI_HINTS):
        return False, "bad_sni"
    if sni not in white_sni and not any(sni.endswith("." + d) for d in white_sni):
        return False, "sni_not_white"
    return True, ""

def hy2_ok(c: Config) -> Tuple[bool, str]:
    if not c.id:
        return False, "no_auth"
    if not (c.insecure or c.pin_sha256):
        return False, "no_insecure_pin"
    if c.obfs and c.obfs not in ("salamander", "gecko"):
        return False, "bad_obfs"
    if c.obfs and not c.obfs_password:
        return False, "obfs_no_pass"
    if not c.sni:
        return False, "no_sni"
    return True, ""

def score(c: Config) -> int:
    s = 0
    sni = (c.sni or "").lower()
    if any(sni == d or sni.endswith("." + d) for d in EMPIRIC_GOOD_SNI):
        s += 400
    if c.ip_white:
        s += 300
    if c.port == 443:
        s += 100
    if c.type == "hy2":
        if c.hop: s += 50
        if c.obfs: s += 50
    else:
        if c.flow: s += 50
        if c.security == "reality": s += 30
    return s

def make_link(c: Config) -> str:
    if c.type == "vless":
        params = []
        if c.security: params.append(f"security={c.security}")
        if c.sni: params.append(f"sni={urllib.parse.quote(c.sni)}")
        if c.flow: params.append(f"flow={c.flow}")
        if c.net != "tcp": params.append(f"type={c.net}")
        if c.path: params.append(f"path={urllib.parse.quote(c.path)}")
        if c.host_header: params.append(f"host={urllib.parse.quote(c.host_header)}")
        if c.service_name: params.append(f"serviceName={urllib.parse.quote(c.service_name)}")
        if c.pbk: params.append(f"pbk={c.pbk}")
        if c.sid: params.append(f"sid={c.sid}")
        if c.fp: params.append(f"fp={c.fp}")
        if c.alpn: params.append(f"alpn={urllib.parse.quote(c.alpn)}")
        q = "?" + "&".join(params) if params else ""
        return f"vless://{c.id}@{c.hostname}:{c.port}{q}#[VLESS] {c.sni} {c.resolved_ip}"
    else:
        params = []
        if c.obfs: params.append(f"obfs={c.obfs}")
        if c.obfs_password: params.append(f"obfs-password={urllib.parse.quote(c.obfs_password)}")
        if c.sni: params.append(f"sni={urllib.parse.quote(c.sni)}")
        if c.insecure: params.append("insecure=1")
        if c.pin_sha256: params.append(f"pinSHA256={c.pin_sha256}")
        q = "?" + "&".join(params) if params else ""
        hop = f",{c.hop}" if c.hop else ""
        return f"hysteria2://{c.id}@{c.hostname}:{c.port}{hop}{q}#[HY2] {c.sni} {c.resolved_ip}"

# ──────────────────────────────────────────────
def main():
    log.info("=== Loading allowlists ===")
    white_sni = {
        l.strip().lower()
        for l in fetch(WHITE_SNI_URL).splitlines()
        if l.strip() and not l.startswith("#")
    }
    networks: List[ipaddress.IPv4Network] = []
    for line in fetch(WHITE_CIDR_URL).splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            try:
                networks.append(ipaddress.IPv4Network(line, strict=False))
            except Exception:
                pass
    white_ips = {
        l.strip()
        for l in fetch(WHITE_IP_URL).splitlines()
        if l.strip() and not l.startswith("#")
    }
    log.info(f"White SNI: {len(white_sni)}, CIDR: {len(networks)}, IPs: {len(white_ips)}")

    rkn = fetch_mmdb(RKN_MMDB_URL)
    if rkn:
        log.info("RKN MMDB loaded")
    else:
        log.warning("RKN MMDB not available — skipping RKN gate")

    sources_file = Path("sources.txt")
    if not sources_file.exists():
        log.error("sources.txt not found")
        sys.exit(1)

    urls = [
        line.strip()
        for line in sources_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]

    all_cfgs: List[Config] = []
    for url in urls:
        name = url.rstrip("/").split("/")[-1][:50]
        text = fetch(url, max_age_h=2)
        if not text:
            log.warning(f"{name}: empty")
            continue
        cnt = 0
        for line in text.splitlines():
            c = parse_line(line, name)
            if c:
                all_cfgs.append(c)
                cnt += 1
        log.info(f"{name}: {cnt} parsed")

    log.info(f"Total parsed: {len(all_cfgs)}")

    seen = set()
    unique: List[Config] = []
    for c in all_cfgs:
        k = c.dedup_key()
        if k not in seen:
            seen.add(k)
            unique.append(c)
    log.info(f"After dedup: {len(unique)}")

    log.info("Resolving DNS (parallel)...")
    hosts = list({c.hostname for c in unique})
    with ThreadPoolExecutor(max_workers=40) as ex:
        list(ex.map(resolve, hosts))
    log.info(f"DNS done, cache size: {len(_dns_cache)}")

    strict_list: List[Config] = []
    relaxed_list: List[Config] = []
    reasons = Counter()
    total = len(unique)

    for i, c in enumerate(unique, 1):
        if i % 1000 == 0 or i == total:
            log.info(f"Filtering {i}/{total}...")

        ip = resolve(c.hostname)
        if not ip:
            reasons["no_dns"] += 1
            continue
        c.resolved_ip = ip

        # RKN
        if rkn is not None:
            try:
                if rkn.get(ip) is not None:
                    reasons["rkn_blocked"] += 1
                    continue
            except Exception:
                pass

        # IP white?
        c.ip_white = ip in white_ips or any(ipaddress.IPv4Address(ip) in n for n in networks)

        # Protocol + SNI gates
        if c.type == "vless":
            ok, reason = vless_ok(c, white_sni)
        else:
            ok, reason = hy2_ok(c)

        if not ok:
            reasons[reason] += 1
            continue

        c.score = score(c)

        # Relaxed — всё, что прошло SNI + формат
        relaxed_list.append(c)

        # Strict — только с белым IP
        if c.ip_white:
            strict_list.append(c)
        else:
            reasons["ip_not_white"] += 1

    strict_list.sort(key=lambda x: x.score, reverse=True)
    relaxed_list.sort(key=lambda x: x.score, reverse=True)

    log.info(f"Strict (IP+SNI): {len(strict_list)}")
    log.info(f"Relaxed (SNI only): {len(relaxed_list)}")
    log.info(f"Reject reasons: {dict(reasons)}")

    # Пишем оба файла
    with (RESULTS_DIR / "working_strict.txt").open("w", encoding="utf-8") as f:
        for c in strict_list:
            f.write(make_link(c) + "\n")

    with (RESULTS_DIR / "working_relaxed.txt").open("w", encoding="utf-8") as f:
        for c in relaxed_list:
            f.write(make_link(c) + "\n")

    # Старый файл для совместимости = relaxed
    with (RESULTS_DIR / "working_vless_hy2.txt").open("w", encoding="utf-8") as f:
        for c in relaxed_list:
            f.write(make_link(c) + "\n")

    stats = {
        "strict_count": len(strict_list),
        "relaxed_count": len(relaxed_list),
        "by_type_strict": dict(Counter(c.type for c in strict_list)),
        "by_type_relaxed": dict(Counter(c.type for c in relaxed_list)),
        "reject_reasons": dict(reasons),
        "top10_relaxed": [(c.score, c.type, c.sni, c.resolved_ip, c.ip_white) for c in relaxed_list[:10]],
    }
    (RESULTS_DIR / "stats.json").write_text(
        json.dumps(stats, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    log.info("Done.")

if __name__ == "__main__":
    main()
