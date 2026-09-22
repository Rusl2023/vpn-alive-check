#!/usr/bin/env python3
"""
Whitelist Filter for Russia — VLESS + Hysteria2
Только статическая фильтрация (DNS + CIDR + SNI + RKN + формат).
Без TCP/TLS-проб.
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

import requests
import maxminddb

# ──────────────────────────────────────────────
# КОНФИГ
# ──────────────────────────────────────────────
CACHE_DIR = Path("cache")
RESULTS_DIR = Path("results")
CACHE_DIR.mkdir(exist_ok=True)
RESULTS_DIR.mkdir(exist_ok=True)

# Базы белых списков (hxehex — лучший на 2026)
WHITE_SNI_URL   = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/whitelist.txt"
WHITE_CIDR_URL  = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/cidrwhitelist.txt"
WHITE_IP_URL    = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/ipwhitelist.txt"

# RKN blocklist (обновляется каждые 6 часов)
RKN_MMDB_URL = "https://cdn.jsdelivr.net/gh/runetfreedom/russia-blocked-geoip@release/Country-ru-only.mmdb"

# Эмпирически рабочие SNI (из замеров на мобильном интернете РФ)
EMPIRIC_GOOD_SNI = {
    "vk.com", "ok.ru", "mail.ru", "yandex.ru", "ya.ru", "dzen.ru",
    "ozon.ru", "wildberries.ru", "avito.ru", "rutube.ru", "mts.ru",
    "userapi.com", "yastatic.net", "vk.ru", "max.ru", "tbank.ru",
    "sberbank.ru", "alfabank.ru", "2gis.ru", "2gis.com", "rzd.ru",
}

# Ловушки и замедляемые
BAD_SNI_HINTS = (
    "gosuslugi", "gov.ru", "kremlin", "wikipedia", "github",
    "stackoverflow", "twitter", "facebook", "instagram",
    "youtube", "googlevideo", "cloudflare", "cf-", "fastly",
)

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
PBK_RE  = re.compile(r"^[A-Za-z0-9_\-]{42,44}={0,2}$")
SID_RE  = re.compile(r"^([0-9a-fA-F]{2}){0,8}$")

CDN_ASNS = {13335, 16509, 209242, 396982, 60068, 15169}  # CF, AWS, CloudFront, Fastly, Google

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("filter")

# ──────────────────────────────────────────────
# DATA
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
    # hy2
    hop: str = ""
    insecure: bool = False
    pin_sha256: str = ""
    obfs: str = ""
    obfs_password: str = ""
    # meta
    source: str = ""
    original: str = ""
    resolved_ip: str = ""
    score: int = 0

    def dedup_key(self) -> str:
        return f"{self.type}:{self.id}@{self.hostname}:{self.port}"

# ──────────────────────────────────────────────
# УТИЛИТЫ
# ──────────────────────────────────────────────
_dns_cache: Dict[str, str] = {}
_session = requests.Session()
_session.headers["User-Agent"] = "WhitelistFilter/2.0"

def resolve(host: str) -> Optional[str]:
    if host in _dns_cache:
        return _dns_cache[host]
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
        if infos:
            ip = infos[0][4][0]
            _dns_cache[host] = ip
            return ip
    except Exception:
        pass
    return None

def fetch(url: str, max_age_h: int = 6) -> str:
    key = hashlib.sha256(url.encode()).hexdigest()
    path = CACHE_DIR / key
    if path.exists() and (time.time() - path.stat().st_mtime) < max_age_h * 3600:
        return path.read_text(encoding="utf-8", errors="ignore")
    try:
        r = _session.get(url, timeout=25)
        r.raise_for_status()
        text = r.text
        path.write_text(text, encoding="utf-8")
        return text
    except Exception as e:
        if path.exists():
            log.warning(f"fetch fail {url}: {e} → cache")
            return path.read_text(encoding="utf-8", errors="ignore")
        raise

def fetch_mmdb(url: str) -> maxminddb.Reader:
    path = CACHE_DIR / "rkn.mmdb"
    if not path.exists() or (time.time() - path.stat().st_mtime) > 6 * 3600:
        r = _session.get(url, timeout=40)
        r.raise_for_status()
        path.write_bytes(r.content)
    return maxminddb.open_database(str(path))

# ──────────────────────────────────────────────
# ПАРСЕРЫ
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
            hostname=host,
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
    """Корректно обрабатывает port hopping: host:443,5000-6000"""
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
            hostname=host,
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
    # base64
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
# ГЕЙТЫ
# ──────────────────────────────────────────────
def vless_ok(c: Config, white_sni: Set[str], bad_sni: Set[str]) -> Tuple[bool, str]:
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

    sni = (c.sni or "").lower()
    if not sni:
        return False, "empty_sni"
    if any(b in sni for b in BAD_SNI_HINTS) or sni in bad_sni:
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

def score(c: Config, white_ips: Set[str]) -> int:
    s = 0
    sni = (c.sni or "").lower()
    if any(sni == d or sni.endswith("." + d) for d in EMPIRIC_GOOD_SNI):
        s += 400
    if c.resolved_ip in white_ips:
        s += 200
    if c.port == 443:
        s += 100
    if c.type == "hy2":
        if c.hop: s += 50
        if c.obfs: s += 50
    else:
        if c.flow: s += 50
    return s

# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────
def main():
    log.info("=== Loading allowlists ===")
    white_sni = set(
        l.strip().lower()
        for l in fetch(WHITE_SNI_URL).splitlines()
        if l.strip() and not l.startswith("#")
    )
    networks = []
    for line in fetch(WHITE_CIDR_URL).splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            try:
                networks.append(ipaddress.IPv4Network(line, strict=False))
            except Exception:
                pass
    white_ips = set(
        l.strip()
        for l in fetch(WHITE_IP_URL).splitlines()
        if l.strip() and not l.startswith("#")
    )
    bad_sni: Set[str] = set()  # можно добавить throttled-list при желании

    log.info(f"White SNI: {len(white_sni)}, CIDR: {len(networks)}, IPs: {len(white_ips)}")

    rkn = fetch_mmdb(RKN_MMDB_URL)
    log.info("RKN MMDB loaded")

    # Источники
    sources_file = Path("sources.txt")
    urls = []
    if sources_file.exists():
        for line in sources_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    else:
        log.error("sources.txt not found")
        sys.exit(1)

    all_cfgs: List[Config] = []
    for url in urls:
        name = url.split("/")[-1][:40]
        try:
            text = fetch(url, max_age_h=2)
            cnt = 0
            for line in text.splitlines():
                c = parse_line(line, name)
                if c:
                    all_cfgs.append(c)
                    cnt += 1
            log.info(f"{name}: {cnt} parsed")
        except Exception as e:
            log.warning(f"{name}: {e}")

    log.info(f"Total parsed: {len(all_cfgs)}")

    # Дедуп
    seen = set()
    unique = []
    for c in all_cfgs:
        k = c.dedup_key()
        if k not in seen:
            seen.add(k)
            unique.append(c)
    log.info(f"After dedup: {len(unique)}")

    # Фильтрация
    passed = []
    reasons = Counter()
    for c in unique:
        ip = resolve(c.hostname)
        if not ip:
            reasons["no_dns"] += 1
            continue
        c.resolved_ip = ip

        # RKN
        try:
            if rkn.get(ip) is not None:
                reasons["rkn_blocked"] += 1
                continue
        except Exception:
            pass

        # White IP/CIDR
        if ip not in white_ips and not any(ipaddress.IPv4Address(ip) in n for n in networks):
            reasons["ip_not_white"] += 1
            continue

        # Protocol gates
        if c.type == "vless":
            ok, reason = vless_ok(c, white_sni, bad_sni)
        else:
            ok, reason = hy2_ok(c)
        if not ok:
            reasons[reason] += 1
            continue

        c.score = score(c, white_ips)
        passed.append(c)

    log.info(f"Passed: {len(passed)}")
    log.info(f"Reject reasons: {dict(reasons)}")

    # Сортировка
    passed.sort(key=lambda x: x.score, reverse=True)

    # Вывод
    out = RESULTS_DIR / "working_vless_hy2.txt"
    with out.open("w", encoding="utf-8") as f:
        for c in passed:
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
                f.write(f"vless://{c.id}@{c.hostname}:{c.port}{q}#[VLESS] {c.sni} {c.resolved_ip}\n")
            else:
                params = []
                if c.obfs: params.append(f"obfs={c.obfs}")
                if c.obfs_password: params.append(f"obfs-password={urllib.parse.quote(c.obfs_password)}")
                if c.sni: params.append(f"sni={urllib.parse.quote(c.sni)}")
                if c.insecure: params.append("insecure=1")
                if c.pin_sha256: params.append(f"pinSHA256={c.pin_sha256}")
                q = "?" + "&".join(params) if params else ""
                hop = f",{c.hop}" if c.hop else ""
                f.write(f"hysteria2://{c.id}@{c.hostname}:{c.port}{hop}{q}#[HY2] {c.sni} {c.resolved_ip}\n")

    log.info(f"Written {len(passed)} configs → {out}")

    # Статистика
    stats = {
        "total_passed": len(passed),
        "by_type": dict(Counter(c.type for c in passed)),
        "reject_reasons": dict(reasons),
        "top10": [(c.score, c.type, c.sni, c.resolved_ip) for c in passed[:10]],
    }
    (RESULTS_DIR / "stats.json").write_text(json.dumps(stats, indent=2, ensure_ascii=False))
    log.info("Done.")

if __name__ == "__main__":
    main()
