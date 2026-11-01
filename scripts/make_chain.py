#!/usr/bin/env python3
"""Build chained V2Ray configs: every entry config x every exit config.

Inputs
  entrylist.txt            entry configs, one share link per line
  arashonline-BestLoc.txt  exit configs (written by the Go pipeline)

Output
  arashonline-chain.json   sing-box outbounds; only the produced chains

Traffic flows  client -> entry server -> exit server -> internet.  In sing-box that is an
exit outbound with  "detour": "<entry tag>".  sing-box can only reference an outbound by tag,
so every entry also appears once as a helper outbound (tags "entry-1", "entry-2", ...).

Chain name:  [entry flag] -> [exit flag] [exit ip] [city] [exit protocol acronym]

Supported links: vmess://  vless://  trojan://  ss://  hysteria2:// (hy2://).
Links sing-box cannot express (xhttp transport, vless encryption, ...) are skipped with a note.
Standard library only.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass

ACRONYMS = {"vmess": "VM", "vless": "VL", "trojan": "TR", "ss": "SS", "hysteria2": "HY2"}
UNKNOWN_FLAG = "\U0001F3F3\ufe0f"
FLAG_RE = re.compile("[\U0001F1E6-\U0001F1FF]{2}")
HOP_RE = re.compile(r"(:\d+)[,\-][\d,\-]+")  # hysteria2 port hopping: host:443,20000-30000


class LinkError(Exception):
    """A link that is invalid or cannot be expressed as a sing-box outbound."""


@dataclass
class Parsed:
    proto: str  # vmess | vless | trojan | ss | hysteria2
    host: str
    port: int
    remark: str
    outbound: dict  # sing-box outbound without tag / detour


@dataclass
class Endpoint:
    p: Parsed
    flag: str = ""
    ip: str = ""
    city: str = ""


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- small helpers

def b64decode(s: str) -> bytes:
    s = re.sub(r"\s+", "", s).replace("-", "+").replace("_", "/").rstrip("=")
    return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)


def truthy(s: str) -> bool:
    return str(s).strip().lower() in ("1", "true")


def to_int(v) -> int:
    try:
        return int(str(v).strip())
    except ValueError:
        return 0


def split_list(s: str) -> list[str]:
    return [x.strip() for x in s.split(",") if x.strip()]


def first(q: dict, *keys: str) -> str:
    for k in keys:
        if q.get(k):
            return q[k][0]
    return ""


def split_fragment(raw: str) -> tuple[str, str]:
    base, _, frag = raw.partition("#")
    return base, urllib.parse.unquote(frag)


def split_hostport(hp: str) -> tuple[str, int]:
    m = re.fullmatch(r"\[([^\]]+)\]:(\d+)", hp) or re.fullmatch(r"([^:]+):(\d+)", hp)
    if not m:
        raise LinkError("bad host:port")
    return m.group(1), int(m.group(2))


def split_url(raw: str):
    base, remark = split_fragment(raw)
    sp = urllib.parse.urlsplit(base)
    try:
        port = sp.port
    except ValueError:
        port = None
    if not sp.hostname or not port:
        raise LinkError("invalid host:port")
    user = urllib.parse.unquote(sp.username or "")
    if sp.password is not None:
        user += ":" + urllib.parse.unquote(sp.password)
    return sp.hostname, port, urllib.parse.parse_qs(sp.query), user, remark


# --------------------------------------------------------------------------- tls + transport

def opts_from_query(q: dict) -> dict:
    return {
        "network": first(q, "type"),
        "security": first(q, "security").lower(),
        "header_type": first(q, "headerType"),
        "host": first(q, "host"),
        "path": first(q, "path"),
        "service_name": first(q, "serviceName"),
        "sni": first(q, "sni", "peer"),
        "fp": first(q, "fp"),
        "alpn": first(q, "alpn"),
        "pbk": first(q, "pbk"),
        "sid": first(q, "sid"),
        "insecure": truthy(first(q, "allowInsecure", "insecure")),
    }


def stream(o: dict) -> dict:
    """sing-box "transport" and "tls" fields shared by vmess, vless and trojan."""
    out: dict = {}
    net = (o["network"] or "tcp").lower()
    host, path = o["host"], o["path"]

    if net in ("tcp", "raw"):
        if o["header_type"].lower() == "http":
            raise LinkError("tcp HTTP-header obfuscation is not supported by sing-box")
    elif net in ("ws", "websocket"):
        p, _, query = (path or "/").partition("?")
        tr = {"type": "ws", "path": p or "/"}
        params = urllib.parse.parse_qsl(query, keep_blank_values=True)
        ed = [v for k, v in params if k == "ed"]
        rest = [(k, v) for k, v in params if k != "ed"]
        if ed and ed[0].isdigit():
            tr["max_early_data"] = int(ed[0])
            tr["early_data_header_name"] = "Sec-WebSocket-Protocol"
        if rest:
            tr["path"] += "?" + urllib.parse.urlencode(rest)
        if host:
            tr["headers"] = {"Host": host}
        out["transport"] = tr
    elif net in ("grpc", "gun"):
        out["transport"] = {"type": "grpc", "service_name": o["service_name"]}
    elif net == "httpupgrade":
        tr = {"type": "httpupgrade", "path": path or "/"}
        if host:
            tr["host"] = host
        out["transport"] = tr
    elif net in ("h2", "http"):
        tr = {"type": "http", "path": path or "/"}
        if host:
            tr["host"] = split_list(host)
        out["transport"] = tr
    else:
        raise LinkError(f"transport {o['network']!r} is not supported by sing-box")

    sec = o["security"]
    if sec in ("", "none"):
        return out
    if sec not in ("tls", "reality"):
        raise LinkError(f"security {sec!r} is not supported")
    tls: dict = {"enabled": True}
    sni = o["sni"] or (host if host and "," not in host else "")
    if sni:
        tls["server_name"] = sni
    if o["insecure"]:
        tls["insecure"] = True
    if o["alpn"]:
        tls["alpn"] = split_list(o["alpn"])
    fp = o["fp"]
    if sec == "reality":
        if not o["pbk"]:
            raise LinkError("reality without public key")
        fp = fp or "chrome"
        tls["reality"] = {"enabled": True, "public_key": o["pbk"], "short_id": o["sid"]}
    if fp:
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    out["tls"] = tls
    return out


# --------------------------------------------------------------------------- link parsers

def parse_vmess(raw: str) -> Parsed:
    payload = split_fragment(raw)[0][len("vmess://"):].strip()
    if "@" in payload:  # vmess://uuid@host:port?... (URL form)
        host, port, q, uid, remark = split_url(raw)
        if not uid:
            raise LinkError("missing uuid")
        ob = {"type": "vmess", "server": host, "server_port": port, "uuid": uid,
              "security": first(q, "encryption") or "auto", "alter_id": 0}
        ob.update(stream(opts_from_query(q)))
        return Parsed("vmess", host, port, remark, ob)

    try:
        m = json.loads(b64decode(payload))
    except (binascii.Error, ValueError) as e:
        raise LinkError(f"bad vmess payload: {e}")
    if not isinstance(m, dict):
        raise LinkError("bad vmess payload")
    host, uid, port = str(m.get("add", "")).strip(), str(m.get("id", "")).strip(), to_int(m.get("port"))
    if not host or not uid or not 1 <= port <= 65535:
        raise LinkError("incomplete vmess config")
    net = str(m.get("net", ""))
    o = {
        "network": net,
        "security": str(m.get("tls", "")).lower(),
        "header_type": str(m.get("type", "")),
        "host": str(m.get("host", "")),
        "path": str(m.get("path", "")),
        "service_name": str(m.get("path", "")) if net.lower() == "grpc" else "",
        "sni": str(m.get("sni", "")),
        "fp": str(m.get("fp", "")),
        "alpn": str(m.get("alpn", "")),
        "pbk": "",
        "sid": "",
        "insecure": truthy(m.get("allowInsecure", m.get("insecure", ""))),
    }
    scy = str(m.get("scy", "")) or "auto"
    if scy not in ("auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305"):
        scy = "auto"
    ob = {"type": "vmess", "server": host, "server_port": port, "uuid": uid,
          "security": scy, "alter_id": to_int(m.get("aid"))}
    ob.update(stream(o))
    return Parsed("vmess", host, port, str(m.get("ps", "")), ob)


def parse_vless(raw: str) -> Parsed:
    host, port, q, uid, remark = split_url(raw)
    if not uid:
        raise LinkError("missing uuid")
    if first(q, "encryption") not in ("", "none"):
        raise LinkError("vless encryption is not supported by sing-box")
    ob = {"type": "vless", "server": host, "server_port": port, "uuid": uid}
    if first(q, "flow"):
        ob["flow"] = first(q, "flow")
    ob["packet_encoding"] = "xudp"
    ob.update(stream(opts_from_query(q)))
    return Parsed("vless", host, port, remark, ob)


def parse_trojan(raw: str) -> Parsed:
    host, port, q, password, remark = split_url(raw)
    if not password:
        raise LinkError("missing password")
    o = opts_from_query(q)
    o["security"] = o["security"] or "tls"  # trojan links default to TLS
    ob = {"type": "trojan", "server": host, "server_port": port, "password": password}
    ob.update(stream(o))
    return Parsed("trojan", host, port, remark, ob)


def parse_ss(raw: str) -> Parsed:
    base, remark = split_fragment(raw)
    body, _, query = base[len("ss://"):].partition("?")
    body = body.rstrip("/")
    if "@" in body:  # SIP002: base64(method:password)@host:port, or plain userinfo
        userinfo, _, hostport = body.rpartition("@")
        try:
            creds = b64decode(userinfo).decode()
            if ":" not in creds:
                raise ValueError
        except (binascii.Error, ValueError):
            creds = urllib.parse.unquote(userinfo)
    else:  # legacy: base64(method:password@host:port)
        try:
            decoded = b64decode(body).decode()
        except (binascii.Error, ValueError) as e:
            raise LinkError(f"bad shadowsocks link: {e}")
        if "@" not in decoded:
            raise LinkError("bad shadowsocks link")
        creds, _, hostport = decoded.rpartition("@")
    method, _, password = creds.partition(":")
    if not method or not password:
        raise LinkError("bad shadowsocks credentials")
    host, port = split_hostport(hostport)
    ob = {"type": "shadowsocks", "server": host, "server_port": port,
          "method": method.lower(), "password": password}
    plugin = first(urllib.parse.parse_qs(query), "plugin")
    if plugin:
        name, _, opts = plugin.partition(";")
        if name not in ("obfs-local", "v2ray-plugin"):
            raise LinkError(f"shadowsocks plugin {name!r} is not supported by sing-box")
        ob["plugin"], ob["plugin_opts"] = name, opts
    return Parsed("ss", host, port, remark, ob)


def parse_hysteria2(raw: str) -> Parsed:
    base, remark = split_fragment(raw)
    rest = base.partition("://")[2]
    m = re.search(r"[/?]", rest)
    end = m.start() if m else len(rest)
    sp = urllib.parse.urlsplit("hysteria2://" + HOP_RE.sub(r"\1", rest[:end]) + rest[end:])
    try:
        port = sp.port or 443
    except ValueError:
        raise LinkError("invalid port")
    if not sp.hostname:
        raise LinkError("missing host")
    auth = urllib.parse.unquote(sp.username or "")
    if sp.password is not None:
        auth += ":" + urllib.parse.unquote(sp.password)
    if not auth:
        raise LinkError("missing hysteria2 password")
    q = urllib.parse.parse_qs(sp.query)
    insecure = truthy(first(q, "insecure", "allowInsecure"))
    if first(q, "pinSHA256") and not insecure:
        raise LinkError("certificate-pinned hysteria2 is not supported")
    tls: dict = {"enabled": True, "alpn": ["h3"]}
    if first(q, "sni", "peer"):
        tls["server_name"] = first(q, "sni", "peer")
    if insecure:
        tls["insecure"] = True
    ob = {"type": "hysteria2", "server": sp.hostname, "server_port": port, "password": auth, "tls": tls}
    obfs = first(q, "obfs")
    if obfs:
        if obfs.lower() != "salamander":
            raise LinkError(f"hysteria2 obfs {obfs!r} is not supported")
        ob["obfs"] = {"type": "salamander", "password": first(q, "obfs-password")}
    return Parsed("hysteria2", sp.hostname, port, remark, ob)


PARSERS = {"vmess": parse_vmess, "vless": parse_vless, "trojan": parse_trojan,
           "ss": parse_ss, "hysteria2": parse_hysteria2, "hy2": parse_hysteria2}


def parse_link(raw: str) -> Parsed:
    scheme = raw.split("://", 1)[0].lower()
    fn = PARSERS.get(scheme)
    if fn is None or "://" not in raw:
        raise LinkError("unknown scheme")
    return fn(raw.strip())


def read_links(path: str, label: str) -> list[Parsed]:
    if not os.path.exists(path):
        sys.exit(f"error: {label} file not found: {path}")
    out: list[Parsed] = []
    seen: set[str] = set()
    skipped = 0
    with open(path, encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                p = parse_link(line)
            except LinkError as e:
                skipped += 1
                log(f"  skip {label}: {e}")
                continue
            key = json.dumps(p.outbound, sort_keys=True)
            if key not in seen:
                seen.add(key)
                out.append(p)
    log(f"{label}: {len(out)} usable, {skipped} skipped ({path})")
    return out


# --------------------------------------------------------------------------- flags + geo

def find_flag(text: str) -> str:
    m = FLAG_RE.search(text or "")
    return m.group(0) if m else ""


def flag_to_cc(flag: str) -> str:
    return "".join(chr(ord(c) - 0x1F1E6 + 65) for c in flag)


def cc_to_flag(cc: str) -> str:
    cc = (cc or "").upper()
    if len(cc) != 2 or not cc.isascii() or not cc.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - 65) for c in cc)


def exit_from_remark(remark: str) -> tuple[str, str]:
    """BestLoc remarks are 'rank | flag | ip:port | ping | speed'. Returns (flag, ip)."""
    parts = [x.strip() for x in remark.split("|")]
    if len(parts) < 3:
        return "", ""
    m = re.fullmatch(r"\[([^\]]+)\]:\d+", parts[2]) or re.fullmatch(r"(.+):\d+", parts[2])
    ip = m.group(1) if m else ""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        ip = ""
    return find_flag(parts[1]), ip


def resolve(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
    except OSError:
        pass
    try:
        return socket.getaddrinfo(host, None)[0][4][0]
    except OSError:
        return ""


def http_json(url: str, payload=None, timeout: int = 20):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json", "User-Agent": "arashonline-chain/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def geolocate(ips: list[str]) -> dict[str, dict]:
    """ip -> {"cc": "DE", "city": "Frankfurt am Main"} via ip-api.com (batch), ipwho.is as fallback."""
    uniq = sorted(set(i for i in ips if i))
    result: dict[str, dict] = {}
    for i in range(0, len(uniq), 100):
        chunk = uniq[i:i + 100]
        try:
            for d in http_json("http://ip-api.com/batch?fields=status,countryCode,city,query", chunk):
                if d.get("status") == "success":
                    result[d["query"]] = {"cc": d.get("countryCode", ""), "city": d.get("city", "")}
        except Exception as e:  # network error, rate limit, bad JSON
            log(f"geo: ip-api batch failed ({e}); falling back to ipwho.is")
        if i + 100 < len(uniq):
            time.sleep(4.5)  # free tier allows 15 batch requests per minute
    for ip in uniq:
        if ip in result:
            continue
        try:
            d = http_json(f"https://ipwho.is/{ip}", timeout=10)
            if d.get("success"):
                result[ip] = {"cc": d.get("country_code", ""), "city": d.get("city", "")}
        except Exception:
            pass
        time.sleep(0.3)
    return result


# --------------------------------------------------------------------------- chain building

def chain_name(entry: Endpoint, exit_: Endpoint) -> str:
    tail = " ".join(x for x in (exit_.flag, exit_.ip, exit_.city, ACRONYMS[exit_.p.proto]) if x)
    return f"{entry.flag or UNKNOWN_FLAG} -> {tail}"


def describe(entries: list[Parsed], exits: list[Parsed]) -> tuple[list[Endpoint], list[Endpoint]]:
    """Work out flag / ip / city for every entry and exit."""
    ens = [Endpoint(p, flag=find_flag(p.remark)) for p in entries]
    exs = []
    for p in exits:
        flag, ip = exit_from_remark(p.remark)
        exs.append(Endpoint(p, flag=flag, ip=ip or resolve(p.host)))

    # entries without a flag in their remark are located by IP
    for en in ens:
        if not en.flag:
            en.ip = resolve(en.p.host)

    geo = geolocate([e.ip for e in exs] + [e.ip for e in ens if not e.flag])

    for en in ens:
        if not en.flag:
            en.flag = cc_to_flag(geo.get(en.ip, {}).get("cc", ""))
    for ex in exs:
        info = geo.get(ex.ip, {})
        ex.city = info.get("city", "")
        if not ex.flag:
            ex.flag = cc_to_flag(info.get("cc", ""))
        elif info.get("cc") and flag_to_cc(ex.flag) != info["cc"]:
            ex.city = ""  # server IP and tested exit country disagree (CDN): a city would mislead
    return ens, exs


def build(ens: list[Endpoint], exs: list[Endpoint]) -> list[dict]:
    chains: list[dict] = []
    helpers: list[dict] = []
    used: set[str] = set()
    for n, en in enumerate(ens, 1):
        entry_tag = f"entry-{n}"
        helpers.append({"type": en.p.outbound["type"], "tag": entry_tag,
                        **{k: v for k, v in en.p.outbound.items() if k != "type"}})
        for ex in exs:
            if (en.p.host, en.p.port) == (ex.p.host, ex.p.port):
                continue  # an entry cannot chain to itself
            name = chain_name(en, ex)
            tag, i = name, 1
            while tag in used:  # entries with the same flag produce the same name
                i += 1
                tag = f"{name} ({i})"
            used.add(tag)
            chains.append({"type": ex.p.outbound["type"], "tag": tag,
                           **{k: v for k, v in ex.p.outbound.items() if k != "type"},
                           "detour": entry_tag})
    return chains + helpers


def main() -> int:
    ap = argparse.ArgumentParser(description="Chain every entry config with every exit config.")
    ap.add_argument("--entries", default="entrylist.txt")
    ap.add_argument("--exits", default="arashonline-BestLoc.txt")
    ap.add_argument("--out", default="arashonline-chain.json")
    ap.add_argument("--array", action="store_true",
                    help='write a bare JSON array of outbounds instead of {"outbounds": [...]}')
    args = ap.parse_args()

    entries = read_links(args.entries, "entry")
    exits = read_links(args.exits, "exit")
    if not entries or not exits:
        log("error: need at least one entry and one exit; existing output is left untouched")
        return 1

    ens, exs = describe(entries, exits)
    outbounds = build(ens, exs)
    chains = sum(1 for o in outbounds if "detour" in o)
    if chains == 0:
        log("error: no chains produced; existing output is left untouched")
        return 1

    doc = outbounds if args.array else {"outbounds": outbounds}
    tmp = args.out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(tmp, args.out)
    log(f"done: {len(ens)} entries x {len(exs)} exits -> {chains} chains in {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
