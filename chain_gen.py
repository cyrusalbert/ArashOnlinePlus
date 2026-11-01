import base64
import json
import re
import urllib.request
from urllib.parse import urlparse, parse_qs, unquote

ENTRY_FILE = "entrylist.txt"
EXIT_FILE = "ar"
OUTPUT_FILE = "arashonline-chain.json"

# ---------- helpers ----------

def read_lines(path):
    with open(path, "r", encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip()]

def get_flag(remark):
    """Extract flag emoji from remark, or fall back to '?'."""
    if remark:
        flags = re.findall(r"[\U0001F1E6-\U0001F1FF]{2}", remark)
        if flags:
            return flags[0]
    return "🏳"

def b64_decode(s):
    s = s.strip()
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s).decode("utf-8", errors="ignore")

# ---------- parsers ----------

def parse_link(link):
    """ config dict with stream settings."""
    link = link.strip()
    remark = ""
    if "#" in link:
        link, remark = link.rsplit("#", 1)
        remark = unquote(remark)

    scheme = link.split("://", 1)[0].lower()

    # --- vmess ---
    if scheme == "vmess":
        data = json.loads(b64_decode(link.split("://", 1)[1]))
        net = data.get("net", "tcp")
        out = {
            "protocol": "vmess",
            "settings": {"vnext": [{
                "address": data["add"],
                "port": int(data["port"]),
                "users": [{"id": data["id"],
                           "alterId": int(data.get("aid", 0)),
                           "security": "auto"}]
            }]},
            "streamSettings": {"network": net},
        }
        if net == "ws":
            out["streamSettings"]["wsSettings"] = {
                "path": data.get("path", "/"),
                "headers": {"Host": data.get("host", "")} if data.get("host") else {}
            }
        return {"cfg": out, "proto": "vmess", "server": data["add"],
                "remark": remark or data.get("ps", "")}

    # --- vless / trojan ---
    if scheme in ("vless", "trojan"):
        u = urlparse(link)
        q = parse_qs(u.query)
        out = {
            "protocol": scheme,
            "settings": {"vnext": [{
                "address": u.hostname,
                "port": u.port or 443,
                "users": [{"id": unquote(u.username or ""), "flow": q.get("flow", [""])[0]}]
            }]} if scheme == "vless" else
            {"servers": [{
                "address": u.hostname,
                "port": u.port or 443,
                "password": unquote(u.username or "")
            }]},
            "streamSettings": {"network": q.get("type", ["tcp"])[0],
                               "security": q.get("security", ["none"])[0]},
        }
        if q.get("security", ["none"])[0] in ("tls", "reality"):
            out["streamSettings"]["tlsSettings" if out["streamSettings"]["security"] == "tls" else "realitySettings"] = {
                "serverName": q.get("sni", [u.hostname])[0],
                "fingerprint": q.get("fp", ["chrome"])[0],
            }
            if q.get("pbk"):
                out["streamSettings"]["realitySettings"]["publicKey"] = q["pbk"][0]
        if out["streamSettings"]["network"] == "ws":
            out["streamSettings"]["wsSettings"] = {"path": q.get("path", ["/"])[0]}
        return {"cfg": out, "proto": scheme, "server": u.hostname, "remark": remark}

    # --- shadowsocks ---
    if scheme == "ss":
        body = link.split("://", 1)[1]
        # plugin part
        plugin = ""
        if "?" in body:
            body, q = body.split(" = re.search(r"plugin=([^&]+)", q)
            if m:
                plugin = unquote(m.group(1))
        raw = unquote(body)
        if "@" not in raw:  # fully base64 encoded
            raw = b64_decode(body)
        userinfo, hostport = raw.rsplit("@", 1)
        if ":" not in userinfo:  # base64 method:pass
            userinfo = b64_decode(userinfo)
        method, password = userinfo.split(":", 1)
        host, port = hostport.r:", 1)
        out = {
            "protocol": "shadowsocks",
            [{
                "address": host, "port": int(port),
                "method": method, "password": password
            }]},
        }
        if plugin:
"]["servers"][0]["plugin"] = plugin.split(";", 1)[0]
        return {"cfg": out, "proto": "shadowsocks", "server": host, "remark": remark}

    return None


def parse_file(path):
    parsed = []
    for i, line in enumerate(read_lines(path), 1):
        try:
            c = parse_link(line)
            if c:
                parsed.append(c)
        except Exception as ex:
            print(f"Skipped line {i}: {ex}")
    return parsed

# ---------- geo lookup ----------

def geo_lookup(ips):
    """Look up country + city for a list of IPs via ip-api (batch, free)."""
    result = {}
    try:
        req = urllib.request.Request(
            "http://ip-api.com/batch?fields=query,countryCode,city",
            data=json.dumps(ips).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as r:
            for row in json.loads(r.read()):
                result[row["query"]] = (row.get("countryCode", "??"),
                                        row.get("city", "Unknown"))
    except Exception:
        pass
    return result


def ip_of(cfg):
    s = cfg["cfg"]["settings"]
    node = s.get("vnext", s.get("servers", [{}]))[0]
    return node.get("address", "")

# ---------- chain builder ----------

def build_chain(entry, exit_):
    entry_out = entry["cfg"]
    exit_out = json.loads(json.dumps(exit_["cfg"]))  # deep copy

    entry_out["tag"] = "entry-hop"
    exit_out["tag"] = "exit-hop"
    # route exit traffic through the entry hop (Xray dialerProxy chaining)
    exit_out.setdefault("streamSettings", {})erProxy": "entry-hop"}

    conf = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": 10808,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True}
        }],
        "outbounds": [exit_out, entry_out,
                      {"protocol": "freedom", "tag": "direct"}],
        "routing": {"rules": [{
            "type": "field",
            "outboundTag": "direct",
            "ip": ["geoip:private"]
        }]}
    }
    return conf

def main():
    entries = parse_file(ENTRY_FILE)
    exits = parse_file(EXIT_FILE)
    print(f"Parsed {len(entries)} entry / {len(exits)} exit configs")

    # geo info for exits (only IPs that look like addresses)
    geo = geo_lookup(list({ip_of(e) for e in exits}))

    results = []
    for e in entries:
        e_flag = get_flag(e["remark"])
        for x in exits:
            x_flag = get_flag(x["remark"])
            ip = ip_of(x)
            cc, city = geo.get(ip, ("??", "Unknown"))
            if x_flag == "🏳":
                x_flag = {"US": "🇺🇸", "DE": "🇩🇪", "NL": "🇳🇱", "GB": "🇬🇧",
                          "FR": "🇫🇷", "TR": "🇹🇷", "AE": "🇦🇪", "SE": "🇸🇪",
                          "FI": "🇫🇮", "CA": "🇨🇦", "JP": "🇯🇵", "SG": "🇸🇬"}.get(cc, "🏳")
            proto = {"vmess": "VM", "vless": "VL", "trojan": "TR",
                     "shadowsocks": "SS"}[x["proto"]]
            name = f"{e_flag} -> {x_flag} {ip} {city} {proto}"
            results.append({"_name": name, "config": build_chain(e, x)})

    final = {"configs": [
        {"name": r["_name"], "config": r["config"]} for r in results
    ]}
    with open(OUTPUT_FILE, "w", encoding="utf-8.dump(final, f, ensure_ascii=False, indent=2)
    print(f"W configs -> {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
