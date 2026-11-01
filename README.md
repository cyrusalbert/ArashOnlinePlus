<div align="center">

# 🌐 ArashOnline

**Fresh, tested and ranked V2Ray / Xray subscriptions, rebuilt every 6 hours.**

[![Update configs](https://github.com/cyrusalbert/ArashOnlinePlus/actions/workflows/update.yml/badge.svg)](https://github.com/cyrusalbert/ArashOnlinePlus/actions/workflows/update.yml)
![Refresh](https://img.shields.io/badge/refresh-every%206%20hours-blue)
![Protocols](https://img.shields.io/badge/protocols-vmess%20%7C%20vless%20%7C%20trojan%20%7C%20ss%20%7C%20hysteria2-informational)

</div>

Every config in these lists was tested through **Xray-core**: it is alive, answers in under
**3000 ms** and downloads at **50 Mbps or more**. The workflow re-tests everything every
6 hours, so dead configs drop out on their own.

## 🔗 Subscription links

Copy a link, then add it as a subscription in your client. Pick the list that fits what you need.

### 📦 ArashOnline: everything
All verified configs, sorted by ping from lowest to highest. The best general-purpose choice.
```
https://raw.githubusercontent.com/cyrusalbert/ArashOnlinePlus/main/arashonline.txt#ArashOnlinePlus
```

### 🚀 ArashOnline-top50speed: fastest 50
The 50 configs with the highest download speed. Best for large downloads and streaming.
```
https://raw.githubusercontent.com/cyrusalbert/ArashOnlinePlus/main/arashonline-top50speed.txt#ArashOnlinePlus-top50speed
```

### ⚡ ArashOnline-highspeed: high-speed 50
The same 50 fastest configs as above, kept under a second name for clients and setups that already use it.
```
https://raw.githubusercontent.com/cyrusalbert/ArashOnlinePlus/main/arashonline-highspeed.txt#ArashOnlinePlus-highspeed
```

### 🎯 ArashOnline-top50ping: lowest latency 50
The 50 configs with the lowest ping. Best for gaming, calls and everyday browsing.
```
https://raw.githubusercontent.com/cyrusalbert/ArashOnlinePlus/main/arashonline-top50ping.txt#ArashOnlinePlus-top50ping
```

### 💎 ArashOnline-highvalue: fast and responsive
Only configs with ping between 0 and 200 ms **and** speed above 800 Mbps. A short list, but the best of both worlds.
```
https://raw.githubusercontent.com/cyrusalbert/ArashOnlinePlus/main/arashonline-highvalue.txt#ArashOnlinePlus-highvalue
```

### 🌍 ArashOnline-BestLoc: best config per country
One config per country, chosen by a balanced score of ping and speed. Best when you need a specific location.
```
https://raw.githubusercontent.com/cyrusalbert/ArashOnlinePlus/main/arashonline-BestLoc.txt#ArashOnlinePlus-BestLoc
```

### 🧭 Which one should I use?

| I want… | Use |
|---|---|
| Plenty of choice, auto-select the fastest | **ArashOnline** |
| Maximum download speed | **ArashOnline-top50speed** |
| Lowest latency | **ArashOnline-top50ping** |
| Both fast and responsive | **ArashOnline-highvalue** |
| A server in a particular country | **ArashOnline-BestLoc** |

### 📲 How to add a subscription

1. Copy one of the links above.
2. In your client (v2rayN, v2rayNG, Hiddify and similar), open **Subscription settings** and add a new subscription.
3. Paste the link, save, then **update subscription**. The text after `#` becomes the subscription's name.
4. Update again from time to time. The lists change every 6 hours.

## 🏷️ Config names

Every config is renamed to the same format in all lists:

```
rank | flag | ip:port | ping | speed
1 | 🇩🇪 | 203.0.113.7:443 | 84ms | 412.6Mbps
```

The rank is the position by ping in the main list, so a config keeps the same name everywhere.

## ⚙️ How it works

1. Reads `sourcelist.txt`, downloads every subscription (plain or base64), parses
   `vmess://` `vless://` `trojan://` `ss://` `hysteria2://` and removes duplicates.
2. Alive test through Xray-core against `https://www.gstatic.com/generate_204`; drops dead
   configs and anything above **3000 ms**.
3. Sorts by ping, then speed-tests the candidates (aggregate download, 4 streams) and drops
   anything below **50 Mbps**.
4. Renames the remarks and writes the six lists above.

**BestLoc score** = 0.5 × `100 / (1 + ping/250)` + 0.5 × `100 × speed / (speed + 200)`.

## 🛠️ Setup (for your own copy)

1. Put subscription URLs in `sourcelist.txt` (one per line). For a public repository keep
   private URLs out of it: add them to the `EXTRA_SOURCES` secret instead (one per line).
2. Settings → Actions → General → Workflow permissions: **Read and write**.
3. Run the workflow once with *Run workflow*; afterwards the cron takes over.

Optional repository variables: `RUNNER_LABEL` (e.g. `self-hosted` to test from your own
network), `XRAY_VERSION` (pin a tag; default is the latest release).

## 💻 Local run

```bash
bash scripts/install-xray.sh ./xray
go vet ./... && go test ./...
go build -o arashonline-bin . && ./arashonline-bin -xray ./xray/xray
```

Tunables (environment variables): `MAX_PING_MS` 3000, `MIN_SPEED_MBPS` 50, `BATCH_SIZE` 200,
`PING_CONCURRENCY` 64, `SPEED_STREAMS` 4, `SPEED_DURATION_SEC` 8, `SPEED_CONCURRENCY` 1,
`MAX_SPEED_CANDIDATES` 800, `MAX_CONFIGS` 0, `PING_URL`, `SPEED_URLS`, `DEBUG`. See
`internal/config/config.go`.

## 📝 Notes

- Current Xray-core removed `allowInsecure` and refuses plaintext VLESS/Trojan to public
  addresses. Such configs are skipped.
- Hysteria2 needs an Xray-core build with the `hysteria` outbound; older builds skip them.
- If nothing passes the filters, the run fails and the previous files stay untouched.
- Speed numbers depend on the runner's bandwidth; they are comparable between configs, not absolute.
