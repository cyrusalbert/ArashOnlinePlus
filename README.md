# arashonline

Fetches every subscription listed in `sourcelist.txt`, tests all configs with **Xray-core**,
and publishes filtered, renamed and sorted lists. A GitHub Actions workflow repeats the whole
cycle every 6 hours and commits the results.

## Pipeline

1. Read `sourcelist.txt`, download all subscriptions (plain or base64), parse
   `vmess://` `vless://` `trojan://` `ss://` `hysteria2://`, de-duplicate.
2. Alive test through Xray-core against `https://www.gstatic.com/generate_204`; drop dead
   configs and anything above **3000 ms**.
3. Sort by ping, then speed-test (aggregate download, 4 streams); drop anything below **50 Mbps**.
4. Rename remarks to `rank | flag | ip:port | ping | speed`, e.g.
   `1 | 🇩🇪 | 203.0.113.7:443 | 84ms | 412.6Mbps`.
5. Write the outputs below.

| File | Content |
|---|---|
| `arashonline.txt` | every verified config, sorted by ping |
| `arashonline-top50speed.txt` | 50 fastest |
| `arashonline-top50ping.txt` | 50 lowest ping |
| `arashonline-highvalue.txt` | ping 0-200 ms and speed > 800 Mbps |
| `arashonline-BestLoc.txt` | best config per country (balanced score) |
| `arashonline-highspeed.txt` | 50 fastest (same selection as top50speed) |

Remarks keep the rank from `arashonline.txt`, so a config has the same name in every file.

**Score** (BestLoc) = 0.5 * `100 / (1 + ping/250)` + 0.5 * `100 * speed / (speed + 200)`.

## Setup

1. Put subscription URLs in `sourcelist.txt` (one per line). For a public repository keep
   private URLs out of it: add them to the `EXTRA_SOURCES` secret instead (one per line).
2. Settings → Actions → General → Workflow permissions: **Read and write**.
3. Run the workflow once with *Run workflow*; afterwards the cron takes over.

Optional repository variables: `RUNNER_LABEL` (e.g. `self-hosted` to test from your own
network), `XRAY_VERSION` (pin a tag; default is the latest release).

## Local run

```bash
bash scripts/install-xray.sh ./xray
go vet ./... && go test ./...
go build -o arashonline-bin . && ./arashonline-bin -xray ./xray/xray
```

Tunables (environment variables): `MAX_PING_MS` 3000, `MIN_SPEED_MBPS` 50, `BATCH_SIZE` 200,
`PING_CONCURRENCY` 64, `SPEED_STREAMS` 4, `SPEED_DURATION_SEC` 8, `SPEED_CONCURRENCY` 1,
`MAX_SPEED_CANDIDATES` 800, `MAX_CONFIGS` 0, `PING_URL`, `SPEED_URLS`, `DEBUG`. See
`internal/config/config.go`.

## Notes

- Current Xray-core removed `allowInsecure`, and refuses plaintext VLESS/Trojan to public
  addresses. Such configs are skipped (counted as "unsupported" in the log).
- Hysteria2 needs an Xray-core build with the `hysteria` outbound; older builds skip them.
- If nothing passes the filters, the run fails and the previous files stay untouched.
- Speed numbers depend on the runner's bandwidth; they are comparable between configs, not absolute.
