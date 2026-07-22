# CPE agent feature guide

How to use `cpe_agent` as it exists today, with copy-paste examples.

---

## Feature map

| Feature | How you use it |
|--------|----------------|
| CLI | `--config`, `--router-id`, `--demo`, `--once`, `--lua`/`--repl`, `--lua-eval`, `--lua-file`, `--help` |
| Lua tools | Embedded Lua 5.4 + linenoise REPL; `cpe.*` API (see [cpe-agent-lua.md](cpe-agent-lua.md)) |
| YAML config | router id, emit mode, probe target, intervals, timeouts |
| Demo ping | Synthetic RTT/loss (no privileges) |
| Live ICMP | Real echo to `demo.target` (`demo.enabled: false`) |
| Live / demo arping | ARP request/reply → `probe=arping` (meta.mac / iface); Lua `cpe.arping` |
| Wi‑Fi state / stats | iface operstate + nl80211 stations → `cpe_wifi` NDJSON; Lua `cpe.wifi_*` |
| Emit: stdout | NDJSON on stdout (lab / Vector pipe) |
| Emit: spool | Append to a file under a size cap |
| Emit: https | Optional mTLS POST (needs mbedTLS build) |
| Timer loop | Continuous samples at `interval_ms` |
| SIGHUP reload | Re-read YAML; keep CLI `--router-id` |
| OpenWrt service | procd init + `reload` → HUP |

Output is always **NDJSON** lines of `type=cpe_perf` (not ClickHouse from the CPE).

---

## 1. CLI flags

```bash
./cpe_agent --help

# One synthetic sample, then exit (smoke test)
./cpe_agent --once --router-id lab-1
./cpe_agent --demo --once --router-id lab-1   # same: forces demo

# Config file + identity override
./cpe_agent --config /etc/cpe_agent/cpe_agent.yaml --router-id cpe-42

# Long-running (timer loop; needs YAML or built-in defaults)
./cpe_agent --config ./my.yaml --router-id cpe-42
```

| Flag | Effect |
|------|--------|
| `--config PATH` | Load YAML from `PATH` |
| `--router-id ID` | Set `router_id`; **kept across SIGHUP** |
| `--demo` | Force synthetic probes (overrides live YAML) |
| `--once` | One demo sample + flush, then exit (**always demo**) |
| *(none of once/demo)* | Continuous loop; demo/live from YAML |

**Important:** `--once` and `--demo` force **demo mode**. Live probes need a YAML with `demo.enabled: false` and **no** `--once`/`--demo`.

---

## 2. YAML configuration

Minimal template:

```yaml
router_id: cpe-lab-1

emit:
  mode: stdout          # stdout | spool | https
  # path: /var/spool/netforensics/cpe_perf.ndjson   # for spool

spool:
  max_lines: 128        # soft default on OpenWrt; hard max 1024

demo:
  enabled: true         # true = synthetic; false = live ICMP
  target: "1.1.1.1"     # probe destination (demo and live)
  interval_ms: 5000     # sample period in the run loop
  timeout_ms: 1000      # live ICMP wait
```

```bash
./cpe_agent --config /path/to/that.yaml
```

---

## 3. Demo mode (synthetic path quality)

No raw sockets, no CAP_NET_RAW. Good for packaging checks and pipelines.

```bash
# One line of NDJSON
./cpe_agent --demo --once --router-id lab-1
```

Example output:

```json
{"type":"cpe_perf","ts":"2026-07-22T01:23:53.836Z","router_id":"lab-1","probe":"ping","target":"1.1.1.1","rtt_ms":5.000,"loss":0.0000,"meta":{"replies":1,"timeouts":0,"demo":true}}
```

`meta.demo: true` means values are **not** real network measurements.

Continuous demo (YAML):

```yaml
router_id: lab-1
emit: { mode: stdout }
demo:
  enabled: true
  target: "1.1.1.1"
  interval_ms: 3000
```

```bash
./cpe_agent --config demo.yaml --router-id lab-1
# Ctrl-C / SIGTERM to stop
```

---

## 4. Live ICMP (real RTT / loss)

```yaml
# live.yaml
router_id: lab-1
emit:
  mode: stdout
demo:
  enabled: false
  target: "192.168.1.1"   # gateway, DNS, CDN, etc.
  interval_ms: 2000
  timeout_ms: 1000
```

```bash
# Prefer root or CAP_NET_RAW if unprivileged ICMP fails
./cpe_agent --config live.yaml --router-id lab-1
```

Expect something like:

```json
{"type":"cpe_perf",...,"target":"192.168.1.1","rtt_ms":1.234,"loss":0.0000,"meta":{"replies":1,"timeouts":0,"demo":false}}
```

Behavior:

- Tries `SOCK_DGRAM` + `IPPROTO_ICMP` first
- Falls back to `SOCK_RAW` (often needs `CAP_NET_RAW` / root)
- Timeout samples still emit (loss/timeouts reflected in meta)

Short multi-target exploration (one target per config):

```bash
for t in 192.168.1.1 8.8.8.8 1.1.1.1; do
  cat >/tmp/p.yaml <<EOF
router_id: lab-1
emit: { mode: stdout }
demo: { enabled: false, target: "$t", interval_ms: 1000, timeout_ms: 800 }
EOF
  echo "=== $t ==="
  timeout 4 ./cpe_agent --config /tmp/p.yaml
done
```

---

## 5. Emit modes

### 5a. `stdout` (default / lab)

```yaml
emit:
  mode: stdout
```

```bash
./cpe_agent --config my.yaml | tee /tmp/cpe_perf.ndjson
# or pipe into Vector / logger
./cpe_agent --config my.yaml | logger -t cpe_agent
```

### 5b. `spool` (file append)

```yaml
# spool.yaml
router_id: lab-1
emit:
  mode: spool
  path: /exa_data/ecolink/cpe_perf.ndjson
spool:
  max_lines: 256
demo:
  enabled: false
  target: "1.1.1.1"
  interval_ms: 5000
  timeout_ms: 1000
```

```bash
mkdir -p /exa_data/ecolink
./cpe_agent --config spool.yaml --router-id lab-1 &

tail -f /exa_data/ecolink/cpe_perf.ndjson
wc -l /exa_data/ecolink/cpe_perf.ndjson
```

When the in-memory spool is full, older lines can drop (`SPOOL_DROP` events internally). Keep `max_lines` modest on small CPEs (128–256 typical).

### 5c. `https` (optional mTLS)

Only works if the binary was built with **mbedTLS** (`-DCPE_AGENT_WITH_MBEDTLS=ON`). Field static Bootlin builds often ship **without** it; then `https` fails and you should use stdout/spool + Vector.

```yaml
emit:
  mode: https
# under config (schema as in example):
# egress:
#   url: https://ingest.example/cpe/v1/events
#   ca_file: /etc/cpe_agent/ca.crt
#   cert_file: /etc/cpe_agent/client.crt
#   key_file: /etc/cpe_agent/client.key
```

Production path recommended by the design: **stdout/spool → Vector → ClickHouse**, not a CH client on the CPE.

---

## 6. Continuous timer loop

Without `--once`, the agent:

1. Loads config
2. Sleeps `interval_ms` (poll loop on field builds; libuv timer on full host builds)
3. Runs one sample tick (demo or live)
4. Flushes emit (stdout / spool / https)
5. Handles SIGHUP / SIGTERM

```yaml
demo:
  enabled: false
  target: "8.8.8.8"
  interval_ms: 60000    # once per minute
  timeout_ms: 1000
```

```bash
./cpe_agent --config /etc/cpe_agent/cpe_agent.yaml --router-id "$(hostname)"
```

---

## 7. SIGHUP config reload

Change target/interval/emit in YAML, then:

```bash
# if started as:
#   ./cpe_agent --config /etc/cpe_agent/cpe_agent.yaml --router-id cpe-42
kill -HUP $(pidof cpe_agent)

# OpenWrt package:
service cpe_agent reload
# or: /etc/init.d/cpe_agent reload
```

- Re-reads the **same** `--config` path
- **Keeps** CLI `--router-id` override
- Re-arms the sample interval if it changed

Example workflow:

```bash
# Start probing the LAN gateway
# edit demo.target to 1.1.1.1 in the YAML
kill -HUP $(pidof cpe_agent)
# next samples use the new target without process restart
```

---

## 8. OpenWrt service (packaged layout)

If installed as the `cpe-agent` package:

```bash
# config
vi /etc/cpe_agent/cpe_agent.yaml

# start / stop / reload
/etc/init.d/cpe_agent start
/etc/init.d/cpe_agent reload   # SIGHUP
logread -e cpe_agent           # if stdout→journal/logd
```

Init roughly runs:

```text
/usr/sbin/cpe_agent --config /etc/cpe_agent/cpe_agent.yaml --router-id <hostname>
```

with `CAP_NET_RAW` for live ICMP when needed.

---

## 9. Reading `cpe_perf` fields

```json
{
  "type": "cpe_perf",
  "ts": "2026-07-22T01:23:53.836Z",
  "router_id": "lab-1",
  "probe": "ping",
  "target": "1.1.1.1",
  "rtt_ms": 5.0,
  "loss": 0.0,
  "meta": { "replies": 1, "timeouts": 0, "demo": true }
}
```

| Field | Meaning |
|-------|---------|
| `type` | Always `cpe_perf` for this agent |
| `router_id` | Device/site id for correlation |
| `probe` | Probe kind (`ping`) |
| `target` | ICMP destination |
| `rtt_ms` | Round-trip ms (demo often ~5.0) |
| `loss` | 0.0–1.0 style loss fraction |
| `meta.demo` | `true` = synthetic; `false` = live |

Quick filters:

```bash
grep cpe_perf /exa_data/ecolink/cpe_perf.ndjson | tail -5
grep '"demo":false' file.ndjson | awk -F'"rtt_ms":' '{print $2}' | cut -d, -f1
```

---

## 10. End-to-end “use the features” cookbook

```bash
# A) Smoke (demo + once + router-id)
./cpe_agent --demo --once --router-id lab-1

# B) Live to gateway on stdout
cat >/exa_data/ecolink/live.yaml <<'EOF'
router_id: lab-1
emit: { mode: stdout }
demo:
  enabled: false
  target: "192.168.1.1"
  interval_ms: 2000
  timeout_ms: 1000
EOF
./cpe_agent --config /exa_data/ecolink/live.yaml --router-id lab-1

# C) Background spool capture
cat >/exa_data/ecolink/spool.yaml <<'EOF'
router_id: lab-1
emit:
  mode: spool
  path: /exa_data/ecolink/cpe_perf.ndjson
spool: { max_lines: 256 }
demo:
  enabled: false
  target: "1.1.1.1"
  interval_ms: 5000
  timeout_ms: 1000
EOF
./cpe_agent --config /exa_data/ecolink/spool.yaml --router-id lab-1 &
tail -f /exa_data/ecolink/cpe_perf.ndjson

# D) Change target without restart
# edit spool.yaml demo.target, then:
kill -HUP $(pidof cpe_agent)

# E) Stop cleanly
kill -TERM $(pidof cpe_agent)
```

---

## 11. What it does *not* expose (yet)

These are **not** CLI/features of the current binary:

- Multi-target list in one process
- Traceroute / TCP probes / port scan
- Direct ClickHouse client
- `--target` without a YAML file

Live multi-target work is done with **multiple YAMLs**, **HUP reloads**, or a small shell loop (as above).

---

## 12. Quick decision guide

| You want… | Use |
|-----------|-----|
| Prove the binary works | `--demo --once --router-id …` |
| Real latency to one host | YAML `demo.enabled: false` + target |
| Capture over time on-box | `emit.mode: spool` + path |
| Stream to log/Vector | `emit.mode: stdout` |
| Change probe without restart | Edit YAML + `SIGHUP` / `service … reload` |
| Stable device id | `--router-id` (survives HUP) |

---

## Related files

- Example config: `config/cpe_agent.example.yaml`
- OpenWrt defaults: `openwrt/cpe-agent/files/cpe_agent.yaml`
- OpenWrt init: `openwrt/cpe-agent/files/cpe_agent.init`
- ADR (live ICMP / spool / https): `docs/decisions/008-field-live-icmp-mtls-spool.md`
- ADR (HUP reload): `docs/decisions/007-field-spool-hup-reload.md`
