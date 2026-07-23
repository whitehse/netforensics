# CPE agent → edgehost → ClickHouse pipeline

End-to-end path for performance and forensics NDJSON from OpenWrt CPE agents
into ClickHouse, via **edgehost** as the fan-in proxy (or Vector as an
alternative).

```text
┌─────────────┐   HTTP(S) NDJSON + optional Basic Auth
│  cpe_agent  │ ──────────────────────────────────────────┐
│  (OpenWrt)  │   POST /api/v1/telemetry/events           │
└─────────────┘                                           ▼
                                                 ┌────────────────┐
                                                 │   edgehost     │
                                                 │ telemetry proxy│
                                                 └───────┬────────┘
                                                         │ JSONEachRow batch
                                                         │ (user/password to CH)
                                                         ▼
                                                 ┌────────────────┐
                                                 │  ClickHouse    │
                                                 │ edgehost.e7_*  │
                                                 │ (payload=CPE)  │
                                                 └────────────────┘

Alternative (lab / site Vector):
  cpe_agent emit.mode=spool|stdout → Vector → forensics.cpe_perf_samples
```

## Auth model

| Hop | Transport | Auth |
|-----|-----------|------|
| cpe_agent → edgehost | **HTTP** (lab) or **HTTPS** (optional mbedTLS) | Optional **Basic** username/password |
| edgehost → ClickHouse | HTTP (default) or HTTPS | ClickHouse `user` / `password` headers |

TLS is **optional** on both hops for lab. Production should enable HTTPS +
credentials.

## cpe_agent config

```yaml
router_id: cpe-42

emit:
  mode: http          # http | https | spool | stdout

egress:
  # edgehost telemetry proxy (preferred product path)
  url: "http://edgehost.example:18080/api/v1/telemetry/events"
  username: cpe_ingest
  password: "change-me"
  # TLS optional:
  # ca_file: /etc/cpe_agent/ca.crt
  # cert_file: /etc/cpe_agent/client.crt   # mTLS if required
  # key_file: /etc/cpe_agent/client.key
  # tls_insecure: false                    # default true when no ca_file

demo:
  enabled: false
  target: "1.1.1.1"
  interval_ms: 5000
```

```bash
./cpe_agent --config /etc/cpe_agent/cpe_agent.yaml --router-id cpe-42
```

`emit.mode=http` always uses plain TCP. `emit.mode=https` requires a build with
mbedTLS (`CPE_AGENT_WITH_MBEDTLS`). Both accept the same Basic Auth fields.

## edgehost config

```yaml
auth:
  mode: lab_password   # or open for pure lab

plugins:
  clickhouse:
    enabled: true
    host: 127.0.0.1
    port: 8123
    database: edgehost
    user: default
    password: ""                 # ClickHouse password (optional)
    use_https: false             # TLS to ClickHouse optional
    events_table: edgehost.e7_netconf_events
    telemetry_proxy: true
    telemetry_user: cpe_ingest   # Basic Auth for CPE devices
    telemetry_password: "change-me"
    flush_interval_ms: 1000
    flush_max_rows: 256
```

Apply schema:

```bash
clickhouse-client --multiquery < edgehost/sql/clickhouse/001_e7_netconf_events.sql
```

### How CPE rows land in ClickHouse

`POST /api/v1/telemetry/events` accepts NDJSON lines (`cpe_perf`, `cpe_nat`,
`cpe_wifi`, …). edgehost **wraps** each object into the E7 events table shape:

| CH column | Source |
|-----------|--------|
| `event_time` | `ts` from NDJSON (or now) |
| `shelf_id` | `router_id` |
| `event_type` | `type` (`cpe_perf`, …) |
| `ont_id` | `probe` when present |
| `source` | `cpe_agent` |
| `payload` | **original JSON object** |

Query examples:

```sql
SELECT event_time, shelf_id, event_type, payload
FROM edgehost.e7_netconf_events
WHERE source = 'cpe_agent' AND event_type = 'cpe_perf'
ORDER BY event_time DESC
LIMIT 50;

SELECT
  shelf_id,
  JSONExtractFloat(payload, 'rtt_ms') AS rtt_ms,
  JSONExtractString(payload, 'probe') AS probe
FROM edgehost.e7_netconf_events
WHERE event_type = 'cpe_perf'
  AND event_time > now() - INTERVAL 1 HOUR;
```

(If `payload` is the native JSON type, use `payload.rtt_ms` instead of
`JSONExtract*`.)

## Smoke test (lab, no TLS)

```bash
# 1) edgehost with clickhouse + telemetry Basic Auth
export EDGEHOST_LAB_PASSWORD=lab
export EDGEHOST_SESSION_HMAC=dev-hmac-not-for-prod
# start edgehost with plugins.clickhouse.enabled + telemetry_user/password

# 2) Manual POST
curl -sS -u cpe_ingest:change-me \
  -H 'Content-Type: application/x-ndjson' \
  -X POST http://127.0.0.1:18080/api/v1/telemetry/events \
  --data-binary $'{"type":"cpe_perf","ts":"2026-07-22T12:00:00.000Z","router_id":"lab-1","probe":"ping","target":"1.1.1.1","rtt_ms":12.3,"loss":0,"meta":{"demo":false}}\n'

# 3) cpe_agent once → edgehost
./cpe_agent --once --config agent-to-edgehost.yaml
```

## Vector alternative

Keep using `vector/vector.yaml` for site-local spool → `forensics.cpe_perf_samples`
when edgehost is not the fan-in tier. ADR-002 still applies: **no native
ClickHouse protocol on the CPE**.

## Related

- ADR-002 NDJSON → Vector/gateway
- ADR-004 CPE TLS = mbedTLS (optional)
- edgehost `docs/guides/clickhouse.md`
- netforensics `docs/guides/cpe-agent-features.md`
