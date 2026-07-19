# Deployment notes

## forensicsd (CPE)

- Unit: `forensicsd.service` (CAP_NET_ADMIN only via AmbientCapabilities)
- Sysctl: `cpe/sysctl/99-forensics.conf` (`nf_conntrack_events=1`)
- Output: NDJSON on stdout (`cpe_nat`, `cpe_wifi`) for Vector or journald

```bash
# Demo (no privileges)
./build/forensicsd --demo --router-id cpe-lab-1

# Live (needs CAP_NET_ADMIN)
./build/forensicsd --netlink --router-id cpe-lab-1
```

## cpe_agent (Track 2)

Product CPE agent (libuv). Co-exists with forensicsd; does **not** replace it.

```bash
# One synthetic perf sample (no privileges)
./build/cpe_agent --once --router-id cpe-lab-1

# Timer loop + YAML
./build/cpe_agent --config config/cpe_agent.example.yaml
```

- Output: NDJSON `type=cpe_perf` on stdout (or spool when configured)
- Schema: `sql/003_cpe_perf_samples.sql` → `forensics.cpe_perf_samples`
- Vector: `vector/vector.yaml` route `perf` → ClickHouse table above
- OpenWrt package for agent: P2.9 (not yet)

## Vector fan-in

See `vector/vector.yaml`. For ~20k CPE:

- Prefer disk buffers on the HTTP/UDP source
- Batch ClickHouse inserts (`batch.max_bytes`, `batch.timeout_secs`)
- Keep CPE mTLS auth in front of the gateway when leaving lab mode
- Routes: `cpe_nat`, `cpe_wifi`, **`cpe_perf`**, BMP/BGP

## ClickHouse

Apply `sql/001_schema.sql`, `sql/002_dictionary.sql`, and
`sql/003_cpe_perf_samples.sql`. Host pipeline tests emit fixture INSERT shapes
without requiring a live CH instance.
