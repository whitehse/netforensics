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

## Vector fan-in

See `vector/vector.yaml`. For ~20k CPE:

- Prefer disk buffers on the HTTP/UDP source
- Batch ClickHouse inserts (`batch.max_bytes`, `batch.timeout_secs`)
- Keep CPE mTLS auth in front of the gateway when leaving lab mode

## ClickHouse

Apply `sql/001_schema.sql` and `sql/002_dictionary.sql`. Host pipeline tests
emit fixture INSERT shapes without requiring a live CH instance.
