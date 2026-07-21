# historical_rib_trie dictionary (MODULE 3)

## Status

DDL skeleton: `002_dictionary.sql`. **Not validated** against a specific
ClickHouse version in CI (no CH in unit tests).

## Validation checklist (lab)

| Step | Action |
|------|--------|
| 1 | Apply `001_schema.sql`, load sample `bgp_updates` with sign=+1 |
| 2 | Create a view that expands prefixes for IP_TRIE if needed |
| 3 | `CREATE DICTIONARY` from `002_dictionary.sql` |
| 4 | `SELECT dictGet('forensics.historical_rib_trie', 'next_hop', tuple(IPv4StringToNum('…')))` |
| 5 | Note ClickHouse version (`SELECT version()`) in ops notes |

## Known constraints

- `LAYOUT(IP_TRIE)` requires ClickHouse with IP_TRIE support (20.x+).
- Source table must reflect **latest** advertised state (collapsing / view).
- Lifetime MIN/MAX 30–120s trades freshness vs load.

## When green

Mark TODO “historical_rib_trie dictionary validated on CH version N” with the
lab version string (e.g. 24.8).
