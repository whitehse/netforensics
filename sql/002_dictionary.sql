-- Historical RIB as IP_TRIE dictionary (MODULE 3)
-- Source table must be populated/collapsed before reliable LPM.

CREATE DICTIONARY IF NOT EXISTS forensics.historical_rib_trie
(
    prefix      String,
    router_id   String,
    next_hop    IPv4,
    as_path     Array(UInt32),
    timestamp   DateTime64(3, 'UTC')
)
PRIMARY KEY prefix
SOURCE(CLICKHOUSE(
    DB 'forensics'
    TABLE 'bgp_updates'
    -- Production: use a view that expands prefixes and latest sign=+1 rows
))
LIFETIME(MIN 30 MAX 120)
LAYOUT(IP_TRIE);
