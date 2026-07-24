-- MODULE 3: TTL / retention policies for forensics tables.
-- Apply after 001_schema.sql and 003_cpe_perf_samples.sql.
-- Adjust intervals per site compliance / disk budget.

-- Core IPFIX: 90 days hot
ALTER TABLE forensics.ipfix_flows
    MODIFY TTL timestamp + INTERVAL 90 DAY DELETE;

-- CPE NAT: 60 days (higher volume from 20k CPE)
ALTER TABLE forensics.cpe_nat_flows_ingest
    MODIFY TTL timestamp + INTERVAL 60 DAY DELETE;
ALTER TABLE forensics.cpe_nat_flows
    MODIFY TTL timestamp + INTERVAL 60 DAY DELETE;

-- Wi-Fi metrics: 45 days
ALTER TABLE forensics.cpe_wifi_metrics
    MODIFY TTL timestamp + INTERVAL 45 DAY DELETE;

-- Perf samples: 180 days (product SLA / member history)
ALTER TABLE forensics.cpe_perf_samples
    MODIFY TTL ts + INTERVAL 180 DAY DELETE;

-- TCP NFLOG control-plane stats: 90 days (higher volume than ping samples)
ALTER TABLE forensics.cpe_tcp_stats
    MODIFY TTL ts + INTERVAL 90 DAY DELETE;

-- BGP updates: 365 days for historical RIB dictionary source
ALTER TABLE forensics.bgp_updates
    MODIFY TTL timestamp + INTERVAL 365 DAY DELETE;
