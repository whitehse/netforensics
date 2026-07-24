/**
 * @file cpe_flow_acct.h
 * @brief Per-flow bandwidth accounting from conntrack (bytes up/down).
 *
 * Requires nf_conntrack_acct=1 so DESTROY/UPDATE carry CTA_COUNTERS_*.
 * Polls multicast events and optionally dumps the table every ~200 ms.
 */
#ifndef CPE_FLOW_ACCT_H
#define CPE_FLOW_ACCT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CPE_FLOW_IP_MAX     48
#define CPE_FLOW_ID_MAX     20
#define CPE_FLOW_STATE_MAX  24
#define CPE_FLOW_MAX        1024
#define CPE_FLOW_NDJSON_MAX 700

/** One live or recently destroyed flow. */
typedef struct {
    char     flow_id[CPE_FLOW_ID_MAX];
    uint32_t ct_id;
    int      has_ct_id;
    uint8_t  proto;
    uint8_t  ip_version; /* 4 or 6 */
    char     lan_ip[CPE_FLOW_IP_MAX];
    uint16_t lan_port;
    char     wan_ip[CPE_FLOW_IP_MAX];
    uint16_t wan_port;
    char     remote_ip[CPE_FLOW_IP_MAX];
    uint16_t remote_port;
    uint64_t orig_pkts;
    uint64_t orig_bytes;
    uint64_t reply_pkts;
    uint64_t reply_bytes;
    /* Oriented (CPE WAN view): up = orig, down = reply */
    uint64_t bytes_up;
    uint64_t bytes_down;
    uint64_t bytes_up_delta;
    uint64_t bytes_down_delta;
    double   rate_up_bps;
    double   rate_down_bps;
    uint64_t first_seen_ms;
    uint64_t last_seen_ms;
    char     state[CPE_FLOW_STATE_MAX]; /* ESTABLISHED | NEW | DESTROY … */
    int      alive;                     /* 0 after destroy emit */
    int      used;
} cpe_flow_entry_t;

/** Snapshot for ctl / tests. */
typedef struct {
    uint32_t         flow_count;
    uint64_t         events_in;
    uint64_t         destroys_emitted;
    uint64_t         samples_emitted;
    uint64_t         dumps;
    int              open_ok;
    char             open_err[96];
    char             ts_iso[40];
    cpe_flow_entry_t flows[CPE_FLOW_MAX];
} cpe_flow_snapshot_t;

/** Runtime state owned by cpe_agent. */
typedef struct cpe_flow_state {
    int      fd; /* event netlink */
    int      dump_fd;
    int      enabled;
    int      open_ok;
    int      join_update;
    int      emit_destroy;
    int      emit_new;
    int      emit_nat; /* also push legacy cpe_nat lines */
    uint32_t poll_interval_ms;
    uint32_t dump_interval_ms;
    uint32_t sample_emit_ms;
    uint32_t sample_top_n;
    uint32_t max_flows;
    uint64_t last_dump_ms;
    uint64_t last_sample_ms;
    uint64_t last_tick_ms;
    uint64_t events_in;
    uint64_t destroys_emitted;
    uint64_t samples_emitted;
    uint64_t dumps;
    int      warned_no_acct;
    char     open_err[96];
    cpe_flow_entry_t table[CPE_FLOW_MAX];
    uint32_t         table_used;
} cpe_flow_state_t;

void cpe_flow_state_init(cpe_flow_state_t *st);

/**
 * Format one cpe_flow NDJSON line.
 * @p event: "sample" | "destroy" | "new"
 * @return bytes written excl NUL, or -1.
 */
int cpe_flow_format_ndjson(const char *router_id, const char *event,
                           const cpe_flow_entry_t *e, char *buf, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif /* CPE_FLOW_ACCT_H */
