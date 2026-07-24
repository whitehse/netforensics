/**
 * @file cpe_tcp_stats.h
 * @brief TCP control-plane stats from NFLOG (SYN/FIN/RST) for cpe_agent.
 *
 * Aggregates per-remote-IP and per-prefix counters for loss hints and
 * partial bandwidth estimation from logged packet sizes. Full stream
 * bandwidth needs additional rules or conntrack accounting; this layer
 * is designed so QUIC analysis can share the same query surfaces later.
 */
#ifndef CPE_TCP_STATS_H
#define CPE_TCP_STATS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CPE_TCP_IP_MAX         48
#define CPE_TCP_PREFIX_STR_MAX 64
#define CPE_TCP_REMOTE_MAX     256
#define CPE_TCP_PREFIX_MAX     128
#define CPE_TCP_NDJSON_MAX     640

/** TCP flag / event class bits (from captured headers). */
typedef enum {
    CPE_TCP_FLAG_FIN = 0x01,
    CPE_TCP_FLAG_SYN = 0x02,
    CPE_TCP_FLAG_RST = 0x04,
    CPE_TCP_FLAG_PSH = 0x08,
    CPE_TCP_FLAG_ACK = 0x10,
    CPE_TCP_FLAG_URG = 0x20
} cpe_tcp_flag_t;

/** One remote endpoint aggregation (WAN-side peer preferred). */
typedef struct {
    char     remote_ip[CPE_TCP_IP_MAX];
    char     local_ip[CPE_TCP_IP_MAX];
    uint16_t remote_port; /**< last seen remote port (0 if mixed) */
    uint16_t local_port;
    uint32_t syn_count;
    uint32_t fin_count;
    uint32_t rst_count;
    uint32_t pkt_count;
    uint32_t syn_retrans; /**< extra SYNs after first per (remote,lport,rport) window */
    uint64_t bytes_est;   /**< sum of IP total length from logged packets */
    uint64_t last_seen_ms;
} cpe_tcp_remote_t;

/** Network prefix rollup (e.g. Netflix CDN /24 or /16). */
typedef struct {
    char     prefix[CPE_TCP_PREFIX_STR_MAX];
    uint32_t remote_count;
    uint32_t syn_count;
    uint32_t fin_count;
    uint32_t rst_count;
    uint32_t pkt_count;
    uint32_t syn_retrans;
    uint64_t bytes_est;
} cpe_tcp_prefix_t;

/** Point-in-time global snapshot for Lua / emit / tests. */
typedef struct {
    uint32_t         nflog_group;
    uint32_t         syn_total;
    uint32_t         fin_total;
    uint32_t         rst_total;
    uint32_t         pkt_total;
    uint32_t         syn_retrans_total;
    uint64_t         bytes_total;
    uint64_t         pkts_parsed;
    uint64_t         pkts_non_tcp;
    uint64_t         pkts_parse_fail;
    uint32_t         remote_count;
    uint32_t         prefix_count;
    uint8_t          prefix_len; /**< aggregation mask length (IPv4) */
    char             ts_iso[40];
    cpe_tcp_remote_t remotes[CPE_TCP_REMOTE_MAX];
    cpe_tcp_prefix_t prefixes[CPE_TCP_PREFIX_MAX];
} cpe_tcp_snapshot_t;

/**
 * Parsed single TCP packet (from IP payload in NFLOG).
 * Addresses are human-readable; @p is_ipv6 set for IPv6.
 */
typedef struct {
    char     src_ip[CPE_TCP_IP_MAX];
    char     dst_ip[CPE_TCP_IP_MAX];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  flags;
    uint8_t  is_ipv6;
    uint16_t ip_len; /**< total IP length (or payload+hdr estimate) */
    uint32_t seq;
} cpe_tcp_packet_t;

/**
 * Parse IPv4/IPv6 + TCP headers from a raw L3 buffer (NFLOG payload).
 * @return 0 ok, -1 not TCP / truncated / unsupported.
 */
int cpe_tcp_parse_ip_packet(const uint8_t *pkt, size_t len,
                            cpe_tcp_packet_t *out);

/**
 * Format one cpe_tcp NDJSON line.
 * @p scope: "summary" | "remote" | "prefix"
 * @p detail: remote or prefix row (NULL for summary; uses snap totals).
 * @return bytes written excl NUL, or -1.
 */
int cpe_tcp_format_ndjson(const char *router_id, const char *scope,
                          const cpe_tcp_snapshot_t *snap,
                          const cpe_tcp_remote_t *remote,
                          const cpe_tcp_prefix_t *prefix, char *buf,
                          size_t buflen);

/**
 * Loss heuristic in [0,1]: RST share of control events, with SYN retrans
 * boost. Not true loss%; a stable signal for ranking bad remotes.
 */
float cpe_tcp_loss_hint(uint32_t syn, uint32_t fin, uint32_t rst,
                        uint32_t syn_retrans);

/**
 * Runtime state owned by cpe_agent (agent_core allocates one per agent).
 * Opaque to most call sites; tcp_stats.c fills it.
 */
typedef struct cpe_tcp_state {
    int                fd; /* NFLOG netlink fd, or -1 */
    uint16_t           group;
    uint32_t           copy_range;
    int                enabled;
    int                open_ok;
    char               open_err[96];
    uint8_t            prefix_len;
    uint32_t           emit_interval_ms;
    uint32_t           emit_top_n;
    uint64_t           last_emit_ms;
    cpe_tcp_snapshot_t snap;
    struct {
        uint32_t sip;
        uint32_t dip;
        uint16_t sport;
        uint16_t dport;
        uint32_t seq;
        uint8_t  used;
    } flows[64];
    size_t flow_i;
} cpe_tcp_state_t;

void cpe_tcp_state_init(cpe_tcp_state_t *st);

#ifdef __cplusplus
}
#endif

#endif /* CPE_TCP_STATS_H */
