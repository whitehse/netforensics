/**
 * @file cpe_agent.h
 * @brief CPE edge agent core (Track 2 / program design).
 *
 * Class-B host: libuv loop in agent binary; syscall-light core here.
 * Performance samples are NDJSON (`type=cpe_perf`) → Vector → ClickHouse
 * (N-A05 / ADR-005). No production ClickHouse client on device.
 */
#ifndef CPE_AGENT_H
#define CPE_AGENT_H

#include "cpe_agent_config.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CPE_PERF_PROBE_MAX   32
#define CPE_PERF_TARGET_MAX  64
#define CPE_PERF_TS_MAX      40
#define CPE_PERF_META_MAX    128
#define CPE_NDJSON_LINE_MAX  512
#define CPE_SPOOL_DEFAULT    256

typedef enum {
    CPE_AGENT_EVENT_NONE = 0,
    CPE_AGENT_EVENT_CONFIG_APPLIED,
    CPE_AGENT_EVENT_CONFIG_REJECTED,
    CPE_AGENT_EVENT_NEED_ALLOC,
    CPE_AGENT_EVENT_SAMPLE_READY,
    CPE_AGENT_EVENT_SPOOL_DROP
} cpe_agent_event_type_t;

typedef struct {
    cpe_agent_event_type_t type;
    char                   reason[128];
    size_t                 need_bytes; /* for NEED_ALLOC */
    uint32_t               slot;       /* buffer slot when applicable */
} cpe_agent_event_t;

/** Last performance sample held in-memory (harness / demo). */
typedef struct {
    char   probe[CPE_PERF_PROBE_MAX];
    char   target[CPE_PERF_TARGET_MAX];
    double rtt_ms;
    float  loss;
    char   ts_iso[CPE_PERF_TS_MAX];
    char   meta[CPE_PERF_META_MAX]; /* small JSON object string or empty */
} cpe_perf_sample_t;

/** Max stations retained in one Wi‑Fi snapshot. */
#define CPE_WIFI_STA_MAX   32
#define CPE_WIFI_IF_MAX    32
#define CPE_WIFI_MAC_MAX   18
#define CPE_WIFI_IFNAME_MAX 32

/** One associated client from nl80211 station dump. */
typedef struct {
    char     mac[CPE_WIFI_MAC_MAX];
    int32_t  signal_dbm;
    int32_t  signal_avg_dbm;
    int8_t   snr_db;
    uint8_t  mcs; /* 0xFF if unknown */
    uint32_t tx_retries;
    uint32_t tx_failed;
    uint32_t rx_bytes;
    uint32_t tx_bytes;
    uint32_t freq_mhz;
    int      has_signal;
    int      has_mcs;
} cpe_wifi_station_t;

/** Interface / radio link state (sysfs + ioctl; no nl80211 required). */
typedef struct {
    char     ifname[CPE_WIFI_IFNAME_MAX];
    int      ifindex;
    int      up;           /**< IFF_UP */
    int      running;      /**< IFF_RUNNING */
    int      wireless;     /**< 1 if appears to be a Wi‑Fi iface */
    char     operstate[16];/**< kernel operstate: up/down/dormant/… */
    char     mac[CPE_WIFI_MAC_MAX];
    uint32_t mtu;
} cpe_wifi_iface_state_t;

/**
 * Point-in-time Wi‑Fi view: iface state + station table.
 * @p stations_valid is 0 if nl80211 dump failed (iface state may still be ok).
 */
typedef struct {
    cpe_wifi_iface_state_t iface;
    cpe_wifi_station_t     stations[CPE_WIFI_STA_MAX];
    size_t                 station_count;
    int                    stations_valid;
    int                    demo;
    char                   ts_iso[CPE_PERF_TS_MAX];
    char                   err[96]; /**< set when dump partially fails */
} cpe_wifi_snapshot_t;

typedef struct cpe_agent cpe_agent_t;

cpe_agent_t *cpe_agent_create(void);
void         cpe_agent_destroy(cpe_agent_t *a);

int  cpe_agent_apply_config(cpe_agent_t *a, const cpe_agent_config_t *cfg);
const cpe_agent_config_t *cpe_agent_config(const cpe_agent_t *a);

/**
 * Pull next event (0 = none, 1 = event, -1 = error).
 * Host drains after apply_config / sample / spool ops.
 */
int cpe_agent_next_event(cpe_agent_t *a, cpe_agent_event_t *ev);

const char *cpe_agent_event_type_name(cpe_agent_event_type_t t);

/**
 * Provide a host-allocated buffer for a prior NEED_ALLOC (P2.3).
 * @return 0 ok, -1 if no pending need or bad args.
 */
int cpe_agent_provide_buffer(cpe_agent_t *a, uint32_t slot, void *ptr,
                             size_t len);

/**
 * Demo / lab: feed synthetic ICMP echo into libnetdiag ping, update
 * in-memory stats + last sample, format NDJSON into spool.
 * No CAP_NET_ADMIN. @return 0 ok, -1 on failure.
 */
int cpe_agent_demo_ping_tick(cpe_agent_t *a);

/**
 * Field path (F4): host-owned ICMP echo to config probe target, measure RTT,
 * emit cpe_perf. Uses SOCK_DGRAM IPPROTO_ICMP when available, else SOCK_RAW
 * (CAP_NET_RAW). @return 0 ok (sample enqueued, even on timeout), -1 hard fail.
 */
int cpe_agent_live_ping_tick(cpe_agent_t *a);

/**
 * Live ARP request for an IPv4 target on a local interface.
 * Emits cpe_perf with probe="arping"; meta includes mac + if when answered.
 * @p ipv4_opt NULL → config demo_target; @p ifname_opt NULL → config arping_if
 * or auto-detect (default route / br-lan / eth0).
 * Needs AF_PACKET (CAP_NET_RAW). @return 0 ok (sample enqueued), -1 hard fail.
 */
int cpe_agent_arping(cpe_agent_t *a, const char *ipv4_opt,
                     const char *ifname_opt);

/** Live arping using config target + interface only. */
int cpe_agent_live_arping_tick(cpe_agent_t *a);

/**
 * Synthetic arping sample (no privileges). Optional @p ipv4_opt target label.
 */
int cpe_agent_demo_arping(cpe_agent_t *a, const char *ipv4_opt);
int cpe_agent_demo_arping_tick(cpe_agent_t *a);

/**
 * Read interface operstate / flags / MAC (no CAP_NET_ADMIN required typically).
 * @p ifname_opt NULL → config wifi_if, else first wireless iface, else "wlan0".
 * @return 0 ok, -1 if interface missing.
 */
int cpe_agent_wifi_iface_state(cpe_agent_t *a, const char *ifname_opt,
                               cpe_wifi_iface_state_t *out);

/**
 * Live: iface state + nl80211 station dump (needs nl80211; CAP_NET_ADMIN often).
 * Stores snapshot as last Wi‑Fi view; optionally emits cpe_wifi NDJSON to spool
 * when @p emit_ndjson is non-zero.
 * @return 0 ok (stations_valid may still be 0), -1 hard fail (no iface).
 */
int cpe_agent_wifi_dump(cpe_agent_t *a, const char *ifname_opt, int emit_ndjson,
                        cpe_wifi_snapshot_t *out_opt);

/** Synthetic stations (no privileges); stores last Wi‑Fi snapshot. */
int cpe_agent_demo_wifi_dump(cpe_agent_t *a, int emit_ndjson,
                             cpe_wifi_snapshot_t *out_opt);

/** Copy last Wi‑Fi snapshot; @return 0 ok, -1 if none yet. */
int cpe_agent_last_wifi(const cpe_agent_t *a, cpe_wifi_snapshot_t *out);

/**
 * List wireless-looking interfaces into @p names (each CPE_WIFI_IFNAME_MAX).
 * @return count written (0..max_names), or -1.
 */
int cpe_agent_wifi_list_ifaces(char names[][CPE_WIFI_IFNAME_MAX],
                               size_t max_names);

/** Max hops retained for one traceroute / mtr run. */
#define CPE_TRACE_HOP_MAX 32

/** Aggregated stats for one hop (TTL). */
typedef struct {
    int      hop; /**< 1-based TTL */
    char     addr[CPE_PERF_TARGET_MAX];
    uint32_t sent;
    uint32_t replies;
    uint32_t timeouts;
    double   last_rtt_ms;
    double   avg_rtt_ms;
    double   min_rtt_ms;
    double   max_rtt_ms;
    float    loss; /**< 0.0 .. 1.0 */
    int      reached_dest;
} cpe_trace_hop_t;

/** Full path discovery result (live traceroute / mtr). */
typedef struct {
    char            target[CPE_PERF_TARGET_MAX];
    char            ts_iso[CPE_PERF_TS_MAX];
    char            method[16]; /**< "udp" | "icmp" | "demo" */
    int             max_ttl;
    int             probes_per_hop;
    int             hop_count;
    int             reached;
    double          dest_rtt_ms;
    cpe_trace_hop_t hops[CPE_TRACE_HOP_MAX];
} cpe_trace_result_t;

/**
 * Live traceroute (one probe per hop, stop when destination answers).
 * UDP + IP_RECVERR preferred; ICMP echo + TTL as fallback.
 * @p target_opt NULL → config target; @p max_ttl 0 → 30;
 * @p timeout_ms 0 → config probe_timeout_ms.
 * Stores last_trace, emits summary cpe_perf probe=traceroute.
 * @return 0 ok (result filled even if incomplete), -1 hard fail (socket/target).
 */
int cpe_agent_traceroute(cpe_agent_t *a, const char *target_opt, int max_ttl,
                         uint32_t timeout_ms, cpe_trace_result_t *out_opt);

/**
 * Live mtr-style multi-probe path stats (probes_per_hop at each TTL).
 * @p probes_per_hop 0 → 3. Same storage / emit (probe=mtr).
 */
int cpe_agent_mtr(cpe_agent_t *a, const char *target_opt, int max_ttl,
                  int probes_per_hop, uint32_t timeout_ms,
                  cpe_trace_result_t *out_opt);

/**
 * Synthetic hop table (no network). C tests / fuzz only — not on Lua.
 */
int cpe_agent_demo_traceroute(cpe_agent_t *a, const char *target_opt,
                              int max_ttl, cpe_trace_result_t *out_opt);

/** Copy last traceroute/mtr result; @return 0 ok, -1 if none yet. */
int cpe_agent_last_trace(const cpe_agent_t *a, cpe_trace_result_t *out);

/** Install last traceroute result (host probes / tests). */
int cpe_agent_set_last_trace(cpe_agent_t *a, const cpe_trace_result_t *r);

/**
 * One sample tick: demo or live based on config.demo_mode.
 * @return 0 ok, -1 on failure.
 */
int cpe_agent_sample_tick(cpe_agent_t *a);

/** Install last sample (host probes / tests). */
int cpe_agent_set_last_sample(cpe_agent_t *a, const cpe_perf_sample_t *s);

/**
 * Feed bare ICMP echo-reply bytes into libnetdiag ping (optional stats).
 * @return 0 ok, -1 on error.
 */
int cpe_agent_feed_icmp_echo_reply(cpe_agent_t *a, const uint8_t *icmp,
                                   size_t len, uint64_t ts_ms);

/** Copy last sample (for libharness get_local_latency). */
int cpe_agent_last_sample(const cpe_agent_t *a, cpe_perf_sample_t *out);

/**
 * Local tool result JSON for get_local_latency (P2.6).
 * When no sample yet: {"available":false}.
 * Otherwise includes rtt_ms, loss, probe, target, ts, router_id.
 * @return bytes written (excl NUL), or -1.
 */
int cpe_agent_get_local_latency_json(const cpe_agent_t *a, char *buf,
                                     size_t buflen);

/** Format one cpe_perf NDJSON line (no trailing newline required in out). */
int cpe_perf_format_ndjson(const char *router_id, const cpe_perf_sample_t *s,
                           char *buf, size_t buflen);

/**
 * Feed conntrack bytes into in-agent nfct parser (P2.8).
 * Reuses libnetdiag nfct + netforensics obs format; puts cpe_nat lines on spool.
 * @return number of NDJSON lines enqueued, or -1 on error.
 */
int cpe_agent_feed_nfct(cpe_agent_t *a, const uint8_t *data, size_t len,
                        uint64_t ts_ms);

/** Count of successful nfct observations since create. */
uint64_t cpe_agent_nfct_obs_count(const cpe_agent_t *a);

/** Spool: push a complete NDJSON line (without requiring trailing \\n). */
int    cpe_agent_spool_push_line(cpe_agent_t *a, const char *line);
size_t cpe_agent_spool_depth(const cpe_agent_t *a);
size_t cpe_agent_spool_drops(const cpe_agent_t *a);

/**
 * Flush spool to FILE* (stdout or open spool file). Each line ends with \\n.
 * @return lines written, or -1 on I/O error.
 */
int cpe_agent_spool_flush(cpe_agent_t *a, FILE *fp);

/**
 * Flush spool according to config emit.mode:
 *   - "stdout" → stdout
 *   - "spool"  → append open of emit.path / spool.path
 * @return lines written, or -1 on I/O error.
 */
int cpe_agent_emit_flush(cpe_agent_t *a);

/**
 * Host options for the libuv loop (field OpenWrt path).
 * All pointers may be NULL; strings are not retained beyond the call
 * (HUP reload re-reads @p config_path from disk each time).
 */
typedef struct {
    unsigned    max_ticks;          /**< 0 = run until signal */
    const char *config_path;        /**< YAML path for SIGHUP shadow reload */
    const char *router_id_override; /**< re-applied after each HUP load */
} cpe_agent_run_opts_t;

/**
 * libuv host entry (P2.2 + field HUP/spool). Blocks until stop or max_ticks.
 * @p opts may be NULL (equivalent to {0, NULL, NULL}).
 * @return 0 ok, non-zero on fatal setup error.
 */
int cpe_agent_run_uv(cpe_agent_t *a, const cpe_agent_run_opts_t *opts);

/** SIGHUP flag helpers (host). */
void cpe_agent_hup_install(void);
int  cpe_agent_hup_take(void); /* 1 if HUP seen since last take */

/**
 * Load YAML from @p path (optional), apply router override (optional),
 * call apply_config. Used by main and SIGHUP shadow reload.
 * @return 0 ok, -1 on load/validate/apply failure (events may be queued).
 */
int cpe_agent_reload_config(cpe_agent_t *a, const char *config_path,
                            const char *router_id_override, char *err,
                            size_t err_len);

#ifdef __cplusplus
}
#endif

#endif /* CPE_AGENT_H */
