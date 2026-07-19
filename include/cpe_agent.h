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
 * libuv host entry (P2.2). Blocks until stop signal or max_ticks.
 * @p max_ticks 0 = run until signal; >0 = emit that many demo samples then exit.
 * @return 0 ok, non-zero on fatal setup error.
 */
int cpe_agent_run_uv(cpe_agent_t *a, unsigned max_ticks);

/** SIGHUP flag helpers (host). */
void cpe_agent_hup_install(void);
int  cpe_agent_hup_take(void); /* 1 if HUP seen since last take */

#ifdef __cplusplus
}
#endif

#endif /* CPE_AGENT_H */
