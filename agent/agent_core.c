/**
 * @file agent_core.c
 * @brief CPE agent core: config apply, events, spool, demo ping (P2.1–P2.5).
 */

#include "cpe_agent.h"
#include "cpe_agent_tls.h"
#include "cpe_host_alloc.h"
#include "cpe_spool.h"

#include "netdiag.h"
#include "netforensics.h"
#include "nfct.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CPE_EVENT_Q     16
#define CPE_SPOOL_LINE  CPE_NDJSON_LINE_MAX
#define CPE_NEED_SLOTS  4

typedef struct {
    int    used;
    void  *ptr;
    size_t len;
    size_t need;
    int    waiting;
} cpe_buf_slot_t;

struct cpe_agent {
    cpe_agent_config_t cfg;
    cpe_agent_event_t  eq[CPE_EVENT_Q];
    size_t             eq_head;
    size_t             eq_tail;
    size_t             eq_cnt;

    cpe_perf_sample_t last;
    int               has_last;

    cpe_wifi_snapshot_t last_wifi;
    int                 has_last_wifi;

    char  (*spool)[CPE_SPOOL_LINE];
    size_t spool_cap;
    size_t spool_head;
    size_t spool_tail;
    size_t spool_cnt;
    size_t spool_drops;

    ping_ctx     *ping;
    nfct_ctx     *nfct; /* optional path reuse (P2.8) */
    uint64_t      nfct_obs;
    cpe_buf_slot_t slots[CPE_NEED_SLOTS];
};

const char *cpe_agent_event_type_name(cpe_agent_event_type_t t)
{
    switch (t) {
    case CPE_AGENT_EVENT_NONE:            return "NONE";
    case CPE_AGENT_EVENT_CONFIG_APPLIED:  return "CONFIG_APPLIED";
    case CPE_AGENT_EVENT_CONFIG_REJECTED: return "CONFIG_REJECTED";
    case CPE_AGENT_EVENT_NEED_ALLOC:      return "NEED_ALLOC";
    case CPE_AGENT_EVENT_SAMPLE_READY:    return "SAMPLE_READY";
    case CPE_AGENT_EVENT_SPOOL_DROP:      return "SPOOL_DROP";
    default:                              return "UNKNOWN";
    }
}

static int eq_push(cpe_agent_t *a, cpe_agent_event_type_t type,
                   const char *reason, size_t need_bytes, uint32_t slot)
{
    cpe_agent_event_t *e;

    if (!a || a->eq_cnt >= CPE_EVENT_Q) {
        return -1;
    }
    e = &a->eq[a->eq_tail];
    memset(e, 0, sizeof(*e));
    e->type = type;
    e->need_bytes = need_bytes;
    e->slot = slot;
    if (reason) {
        snprintf(e->reason, sizeof(e->reason), "%s", reason);
    }
    a->eq_tail = (a->eq_tail + 1) % CPE_EVENT_Q;
    a->eq_cnt++;
    return 0;
}

static void free_spool(cpe_agent_t *a)
{
    if (a->spool) {
        cpe_host_free(a->spool);
        a->spool = NULL;
    }
    a->spool_cap = 0;
    a->spool_head = a->spool_tail = a->spool_cnt = 0;
}

static int ensure_spool(cpe_agent_t *a, size_t cap)
{
    char (*nb)[CPE_SPOOL_LINE];

    if (cap == 0) {
        cap = CPE_CFG_SPOOL_DEFAULT;
    }
    if (a->spool && a->spool_cap == cap) {
        return 0;
    }
    free_spool(a);
    nb = (char (*)[CPE_SPOOL_LINE])cpe_host_alloc(cap * CPE_SPOOL_LINE);
    if (!nb) {
        /* Emit NEED_ALLOC so host can retry with host_alloc if desired. */
        (void)eq_push(a, CPE_AGENT_EVENT_NEED_ALLOC, "spool",
                      cap * CPE_SPOOL_LINE, 0);
        return -1;
    }
    a->spool = nb;
    a->spool_cap = cap;
    a->slots[0].used = 1;
    a->slots[0].ptr = nb;
    a->slots[0].len = cap * CPE_SPOOL_LINE;
    a->slots[0].waiting = 0;
    return 0;
}

cpe_agent_t *cpe_agent_create(void)
{
    cpe_agent_t *a = (cpe_agent_t *)calloc(1, sizeof(*a));
    if (!a) {
        return NULL;
    }
    cpe_agent_config_defaults(&a->cfg);
    a->ping = ping_create(NETDIAG_ROLE_REQUESTER);
    if (!a->ping) {
        free(a);
        return NULL;
    }
    a->nfct = nfct_create(NFCT_ROLE_COLLECTOR);
    if (!a->nfct) {
        ping_destroy(a->ping);
        free(a);
        return NULL;
    }
    if (ensure_spool(a, a->cfg.spool_max_lines) != 0) {
        nfct_destroy(a->nfct);
        ping_destroy(a->ping);
        free(a);
        return NULL;
    }
    return a;
}

void cpe_agent_destroy(cpe_agent_t *a)
{
    if (!a) {
        return;
    }
    free_spool(a);
    if (a->nfct) {
        nfct_destroy(a->nfct);
    }
    if (a->ping) {
        ping_destroy(a->ping);
    }
    free(a);
}

int cpe_agent_apply_config(cpe_agent_t *a, const cpe_agent_config_t *cfg)
{
    char err[128];
    cpe_agent_config_t shadow;

    if (!a || !cfg) {
        return -1;
    }
    shadow = *cfg;
    if (shadow.spool_max_lines == 0) {
        shadow.spool_max_lines = CPE_CFG_SPOOL_DEFAULT;
    }
    if (shadow.sample_interval_ms == 0) {
        shadow.sample_interval_ms = shadow.demo_interval_ms
                                        ? shadow.demo_interval_ms
                                        : 5000;
    }
    if (shadow.demo_interval_ms == 0) {
        shadow.demo_interval_ms = shadow.sample_interval_ms;
    }
    if (shadow.probe_timeout_ms == 0) {
        shadow.probe_timeout_ms = 1000;
    }
    if (cpe_agent_config_validate(&shadow, err, sizeof(err)) != 0) {
        (void)eq_push(a, CPE_AGENT_EVENT_CONFIG_REJECTED, err, 0, 0);
        return -1;
    }
    if (shadow.spool_max_lines != a->spool_cap) {
        if (ensure_spool(a, shadow.spool_max_lines) != 0) {
            (void)eq_push(a, CPE_AGENT_EVENT_CONFIG_REJECTED, "spool alloc", 0,
                          0);
            return -1;
        }
    }
    {
        uint64_t next_gen = a->cfg.generation + 1;

        a->cfg = shadow;
        a->cfg.generation = next_gen;
    }
    (void)eq_push(a, CPE_AGENT_EVENT_CONFIG_APPLIED, "ok", 0, 0);
    return 0;
}

const cpe_agent_config_t *cpe_agent_config(const cpe_agent_t *a)
{
    return a ? &a->cfg : NULL;
}

int cpe_agent_next_event(cpe_agent_t *a, cpe_agent_event_t *ev)
{
    if (!a || !ev) {
        return -1;
    }
    if (a->eq_cnt == 0) {
        return 0;
    }
    *ev = a->eq[a->eq_head];
    a->eq_head = (a->eq_head + 1) % CPE_EVENT_Q;
    a->eq_cnt--;
    return 1;
}

int cpe_agent_provide_buffer(cpe_agent_t *a, uint32_t slot, void *ptr,
                             size_t len)
{
    if (!a || slot >= CPE_NEED_SLOTS || !ptr || len == 0) {
        return -1;
    }
    if (!a->slots[slot].waiting) {
        return -1;
    }
    a->slots[slot].ptr = ptr;
    a->slots[slot].len = len;
    a->slots[slot].used = 1;
    a->slots[slot].waiting = 0;
    if (slot == 0) {
        a->spool = (char (*)[CPE_SPOOL_LINE])ptr;
        a->spool_cap = len / CPE_SPOOL_LINE;
        if (a->spool_cap == 0) {
            return -1;
        }
    }
    return 0;
}

static void iso_now(char *out, size_t n)
{
    struct timespec ts;
    struct tm tm;
    time_t sec;
    int ms;

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        snprintf(out, n, "1970-01-01T00:00:00.000Z");
        return;
    }
    sec = ts.tv_sec;
    ms = (int)(ts.tv_nsec / 1000000);
    if (!gmtime_r(&sec, &tm)) {
        snprintf(out, n, "1970-01-01T00:00:00.000Z");
        return;
    }
    {
        int y = tm.tm_year + 1900;
        if (y < 0) {
            y = 0;
        }
        if (y > 9999) {
            y = 9999;
        }
        snprintf(out, n, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", y, tm.tm_mon + 1,
                 tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, ms);
    }
}

/**
 * Build a minimal ICMP echo reply buffer for ping_feed_input_with_ts.
 * Layout expected by libnetdiag ping: type at [0], seq at [6..7].
 */
static void synth_icmp_echo_reply(uint8_t *b, size_t n, uint16_t seq)
{
    if (n < 8) {
        return;
    }
    memset(b, 0, n);
    b[0] = 0; /* Echo Reply */
    b[1] = 0;
    b[6] = (uint8_t)((seq >> 8) & 0xff);
    b[7] = (uint8_t)(seq & 0xff);
}

int cpe_agent_demo_ping_tick(cpe_agent_t *a)
{
    uint8_t frame[16];
    netdiag_event_t ev;
    netdiag_stats_t st;
    cpe_perf_sample_t sample;
    char line[CPE_NDJSON_LINE_MAX];
    uint64_t now_ms;
    struct timespec ts;
    static uint16_t seq;

    if (!a || !a->ping) {
        return -1;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        now_ms = 0;
    } else {
        now_ms = (uint64_t)ts.tv_sec * 1000ull +
                 (uint64_t)ts.tv_nsec / 1000000ull;
    }

    /*
     * Simulate a successful RTT: mark send_ts by feeding an echo request as
     * responder would, then feed echo reply as requester. Easier path: feed
     * reply with ts > 0 after priming send_ts via process — ping requester
     * path uses send_ts only if set. Feed reply with fabricated latency by
     * setting send_ts indirectly: feed type 8 as responder is wrong role.
     *
     * For REQUESTER: feed type 0 (echo reply) with ts; if send_ts is 0,
     * latency defaults to 5 ms in libnetdiag — acceptable for demo.
     */
    seq++;
    synth_icmp_echo_reply(frame, sizeof(frame), seq);
    if (ping_feed_input_with_ts(a->ping, frame, sizeof(frame),
                                now_ms ? now_ms : 1) != 0) {
        return -1;
    }
    (void)ping_process(a->ping, now_ms ? now_ms + 1 : 1);
    while (ping_next_event(a->ping, &ev) == 1) {
        /* drain */
    }
    if (ping_get_stats(a->ping, &st) != 0) {
        return -1;
    }

    memset(&sample, 0, sizeof(sample));
    snprintf(sample.probe, sizeof(sample.probe), "ping");
    snprintf(sample.target, sizeof(sample.target), "%s", a->cfg.demo_target);
    sample.rtt_ms = (double)(st.avg_latency_ms ? st.avg_latency_ms : 5);
    sample.loss = st.loss_pct / 100.0f;
    iso_now(sample.ts_iso, sizeof(sample.ts_iso));
    snprintf(sample.meta, sizeof(sample.meta),
             "{\"replies\":%u,\"timeouts\":%u,\"demo\":true}",
             (unsigned)st.replies, (unsigned)st.timeouts);

    a->last = sample;
    a->has_last = 1;

    if (cpe_perf_format_ndjson(a->cfg.router_id, &sample, line, sizeof(line)) <
        0) {
        return -1;
    }
    if (cpe_agent_spool_push_line(a, line) != 0) {
        return -1;
    }
    (void)eq_push(a, CPE_AGENT_EVENT_SAMPLE_READY, "demo ping", 0, 0);
    return 0;
}

int cpe_agent_last_sample(const cpe_agent_t *a, cpe_perf_sample_t *out)
{
    if (!a || !out || !a->has_last) {
        return -1;
    }
    *out = a->last;
    return 0;
}

int cpe_agent_set_last_sample(cpe_agent_t *a, const cpe_perf_sample_t *s)
{
    if (!a || !s) {
        return -1;
    }
    a->last = *s;
    a->has_last = 1;
    (void)eq_push(a, CPE_AGENT_EVENT_SAMPLE_READY, "sample", 0, 0);
    return 0;
}

int cpe_agent_set_last_wifi(cpe_agent_t *a, const cpe_wifi_snapshot_t *s)
{
    if (!a || !s) {
        return -1;
    }
    a->last_wifi = *s;
    a->has_last_wifi = 1;
    return 0;
}

int cpe_agent_last_wifi(const cpe_agent_t *a, cpe_wifi_snapshot_t *out)
{
    if (!a || !out || !a->has_last_wifi) {
        return -1;
    }
    *out = a->last_wifi;
    return 0;
}

int cpe_agent_feed_icmp_echo_reply(cpe_agent_t *a, const uint8_t *icmp,
                                   size_t len, uint64_t ts_ms)
{
    netdiag_event_t ev;

    if (!a || !a->ping || !icmp || len < 8) {
        return -1;
    }
    if (ping_feed_input_with_ts(a->ping, icmp, len, ts_ms ? ts_ms : 1) != 0) {
        return -1;
    }
    (void)ping_process(a->ping, ts_ms ? ts_ms + 1 : 1);
    while (ping_next_event(a->ping, &ev) == 1) {
    }
    return 0;
}

int cpe_agent_sample_tick(cpe_agent_t *a)
{
    if (!a) {
        return -1;
    }
    if (a->cfg.demo_mode) {
        return cpe_agent_demo_ping_tick(a);
    }
    return cpe_agent_live_ping_tick(a);
}

int cpe_agent_get_local_latency_json(const cpe_agent_t *a, char *buf,
                                     size_t buflen)
{
    int n;
    const cpe_perf_sample_t *s;

    if (!a || !buf || buflen < 16) {
        return -1;
    }
    if (!a->has_last) {
        n = snprintf(buf, buflen, "{\"available\":false}");
        if (n < 0 || (size_t)n >= buflen) {
            return -1;
        }
        return n;
    }
    s = &a->last;
    n = snprintf(buf, buflen,
                 "{\"available\":true,\"router_id\":\"%s\",\"probe\":\"%s\","
                 "\"target\":\"%s\",\"rtt_ms\":%.3f,\"loss\":%.4f,\"ts\":\"%s\"}",
                 a->cfg.router_id[0] ? a->cfg.router_id : "unknown", s->probe,
                 s->target, s->rtt_ms, (double)s->loss, s->ts_iso);
    if (n < 0 || (size_t)n >= buflen) {
        return -1;
    }
    return n;
}

int cpe_agent_feed_nfct(cpe_agent_t *a, const uint8_t *data, size_t len,
                        uint64_t ts_ms)
{
    nfct_event_t nev;
    nf_flow_obs_t obs;
    char line[CPE_NDJSON_LINE_MAX];
    int count = 0;

    if (!a || !a->nfct || !data || len == 0) {
        return -1;
    }
    if (nfct_feed_input(a->nfct, data, len) != 0) {
        /* parser may still yield partial events */
    }
    while (nfct_next_event(a->nfct, &nev) == 1) {
        if (nf_obs_from_nfct(&nev, a->cfg.router_id, ts_ms, &obs) == 0) {
            if (nf_obs_format(&obs, line, sizeof(line)) == 0) {
                if (cpe_agent_spool_push_line(a, line) == 0) {
                    count++;
                    a->nfct_obs++;
                }
            }
        }
    }
    return count;
}

uint64_t cpe_agent_nfct_obs_count(const cpe_agent_t *a)
{
    return a ? a->nfct_obs : 0;
}

int cpe_agent_spool_push_line(cpe_agent_t *a, const char *line)
{
    size_t n;

    if (!a || !line || !a->spool || a->spool_cap == 0) {
        return -1;
    }
    n = strlen(line);
    if (n >= CPE_SPOOL_LINE) {
        n = CPE_SPOOL_LINE - 1;
    }
    if (a->spool_cnt >= a->spool_cap) {
        /* Drop oldest */
        a->spool_head = (a->spool_head + 1) % a->spool_cap;
        a->spool_cnt--;
        a->spool_drops++;
        (void)eq_push(a, CPE_AGENT_EVENT_SPOOL_DROP, "full", 0, 0);
    }
    memcpy(a->spool[a->spool_tail], line, n);
    a->spool[a->spool_tail][n] = '\0';
    a->spool_tail = (a->spool_tail + 1) % a->spool_cap;
    a->spool_cnt++;
    return 0;
}

size_t cpe_agent_spool_depth(const cpe_agent_t *a)
{
    return a ? a->spool_cnt : 0;
}

size_t cpe_agent_spool_drops(const cpe_agent_t *a)
{
    return a ? a->spool_drops : 0;
}

int cpe_agent_spool_flush(cpe_agent_t *a, FILE *fp)
{
    size_t written = 0;

    if (!a || !fp || !a->spool) {
        return -1;
    }
    while (a->spool_cnt > 0) {
        if (fprintf(fp, "%s\n", a->spool[a->spool_head]) < 0) {
            return -1;
        }
        a->spool_head = (a->spool_head + 1) % a->spool_cap;
        a->spool_cnt--;
        written++;
    }
    if (fflush(fp) != 0) {
        return -1;
    }
    return (int)written;
}

int cpe_agent_emit_flush(cpe_agent_t *a)
{
    FILE *fp;
    int n;
    /* Bounded batch for HTTPS POST — OpenWrt stack budget. */
    char body[8 * CPE_NDJSON_LINE_MAX];
    size_t body_len = 0;
    char err[160];

    if (!a) {
        return -1;
    }
    if (strcmp(a->cfg.emit_mode, "https") == 0) {
        /* Drain ring into a single NDJSON body, then POST. */
        if (a->spool_cnt == 0) {
            return 0;
        }
        body[0] = '\0';
        n = 0;
        while (a->spool_cnt > 0 && body_len + CPE_NDJSON_LINE_MAX < sizeof(body)) {
            size_t L = strlen(a->spool[a->spool_head]);
            if (body_len + L + 2 >= sizeof(body)) {
                break;
            }
            memcpy(body + body_len, a->spool[a->spool_head], L);
            body_len += L;
            body[body_len++] = '\n';
            body[body_len] = '\0';
            a->spool_head = (a->spool_head + 1) % a->spool_cap;
            a->spool_cnt--;
            n++;
        }
        err[0] = '\0';
        if (cpe_agent_tls_post(a->cfg.https_url, body, body_len,
                               a->cfg.tls_ca_file[0] ? a->cfg.tls_ca_file
                                                     : NULL,
                               a->cfg.tls_cert_file[0] ? a->cfg.tls_cert_file
                                                       : NULL,
                               a->cfg.tls_key_file[0] ? a->cfg.tls_key_file
                                                      : NULL,
                               err, sizeof(err)) != 0) {
            return -1;
        }
        return n;
    }
    if (strcmp(a->cfg.emit_mode, "spool") == 0) {
        if (a->cfg.spool_path[0] == '\0') {
            return -1;
        }
        (void)cpe_spool_ensure_parent_dir(a->cfg.spool_path);
        fp = fopen(a->cfg.spool_path, "a");
        if (!fp) {
            return -1;
        }
        n = cpe_agent_spool_flush(a, fp);
        if (fclose(fp) != 0 && n >= 0) {
            return -1;
        }
        return n;
    }
    /* default: stdout */
    return cpe_agent_spool_flush(a, stdout);
}

int cpe_agent_reload_config(cpe_agent_t *a, const char *config_path,
                            const char *router_id_override, char *err,
                            size_t err_len)
{
    cpe_agent_config_t cfg;

    if (!a) {
        if (err && err_len) {
            snprintf(err, err_len, "null agent");
        }
        return -1;
    }

    cpe_agent_config_defaults(&cfg);
    if (config_path && config_path[0]) {
        if (cpe_agent_config_load_yaml_path(config_path, &cfg, err, err_len) !=
            0) {
            return -1;
        }
    } else {
        /* Keep current settings except generation when no path. */
        cfg = a->cfg;
        cfg.generation = 0;
    }

    if (router_id_override && router_id_override[0]) {
        if (strlen(router_id_override) >= sizeof(cfg.router_id)) {
            if (err && err_len) {
                snprintf(err, err_len, "router_id too long");
            }
            return -1;
        }
        snprintf(cfg.router_id, sizeof(cfg.router_id), "%s",
                 router_id_override);
    }

    if (cpe_agent_apply_config(a, &cfg) != 0) {
        if (err && err_len && err[0] == '\0') {
            snprintf(err, err_len, "apply_config rejected");
        }
        return -1;
    }
    return 0;
}
