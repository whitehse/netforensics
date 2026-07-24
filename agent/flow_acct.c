/**
 * @file flow_acct.c
 * @brief Conntrack-based per-flow bandwidth accounting for cpe_agent.
 */

#define _POSIX_C_SOURCE 200809L

#include "cpe_agent.h"
#include "cpe_flow_acct.h"
#include "nfct_netlink.h"

#include "nfct.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Accessors implemented in agent_core.c */
cpe_flow_state_t *cpe_agent_flow_state(cpe_agent_t *a);
const cpe_flow_state_t *cpe_agent_flow_state_const(const cpe_agent_t *a);

void cpe_flow_state_init(cpe_flow_state_t *st)
{
    if (!st) {
        return;
    }
    memset(st, 0, sizeof(*st));
    st->fd = -1;
    st->dump_fd = -1;
    st->poll_interval_ms = 200;
    st->dump_interval_ms = 200;
    st->sample_emit_ms = 2000;
    st->sample_top_n = 32;
    st->max_flows = CPE_FLOW_MAX;
    st->join_update = 1;
    st->emit_destroy = 1;
}

static uint64_t mono_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

static void iso_now(char *buf, size_t n)
{
    struct timespec ts;
    struct tm tm;
    time_t sec;
    int ms;
    int y;

    if (!buf || n < 25) {
        return;
    }
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        snprintf(buf, n, "1970-01-01T00:00:00.000Z");
        return;
    }
    sec = ts.tv_sec;
    ms = (int)(ts.tv_nsec / 1000000L);
    if (ms < 0) {
        ms = 0;
    }
    if (ms > 999) {
        ms = 999;
    }
    if (!gmtime_r(&sec, &tm)) {
        snprintf(buf, n, "1970-01-01T00:00:00.000Z");
        return;
    }
    /* Clamp year so -Wformat-truncation is quiet on armv7 cross-gcc. */
    y = tm.tm_year + 1900;
    if (y < 0) {
        y = 0;
    }
    if (y > 9999) {
        y = 9999;
    }
    snprintf(buf, n, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", y, tm.tm_mon + 1,
             tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, ms);
}

static void ipv4_str(uint32_t host_order, char *buf, size_t n)
{
    struct in_addr a;
    a.s_addr = htonl(host_order);
    if (!inet_ntop(AF_INET, &a, buf, (socklen_t)n)) {
        snprintf(buf, n, "0.0.0.0");
    }
}

static void ipv6_str(const uint8_t *addr, char *buf, size_t n)
{
    if (!inet_ntop(AF_INET6, addr, buf, (socklen_t)n)) {
        snprintf(buf, n, "::");
    }
}

static uint32_t fnv1a(const void *data, size_t len, uint32_t h)
{
    const uint8_t *p = (const uint8_t *)data;
    size_t i;
    if (h == 0) {
        h = 2166136261u;
    }
    for (i = 0; i < len; i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

static void make_flow_id(const cpe_flow_entry_t *e, char *out, size_t n)
{
    uint32_t h = 0;
    h = fnv1a(e->lan_ip, strlen(e->lan_ip), h);
    h = fnv1a(&e->lan_port, sizeof(e->lan_port), h);
    h = fnv1a(e->remote_ip, strlen(e->remote_ip), h);
    h = fnv1a(&e->remote_port, sizeof(e->remote_port), h);
    h = fnv1a(&e->proto, sizeof(e->proto), h);
    if (e->has_ct_id) {
        h = fnv1a(&e->ct_id, sizeof(e->ct_id), h);
    }
    snprintf(out, n, "%08x", (unsigned)h);
}

static const char *event_name(nfct_event_type_t t)
{
    switch (t) {
    case NFCT_EVENT_NEW:
        return "NEW";
    case NFCT_EVENT_UPDATE:
        return "UPDATE";
    case NFCT_EVENT_DESTROY:
        return "DESTROY";
    default:
        return "OTHER";
    }
}

int cpe_flow_format_ndjson(const char *router_id, const char *event,
                           const cpe_flow_entry_t *e, char *buf, size_t buflen)
{
    char ts[40];
    int n;

    if (!router_id || !event || !e || !buf || buflen < 64) {
        return -1;
    }
    iso_now(ts, sizeof(ts));
    n = snprintf(
        buf, buflen,
        "{\"type\":\"cpe_flow\",\"ts\":\"%s\",\"router_id\":\"%s\","
        "\"event\":\"%s\",\"flow_id\":\"%s\",\"ct_id\":%u,\"proto\":%u,"
        "\"ip_version\":%u,\"lan_ip\":\"%s\",\"lan_port\":%u,"
        "\"wan_ip\":\"%s\",\"wan_port\":%u,\"remote_ip\":\"%s\","
        "\"remote_port\":%u,\"orig_bytes\":%llu,\"reply_bytes\":%llu,"
        "\"orig_pkts\":%llu,\"reply_pkts\":%llu,\"bytes_up\":%llu,"
        "\"bytes_down\":%llu,\"bytes_up_delta\":%llu,\"bytes_down_delta\":%llu,"
        "\"rate_up_bps\":%.0f,\"rate_down_bps\":%.0f,\"duration_ms\":%llu,"
        "\"state\":\"%s\",\"path_id\":null}",
        ts, router_id, event, e->flow_id[0] ? e->flow_id : "0",
        e->has_ct_id ? (unsigned)e->ct_id : 0u, (unsigned)e->proto,
        (unsigned)e->ip_version, e->lan_ip, (unsigned)e->lan_port, e->wan_ip,
        (unsigned)e->wan_port, e->remote_ip, (unsigned)e->remote_port,
        (unsigned long long)e->orig_bytes, (unsigned long long)e->reply_bytes,
        (unsigned long long)e->orig_pkts, (unsigned long long)e->reply_pkts,
        (unsigned long long)e->bytes_up, (unsigned long long)e->bytes_down,
        (unsigned long long)e->bytes_up_delta,
        (unsigned long long)e->bytes_down_delta, e->rate_up_bps,
        e->rate_down_bps,
        (unsigned long long)(e->last_seen_ms > e->first_seen_ms
                                 ? e->last_seen_ms - e->first_seen_ms
                                 : 0),
        e->state[0] ? e->state : "UNKNOWN");
    if (n < 0 || (size_t)n >= buflen) {
        return -1;
    }
    return n;
}

static void entry_from_event(cpe_flow_entry_t *e, const nfct_event_t *ev,
                             uint64_t now_ms)
{
    memset(e, 0, sizeof(*e));
    e->used = 1;
    e->alive = (ev->type != NFCT_EVENT_DESTROY);
    e->proto = ev->protocol;
    e->first_seen_ms = now_ms;
    e->last_seen_ms = now_ms;
    snprintf(e->state, sizeof(e->state), "%s", event_name(ev->type));

    if (ev->has_id) {
        e->ct_id = ev->id;
        e->has_ct_id = 1;
    }
    if (ev->is_ipv6) {
        e->ip_version = 6;
        ipv6_str(ev->lan_src_ip6, e->lan_ip, sizeof(e->lan_ip));
        ipv6_str(ev->lan_dst_ip6, e->remote_ip, sizeof(e->remote_ip));
        ipv6_str(ev->wan_src_ip6, e->wan_ip, sizeof(e->wan_ip));
        e->lan_port = ev->lan_src_port;
        e->remote_port = ev->lan_dst_port;
        e->wan_port = ev->wan_src_port;
    } else {
        e->ip_version = 4;
        ipv4_str(ev->lan_src_ip, e->lan_ip, sizeof(e->lan_ip));
        ipv4_str(ev->lan_dst_ip, e->remote_ip, sizeof(e->remote_ip));
        ipv4_str(ev->wan_src_ip, e->wan_ip, sizeof(e->wan_ip));
        e->lan_port = ev->lan_src_port;
        e->remote_port = ev->lan_dst_port;
        e->wan_port = ev->wan_src_port;
    }

    if (ev->has_counters) {
        e->orig_pkts = ev->orig_packets;
        e->orig_bytes = ev->orig_bytes;
        e->reply_pkts = ev->reply_packets;
        e->reply_bytes = ev->reply_bytes;
        e->bytes_up = e->orig_bytes;
        e->bytes_down = e->reply_bytes;
    }
    make_flow_id(e, e->flow_id, sizeof(e->flow_id));
}

static int find_slot(cpe_flow_state_t *st, const cpe_flow_entry_t *key)
{
    uint32_t i;
    int free_i = -1;
    uint64_t oldest = UINT64_MAX;
    int oldest_i = -1;

    for (i = 0; i < st->max_flows && i < CPE_FLOW_MAX; i++) {
        cpe_flow_entry_t *e = &st->table[i];
        if (!e->used) {
            if (free_i < 0) {
                free_i = (int)i;
            }
            continue;
        }
        if (key->has_ct_id && e->has_ct_id && e->ct_id == key->ct_id) {
            return (int)i;
        }
        if (e->proto == key->proto && e->lan_port == key->lan_port &&
            e->remote_port == key->remote_port &&
            strcmp(e->lan_ip, key->lan_ip) == 0 &&
            strcmp(e->remote_ip, key->remote_ip) == 0) {
            return (int)i;
        }
        if (e->last_seen_ms < oldest) {
            oldest = e->last_seen_ms;
            oldest_i = (int)i;
        }
    }
    if (free_i >= 0) {
        return free_i;
    }
    return oldest_i;
}

static void update_rates(cpe_flow_entry_t *e, uint64_t prev_up, uint64_t prev_down,
                         uint64_t prev_ms, uint64_t now_ms)
{
    uint64_t dt = (now_ms > prev_ms) ? (now_ms - prev_ms) : 0;
    e->bytes_up_delta =
        (e->bytes_up >= prev_up) ? (e->bytes_up - prev_up) : e->bytes_up;
    e->bytes_down_delta = (e->bytes_down >= prev_down)
                              ? (e->bytes_down - prev_down)
                              : e->bytes_down;
    if (dt > 0) {
        e->rate_up_bps = (double)e->bytes_up_delta * 8000.0 / (double)dt;
        e->rate_down_bps = (double)e->bytes_down_delta * 8000.0 / (double)dt;
    }
}

static int apply_event(cpe_agent_t *a, cpe_flow_state_t *st,
                       const nfct_event_t *ev, uint64_t now_ms)
{
    cpe_flow_entry_t tmp;
    cpe_flow_entry_t *slot;
    int idx;
    uint64_t prev_up, prev_down, prev_ms;
    char line[CPE_NDJSON_LINE_MAX];
    const cpe_agent_config_t *cfg = cpe_agent_config(a);

    if (!ev->has_lan && !(ev->is_destroy && ev->has_id)) {
        return 0;
    }
    if (ev->has_lan && !ev->has_counters && !st->warned_no_acct &&
        (ev->type == NFCT_EVENT_DESTROY || ev->type == NFCT_EVENT_UPDATE)) {
        fprintf(stderr,
                "cpe_agent: flow_acct: no CTA counters (enable "
                "net.netfilter.nf_conntrack_acct=1)\n");
        st->warned_no_acct = 1;
    }

    entry_from_event(&tmp, ev, now_ms);
    idx = find_slot(st, &tmp);
    if (idx < 0) {
        return -1;
    }
    slot = &st->table[idx];
    prev_up = slot->used ? slot->bytes_up : 0;
    prev_down = slot->used ? slot->bytes_down : 0;
    prev_ms = slot->used ? slot->last_seen_ms : now_ms;

    if (!slot->used) {
        *slot = tmp;
        st->table_used++;
    } else {
        if (!slot->first_seen_ms) {
            slot->first_seen_ms = now_ms;
        }
        slot->last_seen_ms = now_ms;
        if (tmp.has_ct_id) {
            slot->ct_id = tmp.ct_id;
            slot->has_ct_id = 1;
        }
        if (tmp.lan_ip[0]) {
            memcpy(slot->lan_ip, tmp.lan_ip, sizeof(slot->lan_ip));
            slot->lan_port = tmp.lan_port;
            memcpy(slot->remote_ip, tmp.remote_ip, sizeof(slot->remote_ip));
            slot->remote_port = tmp.remote_port;
            memcpy(slot->wan_ip, tmp.wan_ip, sizeof(slot->wan_ip));
            slot->wan_port = tmp.wan_port;
            slot->proto = tmp.proto;
            slot->ip_version = tmp.ip_version;
        }
        if (ev->has_counters) {
            slot->orig_pkts = tmp.orig_pkts;
            slot->orig_bytes = tmp.orig_bytes;
            slot->reply_pkts = tmp.reply_pkts;
            slot->reply_bytes = tmp.reply_bytes;
            slot->bytes_up = tmp.bytes_up;
            slot->bytes_down = tmp.bytes_down;
            update_rates(slot, prev_up, prev_down, prev_ms, now_ms);
        }
        snprintf(slot->state, sizeof(slot->state), "%s", tmp.state);
        if (!slot->flow_id[0]) {
            make_flow_id(slot, slot->flow_id, sizeof(slot->flow_id));
        }
    }

    st->events_in++;

    if (ev->type == NFCT_EVENT_DESTROY && st->emit_destroy && cfg) {
        slot->alive = 0;
        snprintf(slot->state, sizeof(slot->state), "DESTROY");
        if (cpe_flow_format_ndjson(cfg->router_id, "destroy", slot, line,
                                   sizeof(line)) > 0) {
            if (cpe_agent_spool_push_line(a, line) == 0) {
                st->destroys_emitted++;
            }
        }
        /* Keep slot briefly for list; mark unused after emit. */
        slot->used = 0;
        if (st->table_used > 0) {
            st->table_used--;
        }
        return 1;
    }
    if (ev->type == NFCT_EVENT_NEW && st->emit_new && cfg) {
        if (cpe_flow_format_ndjson(cfg->router_id, "new", slot, line,
                                   sizeof(line)) > 0) {
            (void)cpe_agent_spool_push_line(a, line);
        }
    }
    return 0;
}

static int drain_fd(cpe_agent_t *a, cpe_flow_state_t *st, int fd, unsigned max_msgs)
{
    uint8_t buf[8192];
    unsigned n = 0;
    int emitted = 0;
    uint64_t now = mono_ms();
    nfct_ctx *ctx;

    if (fd < 0 || !a) {
        return 0;
    }
    /* Reuse agent nfct parser via feed path that allocates? Create temp. */
    ctx = nfct_create(NFCT_ROLE_COLLECTOR);
    if (!ctx) {
        return -1;
    }

    while (n < max_msgs) {
        int rd = nfct_netlink_recv(fd, buf, sizeof(buf));
        nfct_event_t ev;
        if (rd == 0) {
            break;
        }
        if (rd < 0) {
            break;
        }
        if (nfct_feed_input(ctx, buf, (size_t)rd) != 0) {
            /* continue */
        }
        while (nfct_next_event(ctx, &ev) == 1) {
            if (apply_event(a, st, &ev, now) > 0) {
                emitted++;
            }
        }
        n++;
    }
    nfct_destroy(ctx);
    return emitted;
}

int cpe_agent_flow_open(cpe_agent_t *a)
{
    cpe_flow_state_t *st;
    char err[96];
    const cpe_agent_config_t *cfg;

    if (!a) {
        return -1;
    }
    st = cpe_agent_flow_state(a);
    cfg = cpe_agent_config(a);
    if (!st || !cfg) {
        return -1;
    }
    if (st->fd >= 0) {
        return 0;
    }
    err[0] = '\0';
    st->fd = nfct_netlink_open(st->join_update, err, sizeof(err));
    if (st->fd < 0) {
        st->open_ok = 0;
        snprintf(st->open_err, sizeof(st->open_err), "%s",
                 err[0] ? err : "nfct open failed");
        return -1;
    }
    (void)nfct_netlink_set_nonblock(st->fd);
    st->dump_fd = nfct_netlink_open_dump(err, sizeof(err));
    if (st->dump_fd >= 0) {
        (void)nfct_netlink_set_nonblock(st->dump_fd);
    }
    st->open_ok = 1;
    st->open_err[0] = '\0';
    st->enabled = 1;
    return 0;
}

void cpe_agent_flow_close(cpe_agent_t *a)
{
    cpe_flow_state_t *st;
    if (!a) {
        return;
    }
    st = cpe_agent_flow_state(a);
    if (!st) {
        return;
    }
    nfct_netlink_close(st->fd);
    st->fd = -1;
    nfct_netlink_close(st->dump_fd);
    st->dump_fd = -1;
    st->enabled = 0;
}

int cpe_agent_flow_poll(cpe_agent_t *a, unsigned max_msgs)
{
    cpe_flow_state_t *st;
    int n = 0;

    if (!a) {
        return -1;
    }
    st = cpe_agent_flow_state(a);
    if (!st || !st->enabled) {
        return 0;
    }
    if (st->fd < 0) {
        if (cpe_agent_flow_open(a) != 0) {
            return 0;
        }
    }
    n = drain_fd(a, st, st->fd, max_msgs ? max_msgs : 64);
    return n;
}

static int maybe_dump(cpe_agent_t *a, cpe_flow_state_t *st, uint64_t now)
{
    int emitted = 0;
    if (st->dump_fd < 0) {
        return 0;
    }
    if (st->dump_interval_ms == 0) {
        return 0;
    }
    if (st->last_dump_ms != 0 &&
        now - st->last_dump_ms < st->dump_interval_ms) {
        return 0;
    }
    if (nfct_netlink_dump_request(st->dump_fd) != 0) {
        return 0;
    }
    st->last_dump_ms = now;
    st->dumps++;
    /* Drain dump replies (may be multipacket). */
    emitted = drain_fd(a, st, st->dump_fd, 256);
    return emitted;
}

static int emit_top_samples(cpe_agent_t *a, cpe_flow_state_t *st, uint64_t now)
{
    const cpe_agent_config_t *cfg = cpe_agent_config(a);
    uint32_t top_n = st->sample_top_n ? st->sample_top_n : 32;
    uint32_t i, j, count = 0;
    int indices[CPE_FLOW_MAX];
    int emitted = 0;
    char line[CPE_NDJSON_LINE_MAX];

    if (!cfg || st->sample_emit_ms == 0) {
        return 0;
    }
    if (st->last_sample_ms != 0 &&
        now - st->last_sample_ms < st->sample_emit_ms) {
        return 0;
    }
    st->last_sample_ms = now;

    for (i = 0; i < st->max_flows && i < CPE_FLOW_MAX; i++) {
        if (st->table[i].used && st->table[i].alive) {
            indices[count++] = (int)i;
        }
    }
    /* Selection sort by combined rate (small top_n). */
    for (i = 0; i < count && i < top_n; i++) {
        uint32_t best = i;
        double best_r =
            st->table[indices[i]].rate_up_bps + st->table[indices[i]].rate_down_bps;
        for (j = i + 1; j < count; j++) {
            double r = st->table[indices[j]].rate_up_bps +
                       st->table[indices[j]].rate_down_bps;
            if (r > best_r) {
                best = j;
                best_r = r;
            }
        }
        if (best != i) {
            int tmp = indices[i];
            indices[i] = indices[best];
            indices[best] = tmp;
        }
    }
    for (i = 0; i < count && i < top_n; i++) {
        cpe_flow_entry_t *e = &st->table[indices[i]];
        /* Skip idle samples to save CH bandwidth. */
        if (e->rate_up_bps + e->rate_down_bps < 1.0 &&
            e->bytes_up_delta + e->bytes_down_delta == 0) {
            continue;
        }
        if (cpe_flow_format_ndjson(cfg->router_id, "sample", e, line,
                                   sizeof(line)) > 0) {
            if (cpe_agent_spool_push_line(a, line) == 0) {
                emitted++;
                st->samples_emitted++;
            }
        }
    }
    return emitted;
}

int cpe_agent_flow_tick(cpe_agent_t *a)
{
    cpe_flow_state_t *st;
    uint64_t now;
    int n = 0;

    if (!a) {
        return -1;
    }
    st = cpe_agent_flow_state(a);
    if (!st || !st->enabled) {
        return 0;
    }
    now = mono_ms();
    st->last_tick_ms = now;
    n += cpe_agent_flow_poll(a, 128);
    n += maybe_dump(a, st, now);
    n += emit_top_samples(a, st, now);
    return n;
}

int cpe_agent_flow_snapshot(const cpe_agent_t *a, cpe_flow_snapshot_t *out)
{
    const cpe_flow_state_t *st;
    uint32_t i, n = 0;

    if (!a || !out) {
        return -1;
    }
    st = cpe_agent_flow_state_const(a);
    if (!st) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    out->events_in = st->events_in;
    out->destroys_emitted = st->destroys_emitted;
    out->samples_emitted = st->samples_emitted;
    out->dumps = st->dumps;
    out->open_ok = st->open_ok;
    snprintf(out->open_err, sizeof(out->open_err), "%s", st->open_err);
    iso_now(out->ts_iso, sizeof(out->ts_iso));
    for (i = 0; i < st->max_flows && i < CPE_FLOW_MAX; i++) {
        if (st->table[i].used) {
            out->flows[n++] = st->table[i];
        }
    }
    out->flow_count = n;
    return 0;
}

int cpe_agent_flow_feed_event(cpe_agent_t *a, const nfct_event_t *ev)
{
    cpe_flow_state_t *st;
    if (!a || !ev) {
        return -1;
    }
    st = cpe_agent_flow_state(a);
    if (!st) {
        return -1;
    }
    return apply_event(a, st, ev, mono_ms());
}

const char *cpe_agent_flow_last_error(const cpe_agent_t *a)
{
    const cpe_flow_state_t *st = cpe_agent_flow_state_const(a);
    if (!st || !st->open_err[0]) {
        return NULL;
    }
    return st->open_err;
}
