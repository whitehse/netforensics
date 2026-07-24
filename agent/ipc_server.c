/**
 * @file ipc_server.c
 * @brief Unix domain socket server for cpe_agent control plane.
 */

#define _POSIX_C_SOURCE 200809L

#include "cpe_ipc.h"
#include "cpe_tcp_stats.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

struct cpe_ipc_server {
    cpe_agent_t *agent;
    int          listen_fd;
    int          clients[CPE_IPC_CLIENTS_MAX];
    char         path[CPE_CFG_PATH_MAX];
    char         rbuf[CPE_IPC_CLIENTS_MAX][CPE_IPC_LINE_MAX];
    size_t       rlen[CPE_IPC_CLIENTS_MAX];
};

static int set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static int mkdir_p_parent(const char *path)
{
    char tmp[CPE_CFG_PATH_MAX];
    size_t n;
    char *slash;

    if (!path || !path[0]) {
        return -1;
    }
    n = strlen(path);
    if (n >= sizeof(tmp)) {
        return -1;
    }
    memcpy(tmp, path, n + 1);
    slash = strrchr(tmp, '/');
    if (!slash || slash == tmp) {
        return 0;
    }
    *slash = '\0';
    /* one-level parents: /var/run/netforensics */
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
        /* try grandparent */
        slash = strrchr(tmp, '/');
        if (slash && slash != tmp) {
            *slash = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
                return -1;
            }
            *slash = '/';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
                return -1;
            }
        } else {
            return -1;
        }
    }
    return 0;
}

static int json_get_str(const char *json, const char *key, char *out,
                        size_t out_sz)
{
    char pat[64];
    const char *p;
    size_t i = 0;
    int n;

    if (!json || !key || !out || out_sz == 0) {
        return -1;
    }
    out[0] = '\0';
    n = snprintf(pat, sizeof(pat), "\"%s\"", key);
    if (n < 0 || (size_t)n >= sizeof(pat)) {
        return -1;
    }
    p = strstr(json, pat);
    if (!p) {
        return -1;
    }
    p += (size_t)n;
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    if (*p != ':') {
        return -1;
    }
    p++;
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    if (*p != '"') {
        return -1;
    }
    p++;
    while (*p && *p != '"' && i + 1 < out_sz) {
        if (*p == '\\' && p[1]) {
            p++;
        }
        out[i++] = *p++;
    }
    out[i] = '\0';
    return 0;
}

static int json_get_u32(const char *json, const char *key, uint32_t *out)
{
    char pat[64];
    const char *p;
    char *end;
    unsigned long v;
    int n;

    if (!json || !key || !out) {
        return -1;
    }
    n = snprintf(pat, sizeof(pat), "\"%s\"", key);
    if (n < 0 || (size_t)n >= sizeof(pat)) {
        return -1;
    }
    p = strstr(json, pat);
    if (!p) {
        return -1;
    }
    p += (size_t)n;
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    if (*p != ':') {
        return -1;
    }
    p++;
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    v = strtoul(p, &end, 10);
    if (end == p) {
        return -1;
    }
    *out = (uint32_t)v;
    return 0;
}

static int respond_err(char *out, size_t out_sz, const char *op, const char *msg)
{
    int n = snprintf(out, out_sz,
                     "{\"ok\":false,\"op\":\"%s\",\"error\":\"%s\"}",
                     op && op[0] ? op : "unknown",
                     msg && msg[0] ? msg : "error");
    return (n < 0 || (size_t)n >= out_sz) ? -1 : 0;
}

static int append_remote_json(char *buf, size_t cap, size_t *off,
                              const cpe_tcp_remote_t *r)
{
    int n;
    float loss = cpe_tcp_loss_hint(r->syn_count, r->fin_count, r->rst_count,
                                   r->syn_retrans);
    n = snprintf(buf + *off, cap - *off,
                 "{\"remote_ip\":\"%s\",\"local_ip\":\"%s\","
                 "\"remote_port\":%u,\"local_port\":%u,"
                 "\"syn\":%u,\"fin\":%u,\"rst\":%u,\"syn_retrans\":%u,"
                 "\"pkts\":%u,\"bytes\":%llu,\"loss_hint\":%.4f}",
                 r->remote_ip, r->local_ip, (unsigned)r->remote_port,
                 (unsigned)r->local_port, (unsigned)r->syn_count,
                 (unsigned)r->fin_count, (unsigned)r->rst_count,
                 (unsigned)r->syn_retrans, (unsigned)r->pkt_count,
                 (unsigned long long)r->bytes_est, (double)loss);
    if (n < 0 || (size_t)n >= cap - *off) {
        return -1;
    }
    *off += (size_t)n;
    return 0;
}

static int append_prefix_json(char *buf, size_t cap, size_t *off,
                              const cpe_tcp_prefix_t *p)
{
    int n;
    float loss = cpe_tcp_loss_hint(p->syn_count, p->fin_count, p->rst_count,
                                   p->syn_retrans);
    n = snprintf(buf + *off, cap - *off,
                 "{\"prefix\":\"%s\",\"remotes\":%u,"
                 "\"syn\":%u,\"fin\":%u,\"rst\":%u,\"syn_retrans\":%u,"
                 "\"pkts\":%u,\"bytes\":%llu,\"loss_hint\":%.4f}",
                 p->prefix, (unsigned)p->remote_count, (unsigned)p->syn_count,
                 (unsigned)p->fin_count, (unsigned)p->rst_count,
                 (unsigned)p->syn_retrans, (unsigned)p->pkt_count,
                 (unsigned long long)p->bytes_est, (double)loss);
    if (n < 0 || (size_t)n >= cap - *off) {
        return -1;
    }
    *off += (size_t)n;
    return 0;
}

int cpe_ipc_handle_request(cpe_agent_t *a, const char *req_json, char *out,
                           size_t out_sz)
{
    char op[48];
    const cpe_agent_config_t *cfg;
    int n;

    if (!a || !req_json || !out || out_sz < 32) {
        return -1;
    }
    op[0] = '\0';
    (void)json_get_str(req_json, "op", op, sizeof(op));
    if (!op[0]) {
        return respond_err(out, out_sz, "unknown", "missing op");
    }
    cfg = cpe_agent_config(a);

    if (strcmp(op, "ping") == 0) {
        n = snprintf(out, out_sz, "{\"ok\":true,\"op\":\"ping\",\"data\":\"pong\"}");
        return (n < 0 || (size_t)n >= out_sz) ? -1 : 0;
    }
    if (strcmp(op, "help") == 0) {
        n = snprintf(
            out, out_sz,
            "{\"ok\":true,\"op\":\"help\",\"data\":["
            "\"ping\",\"status\",\"config\",\"last_sample\",\"latency\","
            "\"spool\",\"emit\",\"tcp_poll\",\"tcp_stats\",\"tcp_by_ip\","
            "\"tcp_by_prefix\",\"tcp_emit\",\"tcp_reset\","
            "\"flow_tick\",\"flow_stats\",\"flow_list\""
            "]}");
        return (n < 0 || (size_t)n >= out_sz) ? -1 : 0;
    }
    if (strcmp(op, "status") == 0) {
        n = snprintf(
            out, out_sz,
            "{\"ok\":true,\"op\":\"status\",\"data\":{"
            "\"router_id\":\"%s\","
            "\"emit_mode\":\"%s\","
            "\"egress_url\":\"%s\","
            "\"openai_proxy_url\":\"%s\","
            "\"demo\":%s,"
            "\"tcp_stats\":%s,"
            "\"tcp_nflog_group\":%u,"
            "\"flow_acct\":%s,"
            "\"spool_depth\":%zu,"
            "\"spool_drops\":%zu,"
            "\"generation\":%llu"
            "}}",
            cfg->router_id, cfg->emit_mode, cfg->https_url,
            cfg->openai_proxy_url[0] ? cfg->openai_proxy_url : "",
            cfg->demo_mode ? "true" : "false",
            cfg->tcp_stats_enabled ? "true" : "false",
            (unsigned)cfg->tcp_nflog_group,
            cfg->flow_acct_enabled ? "true" : "false",
            cpe_agent_spool_depth(a), cpe_agent_spool_drops(a),
            (unsigned long long)cfg->generation);
        return (n < 0 || (size_t)n >= out_sz) ? -1 : 0;
    }
    if (strcmp(op, "config") == 0) {
        n = snprintf(
            out, out_sz,
            "{\"ok\":true,\"op\":\"config\",\"data\":{"
            "\"router_id\":\"%s\",\"emit_mode\":\"%s\","
            "\"target\":\"%s\",\"interval_ms\":%u,\"timeout_ms\":%u,"
            "\"demo\":%s,\"tcp_stats\":%s,\"tcp_nflog_group\":%u,"
            "\"tcp_prefix_len\":%u,\"egress_url\":\"%s\","
            "\"openai_proxy_url\":\"%s\",\"ipc_socket\":\"%s\""
            "}}",
            cfg->router_id, cfg->emit_mode, cfg->demo_target,
            (unsigned)cfg->demo_interval_ms, (unsigned)cfg->probe_timeout_ms,
            cfg->demo_mode ? "true" : "false",
            cfg->tcp_stats_enabled ? "true" : "false",
            (unsigned)cfg->tcp_nflog_group, (unsigned)cfg->tcp_prefix_len,
            cfg->https_url,
            cfg->openai_proxy_url[0] ? cfg->openai_proxy_url : "",
            cfg->ipc_socket[0] ? cfg->ipc_socket : CPE_IPC_SOCK_DEFAULT);
        return (n < 0 || (size_t)n >= out_sz) ? -1 : 0;
    }
    if (strcmp(op, "last_sample") == 0) {
        cpe_perf_sample_t s;
        if (cpe_agent_last_sample(a, &s) != 0) {
            n = snprintf(out, out_sz,
                         "{\"ok\":true,\"op\":\"last_sample\",\"data\":null}");
            return (n < 0 || (size_t)n >= out_sz) ? -1 : 0;
        }
        n = snprintf(out, out_sz,
                     "{\"ok\":true,\"op\":\"last_sample\",\"data\":{"
                     "\"probe\":\"%s\",\"target\":\"%s\",\"rtt_ms\":%.3f,"
                     "\"loss\":%.4f,\"ts\":\"%s\",\"meta\":%s}}",
                     s.probe, s.target, s.rtt_ms, (double)s.loss, s.ts_iso,
                     s.meta[0] ? s.meta : "{}");
        return (n < 0 || (size_t)n >= out_sz) ? -1 : 0;
    }
    if (strcmp(op, "latency") == 0) {
        char j[256];
        if (cpe_agent_get_local_latency_json(a, j, sizeof(j)) < 0) {
            return respond_err(out, out_sz, op, "latency failed");
        }
        n = snprintf(out, out_sz,
                     "{\"ok\":true,\"op\":\"latency\",\"data\":%s}", j);
        return (n < 0 || (size_t)n >= out_sz) ? -1 : 0;
    }
    if (strcmp(op, "spool") == 0) {
        n = snprintf(out, out_sz,
                     "{\"ok\":true,\"op\":\"spool\",\"data\":{"
                     "\"depth\":%zu,\"drops\":%zu}}",
                     cpe_agent_spool_depth(a), cpe_agent_spool_drops(a));
        return (n < 0 || (size_t)n >= out_sz) ? -1 : 0;
    }
    if (strcmp(op, "emit") == 0) {
        int lines = cpe_agent_emit_flush(a);
        if (lines < 0) {
            return respond_err(out, out_sz, op, "emit_flush failed");
        }
        n = snprintf(out, out_sz,
                     "{\"ok\":true,\"op\":\"emit\",\"data\":{\"lines\":%d}}",
                     lines);
        return (n < 0 || (size_t)n >= out_sz) ? -1 : 0;
    }
    if (strcmp(op, "tcp_poll") == 0) {
        uint32_t maxm = 64;
        int pkts;
        (void)json_get_u32(req_json, "max", &maxm);
        pkts = cpe_agent_tcp_poll(a, maxm);
        if (pkts < 0) {
            return respond_err(out, out_sz, op, "tcp_poll failed");
        }
        n = snprintf(out, out_sz,
                     "{\"ok\":true,\"op\":\"tcp_poll\",\"data\":{\"pkts\":%d}}",
                     pkts);
        return (n < 0 || (size_t)n >= out_sz) ? -1 : 0;
    }
    if (strcmp(op, "tcp_stats") == 0) {
        cpe_tcp_snapshot_t snap;
        float loss;
        if (cpe_agent_tcp_snapshot(a, &snap) != 0) {
            return respond_err(out, out_sz, op, "no tcp state");
        }
        loss = cpe_tcp_loss_hint(snap.syn_total, snap.fin_total, snap.rst_total,
                                 snap.syn_retrans_total);
        n = snprintf(
            out, out_sz,
            "{\"ok\":true,\"op\":\"tcp_stats\",\"data\":{"
            "\"nflog_group\":%u,\"syn\":%u,\"fin\":%u,\"rst\":%u,"
            "\"syn_retrans\":%u,\"pkts\":%u,\"bytes\":%llu,"
            "\"remotes\":%u,\"prefixes\":%u,\"prefix_len\":%u,"
            "\"loss_hint\":%.4f,\"ts\":\"%s\","
            "\"pkts_parsed\":%llu}}",
            (unsigned)snap.nflog_group, (unsigned)snap.syn_total,
            (unsigned)snap.fin_total, (unsigned)snap.rst_total,
            (unsigned)snap.syn_retrans_total, (unsigned)snap.pkt_total,
            (unsigned long long)snap.bytes_total, (unsigned)snap.remote_count,
            (unsigned)snap.prefix_count, (unsigned)snap.prefix_len, (double)loss,
            snap.ts_iso, (unsigned long long)snap.pkts_parsed);
        return (n < 0 || (size_t)n >= out_sz) ? -1 : 0;
    }
    if (strcmp(op, "flow_tick") == 0) {
        int work = cpe_agent_flow_tick(a);
        if (work < 0) {
            return respond_err(out, out_sz, op, "flow_tick failed");
        }
        n = snprintf(out, out_sz,
                     "{\"ok\":true,\"op\":\"flow_tick\",\"data\":{\"work\":%d}}",
                     work);
        return (n < 0 || (size_t)n >= out_sz) ? -1 : 0;
    }
    if (strcmp(op, "flow_stats") == 0) {
        cpe_flow_snapshot_t snap;
        cpe_flow_state_t *fst;
        /* Refresh before reporting. */
        (void)cpe_agent_flow_tick(a);
        if (cpe_agent_flow_snapshot(a, &snap) != 0) {
            return respond_err(out, out_sz, op, "no flow state");
        }
        fst = cpe_agent_flow_state(a);
        n = snprintf(
            out, out_sz,
            "{\"ok\":true,\"op\":\"flow_stats\",\"data\":{"
            "\"enabled\":%s,\"flow_count\":%u,\"events_in\":%llu,"
            "\"destroys_emitted\":%llu,\"samples_emitted\":%llu,"
            "\"dumps\":%llu,\"open_ok\":%s,\"open_err\":%s%s%s,"
            "\"event_fd\":%d,\"dump_fd\":%d,\"ts\":\"%s\"}}",
            (cfg->flow_acct_enabled) ? "true" : "false",
            (unsigned)snap.flow_count, (unsigned long long)snap.events_in,
            (unsigned long long)snap.destroys_emitted,
            (unsigned long long)snap.samples_emitted,
            (unsigned long long)snap.dumps, snap.open_ok ? "true" : "false",
            snap.open_err[0] ? "\"" : "null",
            snap.open_err[0] ? snap.open_err : "",
            snap.open_err[0] ? "\"" : "", fst ? fst->fd : -1,
            fst ? fst->dump_fd : -1, snap.ts_iso);
        return (n < 0 || (size_t)n >= out_sz) ? -1 : 0;
    }
    if (strcmp(op, "flow_list") == 0) {
        cpe_flow_snapshot_t snap;
        uint32_t limit = 32;
        uint32_t i;
        size_t pos;
        int wn;

        (void)json_get_u32(req_json, "limit", &limit);
        if (limit == 0 || limit > 64) {
            limit = 32;
        }
        /* Force poll+dump so ctl sees current conntrack without waiting. */
        (void)cpe_agent_flow_tick(a);
        if (cpe_agent_flow_snapshot(a, &snap) != 0) {
            return respond_err(out, out_sz, op, "no flow state");
        }
        if (!cfg->flow_acct_enabled) {
            n = snprintf(
                out, out_sz,
                "{\"ok\":true,\"op\":\"flow_list\",\"data\":{\"flows\":[],"
                "\"count\":0,\"hint\":\"flow_acct.enabled is false in "
                "cpe_agent.yaml — set true and restart\"}}");
            return (n < 0 || (size_t)n >= out_sz) ? -1 : 0;
        }
        if (!snap.open_ok) {
            n = snprintf(
                out, out_sz,
                "{\"ok\":true,\"op\":\"flow_list\",\"data\":{\"flows\":[],"
                "\"count\":0,\"hint\":\"conntrack netlink open failed: %s "
                "(need CAP_NET_ADMIN / root)\"}}",
                snap.open_err[0] ? snap.open_err : "unknown");
            return (n < 0 || (size_t)n >= out_sz) ? -1 : 0;
        }
        pos = 0;
        wn = snprintf(out + pos, out_sz - pos,
                      "{\"ok\":true,\"op\":\"flow_list\",\"data\":{\"flows\":[");
        if (wn < 0 || (size_t)wn >= out_sz - pos) {
            return -1;
        }
        pos += (size_t)wn;
        for (i = 0; i < snap.flow_count && i < limit; i++) {
            const cpe_flow_entry_t *e = &snap.flows[i];
            wn = snprintf(
                out + pos, out_sz - pos,
                "%s{\"flow_id\":\"%s\",\"proto\":%u,\"lan\":\"%s:%u\","
                "\"remote\":\"%s:%u\",\"wan\":\"%s:%u\","
                "\"bytes_up\":%llu,\"bytes_down\":%llu,"
                "\"rate_up_bps\":%.0f,\"rate_down_bps\":%.0f,"
                "\"state\":\"%s\"}",
                i ? "," : "", e->flow_id, (unsigned)e->proto, e->lan_ip,
                (unsigned)e->lan_port, e->remote_ip, (unsigned)e->remote_port,
                e->wan_ip, (unsigned)e->wan_port,
                (unsigned long long)e->bytes_up,
                (unsigned long long)e->bytes_down, e->rate_up_bps,
                e->rate_down_bps, e->state);
            if (wn < 0 || (size_t)wn >= out_sz - pos) {
                return -1;
            }
            pos += (size_t)wn;
        }
        wn = snprintf(out + pos, out_sz - pos, "],\"count\":%u}}",
                      (unsigned)snap.flow_count);
        return (wn < 0 || (size_t)wn >= out_sz - pos) ? -1 : 0;
    }
    if (strcmp(op, "tcp_by_ip") == 0) {
        char ip[CPE_TCP_IP_MAX];
        cpe_tcp_snapshot_t snap;
        size_t off;
        uint32_t i;
        uint32_t lim;

        ip[0] = '\0';
        (void)json_get_str(req_json, "ip", ip, sizeof(ip));
        if (ip[0]) {
            cpe_tcp_remote_t r;
            if (cpe_agent_tcp_remote(a, ip, &r) != 0) {
                n = snprintf(out, out_sz,
                             "{\"ok\":true,\"op\":\"tcp_by_ip\",\"data\":null}");
                return (n < 0 || (size_t)n >= out_sz) ? -1 : 0;
            }
            off = 0;
            n = snprintf(out, out_sz,
                         "{\"ok\":true,\"op\":\"tcp_by_ip\",\"data\":");
            if (n < 0 || (size_t)n >= out_sz) {
                return -1;
            }
            off = (size_t)n;
            if (append_remote_json(out, out_sz, &off, &r) != 0) {
                return -1;
            }
            if (off + 2 >= out_sz) {
                return -1;
            }
            out[off++] = '}';
            out[off] = '\0';
            return 0;
        }
        if (cpe_agent_tcp_snapshot(a, &snap) != 0) {
            return respond_err(out, out_sz, op, "no tcp state");
        }
        off = 0;
        n = snprintf(out, out_sz, "{\"ok\":true,\"op\":\"tcp_by_ip\",\"data\":[");
        if (n < 0) {
            return -1;
        }
        off = (size_t)n;
        lim = snap.remote_count;
        if (lim > 64) {
            lim = 64;
        }
        for (i = 0; i < lim; i++) {
            if (i > 0) {
                if (off + 1 >= out_sz) {
                    return -1;
                }
                out[off++] = ',';
            }
            if (append_remote_json(out, out_sz, &off, &snap.remotes[i]) != 0) {
                return -1;
            }
        }
        if (off + 3 >= out_sz) {
            return -1;
        }
        out[off++] = ']';
        out[off++] = '}';
        out[off] = '\0';
        return 0;
    }
    if (strcmp(op, "tcp_by_prefix") == 0) {
        char pfx[CPE_TCP_PREFIX_STR_MAX];
        cpe_tcp_snapshot_t snap;
        size_t off;
        uint32_t i;
        uint32_t lim;

        pfx[0] = '\0';
        (void)json_get_str(req_json, "prefix", pfx, sizeof(pfx));
        if (pfx[0]) {
            cpe_tcp_prefix_t p;
            if (cpe_agent_tcp_prefix(a, pfx, &p) != 0) {
                n = snprintf(
                    out, out_sz,
                    "{\"ok\":true,\"op\":\"tcp_by_prefix\",\"data\":null}");
                return (n < 0 || (size_t)n >= out_sz) ? -1 : 0;
            }
            off = 0;
            n = snprintf(out, out_sz,
                         "{\"ok\":true,\"op\":\"tcp_by_prefix\",\"data\":");
            if (n < 0 || (size_t)n >= out_sz) {
                return -1;
            }
            off = (size_t)n;
            if (append_prefix_json(out, out_sz, &off, &p) != 0) {
                return -1;
            }
            if (off + 2 >= out_sz) {
                return -1;
            }
            out[off++] = '}';
            out[off] = '\0';
            return 0;
        }
        if (cpe_agent_tcp_snapshot(a, &snap) != 0) {
            return respond_err(out, out_sz, op, "no tcp state");
        }
        off = 0;
        n = snprintf(out, out_sz,
                     "{\"ok\":true,\"op\":\"tcp_by_prefix\",\"data\":[");
        if (n < 0) {
            return -1;
        }
        off = (size_t)n;
        lim = snap.prefix_count;
        if (lim > 64) {
            lim = 64;
        }
        for (i = 0; i < lim; i++) {
            if (i > 0) {
                if (off + 1 >= out_sz) {
                    return -1;
                }
                out[off++] = ',';
            }
            if (append_prefix_json(out, out_sz, &off, &snap.prefixes[i]) != 0) {
                return -1;
            }
        }
        if (off + 3 >= out_sz) {
            return -1;
        }
        out[off++] = ']';
        out[off++] = '}';
        out[off] = '\0';
        return 0;
    }
    if (strcmp(op, "tcp_emit") == 0) {
        uint32_t top = 0;
        int lines;
        (void)json_get_u32(req_json, "top_n", &top);
        lines = cpe_agent_tcp_emit(a, top);
        if (lines < 0) {
            return respond_err(out, out_sz, op, "tcp_emit failed");
        }
        n = snprintf(out, out_sz,
                     "{\"ok\":true,\"op\":\"tcp_emit\",\"data\":{\"lines\":%d}}",
                     lines);
        return (n < 0 || (size_t)n >= out_sz) ? -1 : 0;
    }
    if (strcmp(op, "tcp_reset") == 0) {
        cpe_agent_tcp_reset(a);
        n = snprintf(out, out_sz,
                     "{\"ok\":true,\"op\":\"tcp_reset\",\"data\":true}");
        return (n < 0 || (size_t)n >= out_sz) ? -1 : 0;
    }

    return respond_err(out, out_sz, op, "unknown op");
}

cpe_ipc_server_t *cpe_ipc_server_create(cpe_agent_t *agent, const char *path,
                                        char *err, size_t err_len)
{
    cpe_ipc_server_t *s;
    struct sockaddr_un sa;
    int fd;
    int i;

    if (!agent) {
        if (err && err_len) {
            snprintf(err, err_len, "null agent");
        }
        return NULL;
    }
    s = (cpe_ipc_server_t *)calloc(1, sizeof(*s));
    if (!s) {
        if (err && err_len) {
            snprintf(err, err_len, "oom");
        }
        return NULL;
    }
    s->agent = agent;
    s->listen_fd = -1;
    for (i = 0; i < CPE_IPC_CLIENTS_MAX; i++) {
        s->clients[i] = -1;
    }
    if (!path || !path[0]) {
        path = CPE_IPC_SOCK_DEFAULT;
    }
    snprintf(s->path, sizeof(s->path), "%s", path);

    (void)mkdir_p_parent(s->path);
    (void)unlink(s->path);

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        if (err && err_len) {
            snprintf(err, err_len, "socket: %s", strerror(errno));
        }
        free(s);
        return NULL;
    }
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    if (strlen(s->path) >= sizeof(sa.sun_path)) {
        if (err && err_len) {
            snprintf(err, err_len, "socket path too long");
        }
        close(fd);
        free(s);
        return NULL;
    }
    memcpy(sa.sun_path, s->path, strlen(s->path) + 1);
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        if (err && err_len) {
            snprintf(err, err_len, "bind %s: %s", s->path, strerror(errno));
        }
        close(fd);
        free(s);
        return NULL;
    }
    (void)chmod(s->path, 0660);
    if (listen(fd, 4) != 0) {
        if (err && err_len) {
            snprintf(err, err_len, "listen: %s", strerror(errno));
        }
        close(fd);
        (void)unlink(s->path);
        free(s);
        return NULL;
    }
    (void)set_nonblock(fd);
    s->listen_fd = fd;
    return s;
}

void cpe_ipc_server_destroy(cpe_ipc_server_t *s)
{
    int i;
    if (!s) {
        return;
    }
    for (i = 0; i < CPE_IPC_CLIENTS_MAX; i++) {
        if (s->clients[i] >= 0) {
            close(s->clients[i]);
            s->clients[i] = -1;
        }
    }
    if (s->listen_fd >= 0) {
        close(s->listen_fd);
        s->listen_fd = -1;
    }
    if (s->path[0]) {
        (void)unlink(s->path);
    }
    free(s);
}

int cpe_ipc_server_fd(const cpe_ipc_server_t *s)
{
    return s ? s->listen_fd : -1;
}

const char *cpe_ipc_server_path(const cpe_ipc_server_t *s)
{
    return s ? s->path : "";
}

static void close_client(cpe_ipc_server_t *s, int idx)
{
    if (idx < 0 || idx >= CPE_IPC_CLIENTS_MAX) {
        return;
    }
    if (s->clients[idx] >= 0) {
        close(s->clients[idx]);
        s->clients[idx] = -1;
    }
    s->rlen[idx] = 0;
}

static int accept_clients(cpe_ipc_server_t *s)
{
    int n = 0;
    for (;;) {
        int cfd;
        int slot = -1;
        int i;
        cfd = accept(s->listen_fd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            break;
        }
        (void)set_nonblock(cfd);
        for (i = 0; i < CPE_IPC_CLIENTS_MAX; i++) {
            if (s->clients[i] < 0) {
                slot = i;
                break;
            }
        }
        if (slot < 0) {
            close(cfd);
            continue;
        }
        s->clients[slot] = cfd;
        s->rlen[slot] = 0;
        n++;
    }
    return n;
}

static int service_client(cpe_ipc_server_t *s, int idx)
{
    char resp[CPE_IPC_LINE_MAX];
    ssize_t rd;
    size_t i;
    int handled = 0;

    if (s->clients[idx] < 0) {
        return 0;
    }
    rd = recv(s->clients[idx], s->rbuf[idx] + s->rlen[idx],
              sizeof(s->rbuf[idx]) - s->rlen[idx] - 1, 0);
    if (rd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        close_client(s, idx);
        return 0;
    }
    if (rd == 0) {
        close_client(s, idx);
        return 0;
    }
    s->rlen[idx] += (size_t)rd;
    s->rbuf[idx][s->rlen[idx]] = '\0';

    /* Process complete lines. */
    for (;;) {
        char *nl = memchr(s->rbuf[idx], '\n', s->rlen[idx]);
        size_t linelen;
        size_t rest;
        if (!nl) {
            if (s->rlen[idx] >= sizeof(s->rbuf[idx]) - 1) {
                close_client(s, idx);
            }
            break;
        }
        linelen = (size_t)(nl - s->rbuf[idx]);
        *nl = '\0';
        if (linelen > 0 && s->rbuf[idx][linelen - 1] == '\r') {
            s->rbuf[idx][linelen - 1] = '\0';
        }
        if (cpe_ipc_handle_request(s->agent, s->rbuf[idx], resp, sizeof(resp)) !=
            0) {
            snprintf(resp, sizeof(resp),
                     "{\"ok\":false,\"op\":\"unknown\",\"error\":\"handler\"}");
        }
        {
            size_t rlen = strlen(resp);
            if (rlen + 1 < sizeof(resp)) {
                resp[rlen] = '\n';
                resp[rlen + 1] = '\0';
                rlen++;
            }
            if (send(s->clients[idx], resp, rlen, MSG_NOSIGNAL) < 0) {
                close_client(s, idx);
                return handled;
            }
        }
        handled++;
        rest = s->rlen[idx] - (linelen + 1);
        if (rest > 0) {
            memmove(s->rbuf[idx], nl + 1, rest);
        }
        s->rlen[idx] = rest;
        s->rbuf[idx][s->rlen[idx]] = '\0';
        (void)i;
    }
    return handled;
}

int cpe_ipc_server_poll(cpe_ipc_server_t *s)
{
    int handled = 0;
    int i;
    if (!s || s->listen_fd < 0) {
        return 0;
    }
    (void)accept_clients(s);
    for (i = 0; i < CPE_IPC_CLIENTS_MAX; i++) {
        if (s->clients[i] >= 0) {
            handled += service_client(s, i);
        }
    }
    return handled;
}
