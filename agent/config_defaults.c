/**
 * @file config_defaults.c
 * @brief cpe_agent_config defaults + validate (shared; no I/O).
 */

#include "cpe_agent_config.h"
#include "cpe_spool.h"

#include <stdio.h>
#include <string.h>

void cpe_agent_config_defaults(cpe_agent_config_t *c)
{
    if (!c) {
        return;
    }
    memset(c, 0, sizeof(*c));
    snprintf(c->router_id, sizeof(c->router_id), "cpe-lab-1");
    snprintf(c->emit_mode, sizeof(c->emit_mode), "stdout");
    snprintf(c->spool_path, sizeof(c->spool_path), "%s", CPE_SPOOL_PERF_DEFAULT);
    c->spool_max_lines = CPE_CFG_SPOOL_DEFAULT;
    snprintf(c->demo_target, sizeof(c->demo_target), "1.1.1.1");
    c->arping_if[0] = '\0'; /* auto-detect */
    c->wifi_if[0] = '\0';   /* auto-detect wireless iface */
    c->demo_interval_ms = 5000;
    c->sample_interval_ms = 5000;
    c->probe_timeout_ms = 1000;
    c->demo_mode = 1;
    c->egress_tls_insecure = 1; /* soft TLS until ca_file is set */
    c->tcp_stats_enabled = 0;
    c->tcp_nflog_group = 5;
    c->tcp_nflog_size = 60;
    c->tcp_emit_interval_ms = 10000;
    c->tcp_emit_top_n = 20;
    c->tcp_prefix_len = 24;
    snprintf(c->ipc_socket, sizeof(c->ipc_socket),
             "/var/run/netforensics/cpe_agent.sock");
    c->openai_proxy_url[0] = '\0';
    c->postgres_proxy_url[0] = '\0';
    c->generation = 0;
}

int cpe_agent_config_validate(const cpe_agent_config_t *c, char *err,
                              size_t err_len)
{
    if (!c) {
        if (err && err_len) {
            snprintf(err, err_len, "null config");
        }
        return -1;
    }
    if (c->router_id[0] == '\0') {
        if (err && err_len) {
            snprintf(err, err_len, "router_id empty");
        }
        return -1;
    }
    if (strcmp(c->emit_mode, "stdout") != 0 &&
        strcmp(c->emit_mode, "spool") != 0 &&
        strcmp(c->emit_mode, "http") != 0 &&
        strcmp(c->emit_mode, "https") != 0) {
        if (err && err_len) {
            snprintf(err, err_len,
                     "emit.mode must be stdout|spool|http|https");
        }
        return -1;
    }
    if (strcmp(c->emit_mode, "spool") == 0 && c->spool_path[0] == '\0') {
        if (err && err_len) {
            snprintf(err, err_len, "emit.mode=spool requires emit.path");
        }
        return -1;
    }
    if ((strcmp(c->emit_mode, "http") == 0 ||
         strcmp(c->emit_mode, "https") == 0) &&
        c->https_url[0] == '\0') {
        if (err && err_len) {
            snprintf(err, err_len,
                     "emit.mode=%s requires egress.url", c->emit_mode);
        }
        return -1;
    }
    if (c->spool_max_lines == 0) {
        if (err && err_len) {
            snprintf(err, err_len, "spool_max_lines must be > 0");
        }
        return -1;
    }
    if (c->spool_max_lines > CPE_SPOOL_MAX_LINES_HARD) {
        if (err && err_len) {
            snprintf(err, err_len, "spool_max_lines exceeds hard cap %d",
                     CPE_SPOOL_MAX_LINES_HARD);
        }
        return -1;
    }
    if (c->demo_interval_ms == 0 && c->sample_interval_ms == 0) {
        if (err && err_len) {
            snprintf(err, err_len, "interval_ms must be > 0");
        }
        return -1;
    }
    if (c->demo_target[0] == '\0') {
        if (err && err_len) {
            snprintf(err, err_len, "probe target empty");
        }
        return -1;
    }
    return 0;
}
