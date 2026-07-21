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
    c->demo_interval_ms = 5000;
    c->sample_interval_ms = 5000;
    c->probe_timeout_ms = 1000;
    c->demo_mode = 1;
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
        strcmp(c->emit_mode, "https") != 0) {
        if (err && err_len) {
            snprintf(err, err_len, "emit.mode must be stdout|spool|https");
        }
        return -1;
    }
    if (strcmp(c->emit_mode, "spool") == 0 && c->spool_path[0] == '\0') {
        if (err && err_len) {
            snprintf(err, err_len, "emit.mode=spool requires emit.path");
        }
        return -1;
    }
    if (strcmp(c->emit_mode, "https") == 0 && c->https_url[0] == '\0') {
        if (err && err_len) {
            snprintf(err, err_len, "emit.mode=https requires egress.url");
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
