/**
 * @file agent_loop_poll.c
 * @brief Portable host loop without libuv (OpenWrt / aarch64 cross / LXC EE).
 *
 * Used when CPE_AGENT_HAVE_LIBUV is not defined. Same HUP/sample/emit behavior
 * as agent_loop.c (libuv).
 */

#define _POSIX_C_SOURCE 200809L

#include "cpe_agent.h"
#include "cpe_ipc.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t g_hup;
static volatile sig_atomic_t g_stop;

static void hup_handler(int sig)
{
    if (sig == SIGHUP) {
        g_hup = 1;
    } else {
        g_stop = 1;
    }
}

void cpe_agent_hup_install(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = hup_handler;
    sigemptyset(&sa.sa_mask);
    (void)sigaction(SIGHUP, &sa, NULL);
    (void)sigaction(SIGINT, &sa, NULL);
    (void)sigaction(SIGTERM, &sa, NULL);
}

int cpe_agent_hup_take(void)
{
    if (g_hup) {
        g_hup = 0;
        return 1;
    }
    return 0;
}

static void drain_events(cpe_agent_t *a)
{
    cpe_agent_event_t ev;

    while (cpe_agent_next_event(a, &ev) == 1) {
        (void)ev;
    }
}

static void handle_hup(cpe_agent_t *a, const char *config_path,
                       const char *router_override)
{
    char err[160];

    if (!cpe_agent_hup_take()) {
        return;
    }
    err[0] = '\0';
    if (cpe_agent_reload_config(a, config_path, router_override, err,
                                sizeof(err)) != 0) {
        fprintf(stderr, "cpe_agent: HUP reload failed: %s\n",
                err[0] ? err : "unknown");
        drain_events(a);
        return;
    }
    drain_events(a);
}

static void msleep(uint32_t ms)
{
    struct timespec ts;

    ts.tv_sec = (time_t)(ms / 1000u);
    ts.tv_nsec = (long)(ms % 1000u) * 1000000L;
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
        if (g_stop) {
            return;
        }
    }
}

int cpe_agent_run_uv(cpe_agent_t *a, const cpe_agent_run_opts_t *opts)
{
    const cpe_agent_config_t *cfg;
    cpe_agent_run_opts_t local;
    cpe_ipc_server_t *ipc = NULL;
    unsigned ticks = 0;
    uint32_t interval;
    uint32_t ipc_slice;

    if (!a) {
        return 1;
    }
    if (!opts) {
        memset(&local, 0, sizeof(local));
        opts = &local;
    }
    cfg = cpe_agent_config(a);
    if (!cfg) {
        return 1;
    }

    g_stop = 0;
    g_hup = 0;
    cpe_agent_hup_install();

    if (!opts->ipc_disable) {
        const char *ipath = opts->ipc_socket_override;
        char ierr[160];
        if (!ipath || !ipath[0]) {
            ipath = cfg->ipc_socket;
        }
        if (ipath && ipath[0] && strcmp(ipath, "off") != 0 &&
            strcmp(ipath, "none") != 0) {
            ierr[0] = '\0';
            ipc = cpe_ipc_server_create(a, ipath, ierr, sizeof(ierr));
            if (!ipc) {
                fprintf(stderr, "cpe_agent: ipc listen failed (%s): %s\n",
                        ipath, ierr[0] ? ierr : "error");
            } else {
                fprintf(stderr, "cpe_agent: control socket %s\n",
                        cpe_ipc_server_path(ipc));
            }
        }
    }

    interval = cfg->demo_interval_ms ? cfg->demo_interval_ms : 5000;
    /* First sample soon after start (mirrors libuv 10 ms first fire). */
    msleep(10);

    while (!g_stop) {
        handle_hup(a, opts->config_path, opts->router_id_override);
        cfg = cpe_agent_config(a);
        if (cfg) {
            interval = cfg->demo_interval_ms ? cfg->demo_interval_ms : 5000;
            if (cpe_agent_sample_tick(a) == 0) {
                if (cpe_agent_emit_flush(a) < 0) {
                    fprintf(stderr, "cpe_agent: emit_flush failed\n");
                }
            } else {
                fprintf(stderr, "cpe_agent: sample_tick failed (demo=%d)\n",
                        cfg->demo_mode);
            }
            if (cfg->tcp_stats_enabled) {
                if (cpe_agent_tcp_tick(a) > 0) {
                    if (cpe_agent_emit_flush(a) < 0) {
                        fprintf(stderr, "cpe_agent: tcp emit_flush failed\n");
                    }
                }
            }
            if (ipc) {
                (void)cpe_ipc_server_poll(ipc);
            }
            drain_events(a);
            ticks++;
            if (opts->max_ticks > 0 && ticks >= opts->max_ticks) {
                break;
            }
        }
        /* Slice sleep so UDS + flow_acct stay responsive between samples. */
        ipc_slice = 200;
        {
            uint32_t left = interval;
            while (left > 0 && !g_stop) {
                uint32_t step = left > ipc_slice ? ipc_slice : left;
                msleep(step);
                if (ipc) {
                    (void)cpe_ipc_server_poll(ipc);
                }
                cfg = cpe_agent_config(a);
                if (cfg && cfg->flow_acct_enabled) {
                    if (cpe_agent_flow_tick(a) > 0) {
                        if (cpe_agent_emit_flush(a) < 0) {
                            fprintf(stderr,
                                    "cpe_agent: flow emit_flush failed\n");
                        }
                    }
                }
                left -= step;
            }
        }
    }
    cpe_ipc_server_destroy(ipc);
    return 0;
}
