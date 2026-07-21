/**
 * @file agent_loop.c
 * @brief libuv host loop + SIGHUP reload for CPE agent (P2.2 / field path).
 */

#define _POSIX_C_SOURCE 200809L

#include "cpe_agent.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>

#include <uv.h>

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

static void on_signal_uv(uv_signal_t *handle, int signum)
{
    (void)handle;
    if (signum == SIGHUP) {
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
}

int cpe_agent_hup_take(void)
{
    if (g_hup) {
        g_hup = 0;
        return 1;
    }
    return 0;
}

typedef struct {
    cpe_agent_t *agent;
    uv_timer_t   timer;
    uv_signal_t  sigint;
    uv_signal_t  sigterm;
    uv_signal_t  sighup;
    unsigned     max_ticks;
    unsigned     ticks;
    int          rc;
    const char  *config_path;
    const char  *router_override;
    uint32_t     last_interval_ms;
} cpe_uv_ctx_t;

static void on_timer(uv_timer_t *t);

static void drain_events(cpe_agent_t *a)
{
    cpe_agent_event_t ev;

    while (cpe_agent_next_event(a, &ev) == 1) {
        (void)ev;
    }
}

static void rearm_timer(cpe_uv_ctx_t *ctx)
{
    const cpe_agent_config_t *cfg;
    uint64_t interval;

    if (!ctx || !ctx->agent) {
        return;
    }
    cfg = cpe_agent_config(ctx->agent);
    if (!cfg) {
        return;
    }
    interval = cfg->demo_interval_ms ? cfg->demo_interval_ms : 5000;
    if (interval == ctx->last_interval_ms) {
        return;
    }
    ctx->last_interval_ms = (uint32_t)interval;
    (void)uv_timer_stop(&ctx->timer);
    (void)uv_timer_start(&ctx->timer, on_timer, 0, interval);
}

static void handle_hup(cpe_uv_ctx_t *ctx)
{
    char err[160];

    if (!ctx || !ctx->agent) {
        return;
    }
    if (!cpe_agent_hup_take()) {
        return;
    }
    err[0] = '\0';
    if (cpe_agent_reload_config(ctx->agent, ctx->config_path,
                                ctx->router_override, err, sizeof(err)) != 0) {
        fprintf(stderr, "cpe_agent: HUP reload failed: %s\n",
                err[0] ? err : "unknown");
        drain_events(ctx->agent);
        return;
    }
    drain_events(ctx->agent);
    rearm_timer(ctx);
}

static void on_timer(uv_timer_t *t)
{
    cpe_uv_ctx_t *ctx = (cpe_uv_ctx_t *)t->data;
    const cpe_agent_config_t *cfg;

    if (!ctx || !ctx->agent) {
        return;
    }
    if (g_stop) {
        uv_stop(t->loop);
        return;
    }

    handle_hup(ctx);

    cfg = cpe_agent_config(ctx->agent);
    if (cfg) {
        if (cpe_agent_sample_tick(ctx->agent) == 0) {
            if (cpe_agent_emit_flush(ctx->agent) < 0) {
                fprintf(stderr, "cpe_agent: emit_flush failed\n");
            }
        } else {
            fprintf(stderr, "cpe_agent: sample_tick failed (demo=%d)\n",
                    cfg->demo_mode);
        }
        drain_events(ctx->agent);
        ctx->ticks++;
        if (ctx->max_ticks > 0 && ctx->ticks >= ctx->max_ticks) {
            uv_stop(t->loop);
        }
    }
}

int cpe_agent_run_uv(cpe_agent_t *a, const cpe_agent_run_opts_t *opts)
{
    uv_loop_t *loop;
    cpe_uv_ctx_t ctx;
    const cpe_agent_config_t *cfg;
    uint64_t interval;
    cpe_agent_run_opts_t local;

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

    memset(&ctx, 0, sizeof(ctx));
    ctx.agent = a;
    ctx.max_ticks = opts->max_ticks;
    ctx.config_path = opts->config_path;
    ctx.router_override = opts->router_id_override;
    g_stop = 0;
    g_hup = 0;

    loop = uv_default_loop();
    if (!loop) {
        return 1;
    }

    if (uv_timer_init(loop, &ctx.timer) != 0) {
        return 1;
    }
    ctx.timer.data = &ctx;
    interval = cfg->demo_interval_ms ? cfg->demo_interval_ms : 5000;
    ctx.last_interval_ms = (uint32_t)interval;
    if (uv_timer_start(&ctx.timer, on_timer, 10, interval) != 0) {
        return 1;
    }

    if (uv_signal_init(loop, &ctx.sigint) == 0) {
        (void)uv_signal_start(&ctx.sigint, on_signal_uv, SIGINT);
    }
    if (uv_signal_init(loop, &ctx.sigterm) == 0) {
        (void)uv_signal_start(&ctx.sigterm, on_signal_uv, SIGTERM);
    }
    if (uv_signal_init(loop, &ctx.sighup) == 0) {
        (void)uv_signal_start(&ctx.sighup, on_signal_uv, SIGHUP);
    }

    cpe_agent_hup_install();
    (void)uv_run(loop, UV_RUN_DEFAULT);

    uv_close((uv_handle_t *)&ctx.timer, NULL);
    uv_close((uv_handle_t *)&ctx.sigint, NULL);
    uv_close((uv_handle_t *)&ctx.sigterm, NULL);
    uv_close((uv_handle_t *)&ctx.sighup, NULL);
    (void)uv_run(loop, UV_RUN_DEFAULT);

    return ctx.rc;
}
