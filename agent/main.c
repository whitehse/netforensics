/**
 * @file main.c
 * @brief cpe_agent process entry — libuv host (Track 2 + field path).
 *
 * Does not replace forensicsd; co-exists for perf samples (N-A05).
 */

#include "cpe_agent.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s [--config PATH] [--router-id ID] [--demo] [--once]\n"
            "  --config      YAML path (optional; defaults if omitted)\n"
            "  --router-id   override router_id (preserved across SIGHUP)\n"
            "  --demo        force demo_mode (synthetic ping → cpe_perf NDJSON)\n"
            "  --once        emit one sample then exit (tests / lab)\n"
            "  --help\n"
            "\n"
            "forensicsd remains the conntrack/wifi NDJSON daemon (ADR-002).\n"
            "This agent emits type=cpe_perf performance samples (N-A05).\n"
            "emit.mode=spool appends to emit.path; SIGHUP reloads --config.\n",
            argv0);
}

int main(int argc, char **argv)
{
    const char *config_path = NULL;
    const char *router_override = NULL;
    int force_demo = 0;
    int once = 0;
    cpe_agent_config_t cfg;
    cpe_agent_t *agent;
    cpe_agent_event_t ev;
    cpe_agent_run_opts_t run_opts;
    char err[160];
    int opt;
    int rc;

    static struct option long_opts[] = {
        {"config", required_argument, 0, 'c'},
        {"router-id", required_argument, 0, 'r'},
        {"demo", no_argument, 0, 'd'},
        {"once", no_argument, 0, '1'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "c:r:d1h", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'c':
            config_path = optarg;
            break;
        case 'r':
            router_override = optarg;
            break;
        case 'd':
            force_demo = 1;
            break;
        case '1':
            once = 1;
            break;
        case 'h':
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }

    agent = cpe_agent_create();
    if (!agent) {
        fprintf(stderr, "cpe_agent: create failed\n");
        return 1;
    }

    err[0] = '\0';
    if (cpe_agent_reload_config(agent, config_path, router_override, err,
                                sizeof(err)) != 0) {
        fprintf(stderr, "cpe_agent: config load/apply failed: %s\n",
                err[0] ? err : "unknown");
        while (cpe_agent_next_event(agent, &ev) == 1) {
            fprintf(stderr, "  event %s: %s\n",
                    cpe_agent_event_type_name(ev.type), ev.reason);
        }
        cpe_agent_destroy(agent);
        return 1;
    }

    /* Optional CLI force of demo after YAML apply. */
    if (force_demo || once) {
        cfg = *cpe_agent_config(agent);
        cfg.demo_mode = 1;
        if (cpe_agent_apply_config(agent, &cfg) != 0) {
            fprintf(stderr, "cpe_agent: force demo apply rejected\n");
            cpe_agent_destroy(agent);
            return 1;
        }
    }
    while (cpe_agent_next_event(agent, &ev) == 1) {
        /* drain CONFIG_APPLIED */
    }

    if (once) {
        if (cpe_agent_demo_ping_tick(agent) != 0) {
            fprintf(stderr, "cpe_agent: demo tick failed\n");
            cpe_agent_destroy(agent);
            return 1;
        }
        if (cpe_agent_emit_flush(agent) < 0) {
            fprintf(stderr, "cpe_agent: emit_flush failed\n");
            cpe_agent_destroy(agent);
            return 1;
        }
        while (cpe_agent_next_event(agent, &ev) == 1) {
        }
        cpe_agent_destroy(agent);
        return 0;
    }

    memset(&run_opts, 0, sizeof(run_opts));
    run_opts.max_ticks = 0;
    run_opts.config_path = config_path;
    run_opts.router_id_override = router_override;
    rc = cpe_agent_run_uv(agent, &run_opts);
    cpe_agent_destroy(agent);
    return rc;
}
