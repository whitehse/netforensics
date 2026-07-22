/**
 * @file main.c
 * @brief cpe_agent process entry — timer host / Lua REPL (Track 2 + field path).
 *
 * Does not replace forensicsd; co-exists for perf samples (N-A05).
 */

#include "cpe_agent.h"
#include "cpe_agent_lua.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s [options]\n"
            "  --config PATH     YAML path (optional; defaults if omitted)\n"
            "  --router-id ID    override router_id (preserved across SIGHUP)\n"
            "  --demo            force demo_mode (synthetic ping → cpe_perf)\n"
            "  --once            emit one demo sample then exit\n"
            "  --lua / --repl    interactive Lua REPL (linenoise history)\n"
            "  --lua-eval SRC    run one Lua chunk then exit\n"
            "  --lua-file PATH   run a Lua tool script then exit\n"
            "  --history PATH    REPL history file (default ~/.cpe_agent_history)\n"
            "  --help\n"
            "\n"
            "forensicsd remains the conntrack/wifi NDJSON daemon (ADR-002).\n"
            "This agent emits type=cpe_perf performance samples (N-A05).\n"
            "emit.mode=spool appends to emit.path; SIGHUP reloads --config.\n"
            "Lua tools: see docs/guides/cpe-agent-lua.md  (cpe.help() in REPL).\n",
            argv0);
}

int main(int argc, char **argv)
{
    const char *config_path = NULL;
    const char *router_override = NULL;
    const char *history_path = NULL;
    const char *lua_eval = NULL;
    const char *lua_file = NULL;
    int force_demo = 0;
    int once = 0;
    int lua_repl = 0;
    cpe_agent_config_t cfg;
    cpe_agent_t *agent;
    cpe_agent_event_t ev;
    cpe_agent_run_opts_t run_opts;
    cpe_lua_t *lua = NULL;
    char err[256];
    int opt;
    int rc = 0;

    static struct option long_opts[] = {
        {"config", required_argument, 0, 'c'},
        {"router-id", required_argument, 0, 'r'},
        {"demo", no_argument, 0, 'd'},
        {"once", no_argument, 0, '1'},
        {"lua", no_argument, 0, 'i'},
        {"repl", no_argument, 0, 'i'},
        {"lua-eval", required_argument, 0, 'e'},
        {"lua-file", required_argument, 0, 'f'},
        {"history", required_argument, 0, 'H'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "c:r:d1ie:f:H:h", long_opts, NULL)) !=
           -1) {
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
        case 'i':
            lua_repl = 1;
            break;
        case 'e':
            lua_eval = optarg;
            break;
        case 'f':
            lua_file = optarg;
            break;
        case 'H':
            history_path = optarg;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
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

    if (lua_repl || lua_eval || lua_file) {
        lua = cpe_lua_create(agent);
        if (!lua) {
            fprintf(stderr,
                    "cpe_agent: Lua unavailable (rebuild with "
                    "-DCPE_AGENT_WITH_LUA=ON)\n");
            cpe_agent_destroy(agent);
            return 1;
        }
        if (lua_file) {
            err[0] = '\0';
            if (cpe_lua_dofile(lua, lua_file, err, sizeof(err)) != 0) {
                fprintf(stderr, "cpe_agent: lua-file: %s\n",
                        err[0] ? err : "error");
                rc = 1;
            }
        }
        if (rc == 0 && lua_eval) {
            err[0] = '\0';
            if (cpe_lua_dostring(lua, lua_eval, err, sizeof(err)) != 0) {
                fprintf(stderr, "cpe_agent: lua-eval: %s\n",
                        err[0] ? err : "error");
                rc = 1;
            }
        }
        if (rc == 0 && lua_repl) {
            rc = cpe_lua_repl(lua, history_path);
        }
        cpe_lua_destroy(lua);
        cpe_agent_destroy(agent);
        return rc;
    }

    memset(&run_opts, 0, sizeof(run_opts));
    run_opts.max_ticks = 0;
    run_opts.config_path = config_path;
    run_opts.router_id_override = router_override;
    rc = cpe_agent_run_uv(agent, &run_opts);
    cpe_agent_destroy(agent);
    return rc;
}
