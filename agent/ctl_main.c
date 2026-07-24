/**
 * @file ctl_main.c
 * @brief cpe_ctl — human/AI interactive front-end to cpe_agent daemon (UDS).
 *
 * Does not collect packets itself; queries the daemon control socket and
 * optionally runs Lua scripts against remote statistics.
 */

#include "cpe_ctl_lua.h"
#include "cpe_ipc.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s [options] [op]\n"
            "\n"
            "Interactive / scripted client for the cpe_agent daemon.\n"
            "The daemon collects stats and POSTs NDJSON to edgehost (ClickHouse\n"
            "proxy). This binary only queries the daemon over a Unix socket.\n"
            "\n"
            "Options:\n"
            "  --socket PATH     daemon UDS (default %s)\n"
            "  --lua / --repl    interactive Lua REPL\n"
            "  --lua-eval SRC    run one Lua chunk\n"
            "  --lua-file PATH   run a Lua script\n"
            "  --history PATH    REPL history (default /tmp/cpe_ctl_history)\n"
            "  --help\n"
            "\n"
            "One-shot ops (no Lua):\n"
            "  status | config | tcp_stats | tcp_by_ip [IP] | tcp_by_prefix [CIDR]\n"
            "  last_sample | spool | emit | ping | help\n"
            "\n"
            "Examples:\n"
            "  %s status\n"
            "  %s tcp_stats\n"
            "  %s --lua\n"
            "  %s --lua-eval \"print(cpe.tcp_stats().loss_hint)\"\n",
            argv0, CPE_IPC_SOCK_DEFAULT, argv0, argv0, argv0, argv0);
}

static int oneshot(const char *sock, const char *op, const char *arg)
{
    char req[256];
    char resp[CPE_IPC_LINE_MAX];
    char err[160];

    if (strcmp(op, "status") == 0 || strcmp(op, "config") == 0 ||
        strcmp(op, "ping") == 0 || strcmp(op, "help") == 0 ||
        strcmp(op, "last_sample") == 0 || strcmp(op, "latency") == 0 ||
        strcmp(op, "spool") == 0 || strcmp(op, "emit") == 0 ||
        strcmp(op, "tcp_stats") == 0 || strcmp(op, "tcp_reset") == 0) {
        snprintf(req, sizeof(req), "{\"op\":\"%s\"}", op);
    } else if (strcmp(op, "tcp_by_ip") == 0) {
        if (arg && arg[0]) {
            snprintf(req, sizeof(req), "{\"op\":\"tcp_by_ip\",\"ip\":\"%s\"}",
                     arg);
        } else {
            snprintf(req, sizeof(req), "{\"op\":\"tcp_by_ip\"}");
        }
    } else if (strcmp(op, "tcp_by_prefix") == 0) {
        if (arg && arg[0]) {
            snprintf(req, sizeof(req),
                     "{\"op\":\"tcp_by_prefix\",\"prefix\":\"%s\"}", arg);
        } else {
            snprintf(req, sizeof(req), "{\"op\":\"tcp_by_prefix\"}");
        }
    } else if (strcmp(op, "tcp_poll") == 0) {
        snprintf(req, sizeof(req), "{\"op\":\"tcp_poll\",\"max\":%s}",
                 arg && arg[0] ? arg : "64");
    } else if (strcmp(op, "tcp_emit") == 0) {
        snprintf(req, sizeof(req), "{\"op\":\"tcp_emit\",\"top_n\":%s}",
                 arg && arg[0] ? arg : "20");
    } else {
        fprintf(stderr, "unknown op: %s\n", op);
        return 1;
    }

    err[0] = '\0';
    if (cpe_ipc_client_request(sock, req, resp, sizeof(resp), err,
                               sizeof(err)) != 0) {
        fprintf(stderr, "cpe_ctl: %s\n", err[0] ? err : "request failed");
        return 1;
    }
    printf("%s\n", resp);
    return 0;
}

int main(int argc, char **argv)
{
    const char *sock = CPE_IPC_SOCK_DEFAULT;
    const char *history = NULL;
    const char *lua_eval = NULL;
    const char *lua_file = NULL;
    int lua_repl = 0;
    int opt;
    int rc = 0;

    static struct option long_opts[] = {
        {"socket", required_argument, 0, 's'},
        {"lua", no_argument, 0, 'i'},
        {"repl", no_argument, 0, 'i'},
        {"lua-eval", required_argument, 0, 'e'},
        {"lua-file", required_argument, 0, 'f'},
        {"history", required_argument, 0, 'H'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "s:ie:f:H:h", long_opts, NULL)) !=
           -1) {
        switch (opt) {
        case 's':
            sock = optarg;
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
            history = optarg;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (lua_repl || lua_eval || lua_file) {
        cpe_ctl_lua_t *L;
        char err[256];

        L = cpe_ctl_lua_create(sock);
        if (!L) {
            fprintf(stderr,
                    "cpe_ctl: Lua unavailable (rebuild with "
                    "-DCPE_AGENT_WITH_LUA=ON)\n");
            return 1;
        }
        if (lua_file) {
            err[0] = '\0';
            if (cpe_ctl_lua_dofile(L, lua_file, err, sizeof(err)) != 0) {
                fprintf(stderr, "cpe_ctl: %s\n", err[0] ? err : "dofile");
                rc = 1;
            }
        }
        if (rc == 0 && lua_eval) {
            err[0] = '\0';
            if (cpe_ctl_lua_dostring(L, lua_eval, err, sizeof(err)) != 0) {
                fprintf(stderr, "cpe_ctl: %s\n", err[0] ? err : "eval");
                rc = 1;
            }
        }
        if (rc == 0 && lua_repl) {
            rc = cpe_ctl_lua_repl(L, history);
        }
        cpe_ctl_lua_destroy(L);
        return rc;
    }

    if (optind < argc) {
        const char *op = argv[optind];
        const char *arg = (optind + 1 < argc) ? argv[optind + 1] : NULL;
        return oneshot(sock, op, arg);
    }

    /* Default: short status then drop into REPL if Lua available. */
    {
        char resp[CPE_IPC_LINE_MAX];
        char err[160];
        err[0] = '\0';
        if (cpe_ipc_client_request(sock, "{\"op\":\"status\"}", resp,
                                   sizeof(resp), err, sizeof(err)) != 0) {
            fprintf(stderr, "cpe_ctl: %s\n", err[0] ? err : "connect failed");
            fprintf(stderr,
                    "Start the daemon first, e.g.:\n"
                    "  cpe_agent --config /etc/cpe_agent/cpe_agent.yaml\n");
            return 1;
        }
        printf("%s\n", resp);
    }

    {
        cpe_ctl_lua_t *L = cpe_ctl_lua_create(sock);
        if (!L) {
            return 0; /* status already printed */
        }
        rc = cpe_ctl_lua_repl(L, history);
        cpe_ctl_lua_destroy(L);
        return rc;
    }
}
