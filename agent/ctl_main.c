/**
 * @file ctl_main.c
 * @brief cpe_ctl — human/AI interactive front-end to cpe_agent daemon (UDS)
 *        and optional ClickHouse historical flow queries.
 *
 * Live stats: Unix socket to cpe_agent.
 * Historical flows: ClickHouse HTTP (ops/lab host; not the field CPE path).
 */

#include "cpe_ctl_ch.h"
#include "cpe_ctl_lua.h"
#include "cpe_ipc.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *sock;
    const char *ch_url;
    const char *ch_user;
    const char *ch_password;
    const char *ch_table;
    const char *router_id;
    unsigned    limit;
    int         history; /* 1 = query ClickHouse */
    int         raw;     /* print raw JSONEachRow */
} ctl_opts_t;

static void usage(const char *argv0)
{
    fprintf(
        stderr,
        "Usage: %s [options] [op] [arg]\n"
        "\n"
        "Client for the cpe_agent daemon (Unix socket) and optional\n"
        "ClickHouse historical flow queries (ops/lab hosts).\n"
        "\n"
        "Options:\n"
        "  --socket PATH        daemon UDS (default %s)\n"
        "  --history            list historical flows from ClickHouse\n"
        "  --ch-url URL         ClickHouse HTTP base (default $CPE_CH_URL or\n"
        "                       http://127.0.0.1:8123)\n"
        "  --ch-user USER       CH user (default $CPE_CH_USER or default)\n"
        "  --ch-password PASS   CH password (default $CPE_CH_PASSWORD)\n"
        "  --ch-table TABLE     flows table (default edgehost.cpe_flows)\n"
        "  --router-id ID       filter flows by CPE router_id\n"
        "  --limit N            max rows (default 50 history / 32 live)\n"
        "  --raw                print raw JSONEachRow (history only)\n"
        "  --lua / --repl       interactive Lua REPL (daemon)\n"
        "  --lua-eval SRC       run one Lua chunk\n"
        "  --lua-file PATH      run a Lua script\n"
        "  --history-file PATH  REPL history (default /tmp/cpe_ctl_history)\n"
        "  --help\n"
        "\n"
        "One-shot ops (daemon UDS unless --history):\n"
        "  status | config | tcp_stats | tcp_by_ip [IP] | tcp_by_prefix [CIDR]\n"
        "  flow_stats | flow_list [limit] | flow_tick | flows\n"
        "  last_sample | spool | emit | ping | help\n"
        "\n"
        "Flow listing:\n"
        "  %s flow_list                  live table from cpe_agent\n"
        "  %s flow_list --history        historical rows from ClickHouse\n"
        "  %s flows --history --router-id cpe-42 --limit 20\n"
        "\n"
        "Examples:\n"
        "  %s status\n"
        "  %s tcp_stats\n"
        "  %s flow_list\n"
        "  %s flow_list --history --ch-password passw0rd\n"
        "  CPE_CH_PASSWORD=passw0rd %s flows --history --router-id lab-cpe-1\n"
        "  %s --lua\n",
        argv0, CPE_IPC_SOCK_DEFAULT, argv0, argv0, argv0, argv0, argv0, argv0,
        argv0, argv0, argv0);
}

static int oneshot_daemon(const char *sock, const char *op, const char *arg,
                          unsigned limit)
{
    char req[256];
    char resp[CPE_IPC_LINE_MAX];
    char err[160];
    char limbuf[16];

    if (strcmp(op, "status") == 0 || strcmp(op, "config") == 0 ||
        strcmp(op, "ping") == 0 || strcmp(op, "help") == 0 ||
        strcmp(op, "last_sample") == 0 || strcmp(op, "latency") == 0 ||
        strcmp(op, "spool") == 0 || strcmp(op, "emit") == 0 ||
        strcmp(op, "tcp_stats") == 0 || strcmp(op, "tcp_reset") == 0 ||
        strcmp(op, "flow_stats") == 0 || strcmp(op, "flow_tick") == 0) {
        snprintf(req, sizeof(req), "{\"op\":\"%s\"}", op);
    } else if (strcmp(op, "flow_list") == 0 || strcmp(op, "flows") == 0) {
        if (arg && arg[0]) {
            snprintf(req, sizeof(req), "{\"op\":\"flow_list\",\"limit\":%s}",
                     arg);
        } else {
            snprintf(limbuf, sizeof(limbuf), "%u", limit ? limit : 32u);
            snprintf(req, sizeof(req), "{\"op\":\"flow_list\",\"limit\":%s}",
                     limbuf);
        }
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

static int oneshot_history(const ctl_opts_t *o, const char *arg)
{
    cpe_ctl_ch_opts_t ch;
    char *body;
    char err[256];
    unsigned limit = o->limit ? o->limit : 50u;
    const char *env_url;
    const char *env_user;
    const char *env_pass;
    int rc;

    if (arg && arg[0]) {
        limit = (unsigned)atoi(arg);
        if (limit == 0) {
            limit = 50;
        }
    }

    env_url = getenv("CPE_CH_URL");
    env_user = getenv("CPE_CH_USER");
    env_pass = getenv("CPE_CH_PASSWORD");

    memset(&ch, 0, sizeof(ch));
    ch.url = o->ch_url ? o->ch_url : (env_url && env_url[0] ? env_url : NULL);
    ch.user =
        o->ch_user ? o->ch_user : (env_user && env_user[0] ? env_user : NULL);
    ch.password = o->ch_password
                      ? o->ch_password
                      : (env_pass && env_pass[0] ? env_pass : NULL);
    ch.table = o->ch_table;
    ch.router_id = o->router_id;
    ch.limit = limit;

    body = (char *)malloc(512 * 1024);
    if (!body) {
        fprintf(stderr, "cpe_ctl: oom\n");
        return 1;
    }
    err[0] = '\0';
    rc = cpe_ctl_ch_query_flows(&ch, body, 512 * 1024, err, sizeof(err));
    if (rc != 0) {
        fprintf(stderr, "cpe_ctl: ClickHouse query failed: %s\n",
                err[0] ? err : "error");
        fprintf(stderr,
                "Hint: set --ch-url/--ch-password or CPE_CH_URL / "
                "CPE_CH_PASSWORD\n"
                "  e.g. %s flow_list --history --ch-password passw0rd\n",
                "cpe_ctl");
        free(body);
        return 1;
    }
    if (o->raw) {
        fputs(body, stdout);
        if (body[0] && body[strlen(body) - 1] != '\n') {
            fputc('\n', stdout);
        }
    } else {
        (void)cpe_ctl_ch_print_flows(body);
    }
    free(body);
    return 0;
}

int main(int argc, char **argv)
{
    ctl_opts_t o;
    const char *history = NULL;
    const char *lua_eval = NULL;
    const char *lua_file = NULL;
    int lua_repl = 0;
    int opt;
    int rc = 0;

    memset(&o, 0, sizeof(o));
    o.sock = CPE_IPC_SOCK_DEFAULT;

    static struct option long_opts[] = {
        {"socket", required_argument, 0, 's'},
        {"history", no_argument, 0, 'y'},
        {"ch-url", required_argument, 0, 'U'},
        {"ch-user", required_argument, 0, 'u'},
        {"ch-password", required_argument, 0, 'P'},
        {"ch-table", required_argument, 0, 'T'},
        {"router-id", required_argument, 0, 'r'},
        {"limit", required_argument, 0, 'n'},
        {"raw", no_argument, 0, 'R'},
        {"lua", no_argument, 0, 'i'},
        {"repl", no_argument, 0, 'i'},
        {"lua-eval", required_argument, 0, 'e'},
        {"lua-file", required_argument, 0, 'f'},
        {"history-file", required_argument, 0, 'H'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}};

    while ((opt = getopt_long(argc, argv, "s:yU:u:P:T:r:n:Rie:f:H:h", long_opts,
                              NULL)) != -1) {
        switch (opt) {
        case 's':
            o.sock = optarg;
            break;
        case 'y':
            o.history = 1;
            break;
        case 'U':
            o.ch_url = optarg;
            break;
        case 'u':
            o.ch_user = optarg;
            break;
        case 'P':
            o.ch_password = optarg;
            break;
        case 'T':
            o.ch_table = optarg;
            break;
        case 'r':
            o.router_id = optarg;
            break;
        case 'n':
            o.limit = (unsigned)atoi(optarg);
            break;
        case 'R':
            o.raw = 1;
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

        L = cpe_ctl_lua_create(o.sock);
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

        if (strcmp(op, "flow_list") == 0 || strcmp(op, "flows") == 0 ||
            strcmp(op, "flow_history") == 0) {
            if (o.history || strcmp(op, "flow_history") == 0) {
                return oneshot_history(&o, arg);
            }
            return oneshot_daemon(o.sock, "flow_list", arg, o.limit);
        }
        if (o.history) {
            fprintf(stderr,
                    "cpe_ctl: --history only applies to flow_list / flows\n");
            return 1;
        }
        return oneshot_daemon(o.sock, op, arg, o.limit);
    }

    /* Bare --history → historical flows */
    if (o.history) {
        return oneshot_history(&o, NULL);
    }

    /* Default: short status then drop into REPL if Lua available. */
    {
        char resp[CPE_IPC_LINE_MAX];
        char err[160];
        err[0] = '\0';
        if (cpe_ipc_client_request(o.sock, "{\"op\":\"status\"}", resp,
                                   sizeof(resp), err, sizeof(err)) != 0) {
            fprintf(stderr, "cpe_ctl: %s\n", err[0] ? err : "connect failed");
            fprintf(stderr,
                    "Start the daemon first, e.g.:\n"
                    "  cpe_agent --config /etc/cpe_agent/cpe_agent.yaml\n"
                    "Or list historical flows without the daemon:\n"
                    "  %s flow_list --history --ch-password …\n",
                    argv[0]);
            return 1;
        }
        printf("%s\n", resp);
    }

    {
        cpe_ctl_lua_t *L = cpe_ctl_lua_create(o.sock);
        if (!L) {
            return 0; /* status already printed */
        }
        rc = cpe_ctl_lua_repl(L, history);
        cpe_ctl_lua_destroy(L);
        return rc;
    }
}
