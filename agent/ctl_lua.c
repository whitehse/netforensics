/**
 * @file ctl_lua.c
 * @brief Lua bindings for cpe_ctl — remote query of cpe_agent daemon via UDS.
 */

#include "cpe_ctl_lua.h"
#include "cpe_ipc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(CPE_AGENT_HAVE_LUA)

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#if defined(CPE_AGENT_HAVE_LINENOISE) || 1
#include "linenoise.h"
#endif

struct cpe_ctl_lua {
    lua_State *L;
    char       sock[CPE_CFG_PATH_MAX];
};

static const char *sock_of(lua_State *L)
{
    const char *s;
    lua_getfield(L, LUA_REGISTRYINDEX, "cpe_ctl_sock");
    s = lua_tostring(L, -1);
    lua_pop(L, 1);
    return s;
}

/** Push JSON response body: if data is object/array/null, decode-ish as string
 * table fields; we return raw JSON string under .json and try simple decode. */
static int ipc_call(lua_State *L, const char *req)
{
    char resp[CPE_IPC_LINE_MAX];
    char err[160];
    const char *sock = sock_of(L);
    const char *data;
    const char *p;

    err[0] = '\0';
    if (cpe_ipc_client_request(sock, req, resp, sizeof(resp), err,
                               sizeof(err)) != 0) {
        return luaL_error(L, "%s", err[0] ? err : "ipc failed");
    }
    if (strstr(resp, "\"ok\":false") || strstr(resp, "\"ok\": false")) {
        char emsg[128];
        emsg[0] = '\0';
        /* crude error extract */
        p = strstr(resp, "\"error\"");
        if (p) {
            p = strchr(p, ':');
            if (p) {
                p++;
                while (*p == ' ' || *p == '"') {
                    p++;
                }
                {
                    size_t i = 0;
                    while (*p && *p != '"' && i + 1 < sizeof(emsg)) {
                        emsg[i++] = *p++;
                    }
                    emsg[i] = '\0';
                }
            }
        }
        return luaL_error(L, "%s", emsg[0] ? emsg : resp);
    }

    /* Return full response as string AND parse data when simple. */
    data = strstr(resp, "\"data\":");
    if (!data) {
        lua_pushstring(L, resp);
        return 1;
    }
    data += 7;
    while (*data == ' ' || *data == '\t') {
        data++;
    }

    /* null */
    if (strncmp(data, "null", 4) == 0) {
        lua_pushnil(L);
        return 1;
    }
    /* boolean */
    if (strncmp(data, "true", 4) == 0) {
        lua_pushboolean(L, 1);
        return 1;
    }
    if (strncmp(data, "false", 5) == 0) {
        lua_pushboolean(L, 0);
        return 1;
    }
    /* number (emit lines / tcp_poll) — return whole data JSON string for tables */
    if (*data == '{' || *data == '[') {
        /* Find matching end: strip trailing } of outer response. */
        size_t len = strlen(data);
        /* Outer is {"ok":true,"op":"...","data":...} — trim final } */
        if (len > 0 && data[len - 1] == '}') {
            /* may be object; keep as JSON string for Lua to decode manually */
            char *copy = (char *)malloc(len + 1);
            if (!copy) {
                lua_pushstring(L, data);
                return 1;
            }
            memcpy(copy, data, len);
            copy[len] = '\0';
            /* if last char is outer close, and data is object, walk back one } */
            if (copy[len - 1] == '}') {
                /* check if this is the envelope's closing brace */
                int depth = 0;
                size_t i;
                size_t end = len;
                for (i = 0; i < len; i++) {
                    if (copy[i] == '{' || copy[i] == '[') {
                        depth++;
                    } else if (copy[i] == '}' || copy[i] == ']') {
                        depth--;
                        if (depth == 0) {
                            end = i + 1;
                            break;
                        }
                    }
                }
                copy[end] = '\0';
            }
            /* Minimal JSON→Lua table for objects with string/number fields. */
            {
                lua_newtable(L);
                /* Store raw JSON always. */
                lua_pushstring(L, copy);
                lua_setfield(L, -2, "_json");
                /* Scan "key":value pairs for flat objects. */
                {
                    const char *q = copy;
                    if (*q == '{') {
                        q++;
                    }
                    while (*q) {
                        char key[64];
                        size_t ki = 0;
                        while (*q && *q != '"') {
                            q++;
                        }
                        if (*q != '"') {
                            break;
                        }
                        q++;
                        while (*q && *q != '"' && ki + 1 < sizeof(key)) {
                            key[ki++] = *q++;
                        }
                        key[ki] = '\0';
                        if (*q == '"') {
                            q++;
                        }
                        while (*q && *q != ':') {
                            q++;
                        }
                        if (*q == ':') {
                            q++;
                        }
                        while (*q == ' ' || *q == '\t') {
                            q++;
                        }
                        if (*q == '"') {
                            char val[256];
                            size_t vi = 0;
                            q++;
                            while (*q && *q != '"' && vi + 1 < sizeof(val)) {
                                if (*q == '\\' && q[1]) {
                                    q++;
                                }
                                val[vi++] = *q++;
                            }
                            val[vi] = '\0';
                            if (*q == '"') {
                                q++;
                            }
                            lua_pushstring(L, val);
                            lua_setfield(L, -2, key);
                        } else if (*q == 't' || *q == 'f') {
                            int b = (*q == 't');
                            lua_pushboolean(L, b);
                            lua_setfield(L, -2, key);
                            while (*q && *q != ',' && *q != '}') {
                                q++;
                            }
                        } else if ((*q >= '0' && *q <= '9') || *q == '-' ||
                                   *q == '.') {
                            char *end = NULL;
                            double num = strtod(q, &end);
                            lua_pushnumber(L, num);
                            lua_setfield(L, -2, key);
                            q = end ? end : q + 1;
                        } else if (*q == '{' || *q == '[') {
                            /* nested: skip, leave in _json only */
                            int depth = 0;
                            do {
                                if (*q == '{' || *q == '[') {
                                    depth++;
                                } else if (*q == '}' || *q == ']') {
                                    depth--;
                                }
                                q++;
                            } while (*q && depth > 0);
                        } else {
                            break;
                        }
                        while (*q == ' ' || *q == ',' || *q == '\t') {
                            q++;
                        }
                        if (*q == '}') {
                            break;
                        }
                    }
                }
                free(copy);
                return 1;
            }
        }
        lua_pushstring(L, data);
        return 1;
    }
    /* bare number */
    if ((*data >= '0' && *data <= '9') || *data == '-') {
        lua_pushnumber(L, strtod(data, NULL));
        return 1;
    }
    /* string */
    if (*data == '"') {
        char val[512];
        size_t vi = 0;
        data++;
        while (*data && *data != '"' && vi + 1 < sizeof(val)) {
            val[vi++] = *data++;
        }
        val[vi] = '\0';
        lua_pushstring(L, val);
        return 1;
    }
    lua_pushstring(L, resp);
    return 1;
}

static int l_help(lua_State *L)
{
    (void)L;
    cpe_ctl_lua_print_help(stdout);
    return 0;
}

static int l_status(lua_State *L)
{
    return ipc_call(L, "{\"op\":\"status\"}");
}

static int l_config(lua_State *L)
{
    return ipc_call(L, "{\"op\":\"config\"}");
}

static int l_last_sample(lua_State *L)
{
    return ipc_call(L, "{\"op\":\"last_sample\"}");
}

static int l_latency(lua_State *L)
{
    return ipc_call(L, "{\"op\":\"latency\"}");
}

static int l_spool(lua_State *L)
{
    return ipc_call(L, "{\"op\":\"spool\"}");
}

static int l_emit(lua_State *L)
{
    return ipc_call(L, "{\"op\":\"emit\"}");
}

static int l_tcp_poll(lua_State *L)
{
    char req[80];
    unsigned maxm = 64;
    if (lua_gettop(L) >= 1 && !lua_isnil(L, 1)) {
        maxm = (unsigned)luaL_checkinteger(L, 1);
    }
    snprintf(req, sizeof(req), "{\"op\":\"tcp_poll\",\"max\":%u}", maxm);
    return ipc_call(L, req);
}

static int l_tcp_stats(lua_State *L)
{
    return ipc_call(L, "{\"op\":\"tcp_stats\"}");
}

static int l_tcp_by_ip(lua_State *L)
{
    char req[160];
    if (lua_gettop(L) >= 1 && !lua_isnil(L, 1)) {
        const char *ip = luaL_checkstring(L, 1);
        snprintf(req, sizeof(req), "{\"op\":\"tcp_by_ip\",\"ip\":\"%s\"}", ip);
    } else {
        snprintf(req, sizeof(req), "{\"op\":\"tcp_by_ip\"}");
    }
    return ipc_call(L, req);
}

static int l_tcp_by_prefix(lua_State *L)
{
    char req[200];
    if (lua_gettop(L) >= 1 && !lua_isnil(L, 1)) {
        const char *p = luaL_checkstring(L, 1);
        snprintf(req, sizeof(req),
                 "{\"op\":\"tcp_by_prefix\",\"prefix\":\"%s\"}", p);
    } else {
        snprintf(req, sizeof(req), "{\"op\":\"tcp_by_prefix\"}");
    }
    return ipc_call(L, req);
}

static int l_tcp_emit(lua_State *L)
{
    char req[80];
    unsigned top = 0;
    if (lua_gettop(L) >= 1 && !lua_isnil(L, 1)) {
        top = (unsigned)luaL_checkinteger(L, 1);
    }
    snprintf(req, sizeof(req), "{\"op\":\"tcp_emit\",\"top_n\":%u}", top);
    return ipc_call(L, req);
}

static int l_tcp_reset(lua_State *L)
{
    return ipc_call(L, "{\"op\":\"tcp_reset\"}");
}

static int l_ping(lua_State *L)
{
    return ipc_call(L, "{\"op\":\"ping\"}");
}

static int l_raw(lua_State *L)
{
    const char *req = luaL_checkstring(L, 1);
    return ipc_call(L, req);
}

static const luaL_Reg cpe_funcs[] = {
    {"help", l_help},
    {"ping", l_ping},
    {"status", l_status},
    {"config", l_config},
    {"last_sample", l_last_sample},
    {"latency", l_latency},
    {"spool", l_spool},
    {"emit", l_emit},
    {"tcp_poll", l_tcp_poll},
    {"tcp_stats", l_tcp_stats},
    {"tcp_by_ip", l_tcp_by_ip},
    {"tcp_by_prefix", l_tcp_by_prefix},
    {"tcp_emit", l_tcp_emit},
    {"tcp_reset", l_tcp_reset},
    {"raw", l_raw},
    {NULL, NULL}
};

void cpe_ctl_lua_print_help(FILE *fp)
{
    if (!fp) {
        fp = stdout;
    }
    fprintf(fp,
            "cpe_ctl Lua tools (query cpe_agent daemon over Unix socket):\n"
            "  cpe.help() / cpe.ping() / cpe.status() / cpe.config()\n"
            "  cpe.last_sample() / cpe.latency() / cpe.spool() / cpe.emit()\n"
            "  cpe.tcp_poll([max]) / cpe.tcp_stats()\n"
            "  cpe.tcp_by_ip([ip]) / cpe.tcp_by_prefix([cidr])\n"
            "  cpe.tcp_emit([top_n]) / cpe.tcp_reset()\n"
            "  cpe.raw('{\"op\":\"status\"}')  -- advanced\n"
            "\n"
            "Daemon collects samples + TCP NFLOG stats and POSTs NDJSON to\n"
            "edgehost telemetry (→ ClickHouse). This client only queries.\n"
            "Tables include flat fields plus raw JSON in ._json.\n"
            "REPL: quit | exit | Ctrl-D\n");
}

cpe_ctl_lua_t *cpe_ctl_lua_create(const char *sock_path)
{
    cpe_ctl_lua_t *wrap;
    lua_State *L;
    const char *path =
        sock_path && sock_path[0] ? sock_path : CPE_IPC_SOCK_DEFAULT;

    wrap = (cpe_ctl_lua_t *)calloc(1, sizeof(*wrap));
    if (!wrap) {
        return NULL;
    }
    snprintf(wrap->sock, sizeof(wrap->sock), "%s", path);
    L = luaL_newstate();
    if (!L) {
        free(wrap);
        return NULL;
    }
    luaL_openlibs(L);
    wrap->L = L;
    lua_pushstring(L, wrap->sock);
    lua_setfield(L, LUA_REGISTRYINDEX, "cpe_ctl_sock");
    luaL_newlib(L, cpe_funcs);
    lua_setglobal(L, "cpe");
    return wrap;
}

void cpe_ctl_lua_destroy(cpe_ctl_lua_t *Lwrap)
{
    if (!Lwrap) {
        return;
    }
    if (Lwrap->L) {
        lua_close(Lwrap->L);
    }
    free(Lwrap);
}

int cpe_ctl_lua_dostring(cpe_ctl_lua_t *Lwrap, const char *src, char *err,
                         size_t err_len)
{
    int rc;
    if (!Lwrap || !Lwrap->L || !src) {
        if (err && err_len) {
            snprintf(err, err_len, "bad args");
        }
        return -1;
    }
    rc = luaL_dostring(Lwrap->L, src);
    if (rc != LUA_OK) {
        const char *msg = lua_tostring(Lwrap->L, -1);
        if (err && err_len) {
            snprintf(err, err_len, "%s", msg ? msg : "lua error");
        }
        lua_pop(Lwrap->L, 1);
        return -1;
    }
    return 0;
}

int cpe_ctl_lua_dofile(cpe_ctl_lua_t *Lwrap, const char *path, char *err,
                       size_t err_len)
{
    int rc;
    if (!Lwrap || !Lwrap->L || !path) {
        if (err && err_len) {
            snprintf(err, err_len, "bad args");
        }
        return -1;
    }
    rc = luaL_dofile(Lwrap->L, path);
    if (rc != LUA_OK) {
        const char *msg = lua_tostring(Lwrap->L, -1);
        if (err && err_len) {
            snprintf(err, err_len, "%s", msg ? msg : "lua error");
        }
        lua_pop(Lwrap->L, 1);
        return -1;
    }
    return 0;
}

int cpe_ctl_lua_repl(cpe_ctl_lua_t *Lwrap, const char *history_path)
{
    char *line;
    const char *hist =
        history_path && history_path[0] ? history_path : "/tmp/cpe_ctl_history";

    if (!Lwrap || !Lwrap->L) {
        return 1;
    }
    linenoiseHistoryLoad(hist);
    linenoiseSetMultiLine(1);
    printf("cpe_ctl connected to %s — cpe.help() for API, quit to exit\n",
           Lwrap->sock);
    while ((line = linenoise("cpe_ctl> ")) != NULL) {
        char err[256];
        char chunk[4096];
        if (!line[0]) {
            linenoiseFree(line);
            continue;
        }
        if (strcmp(line, "quit") == 0 || strcmp(line, "exit") == 0) {
            linenoiseFree(line);
            break;
        }
        linenoiseHistoryAdd(line);
        /* Auto-return expressions like local cpe_agent REPL. */
        if (strncmp(line, "return ", 7) == 0 || strstr(line, "=") ||
            strncmp(line, "for ", 4) == 0 || strncmp(line, "if ", 3) == 0 ||
            strncmp(line, "while ", 6) == 0 || strncmp(line, "local ", 6) == 0 ||
            strncmp(line, "function ", 9) == 0 || strncmp(line, "do ", 3) == 0) {
            snprintf(chunk, sizeof(chunk), "%s", line);
        } else {
            snprintf(chunk, sizeof(chunk), "return %s", line);
        }
        err[0] = '\0';
        if (cpe_ctl_lua_dostring(Lwrap, chunk, err, sizeof(err)) != 0) {
            /* retry without return */
            err[0] = '\0';
            if (cpe_ctl_lua_dostring(Lwrap, line, err, sizeof(err)) != 0) {
                fprintf(stderr, "error: %s\n", err[0] ? err : "lua");
            }
        } else if (lua_gettop(Lwrap->L) > 0) {
            if (lua_istable(Lwrap->L, -1)) {
                /* print simple table */
                lua_pushnil(Lwrap->L);
                printf("{");
                int first = 1;
                while (lua_next(Lwrap->L, -2) != 0) {
                    if (!first) {
                        printf(", ");
                    }
                    first = 0;
                    if (lua_type(Lwrap->L, -2) == LUA_TSTRING) {
                        printf("%s=", lua_tostring(Lwrap->L, -2));
                    }
                    if (lua_isstring(Lwrap->L, -1) && !lua_isnumber(Lwrap->L, -1)) {
                        printf("%s", lua_tostring(Lwrap->L, -1));
                    } else if (lua_isboolean(Lwrap->L, -1)) {
                        printf("%s", lua_toboolean(Lwrap->L, -1) ? "true" : "false");
                    } else if (lua_isnumber(Lwrap->L, -1)) {
                        printf("%g", lua_tonumber(Lwrap->L, -1));
                    } else {
                        printf("%s", luaL_typename(Lwrap->L, -1));
                    }
                    lua_pop(Lwrap->L, 1);
                }
                printf("}\n");
            } else if (!lua_isnil(Lwrap->L, -1)) {
                if (lua_isstring(Lwrap->L, -1)) {
                    printf("%s\n", lua_tostring(Lwrap->L, -1));
                } else if (lua_isboolean(Lwrap->L, -1)) {
                    printf("%s\n",
                           lua_toboolean(Lwrap->L, -1) ? "true" : "false");
                } else if (lua_isnumber(Lwrap->L, -1)) {
                    printf("%g\n", lua_tonumber(Lwrap->L, -1));
                }
            }
            lua_settop(Lwrap->L, 0);
        }
        linenoiseFree(line);
    }
    linenoiseHistorySave(hist);
    return 0;
}

#else /* !CPE_AGENT_HAVE_LUA */

struct cpe_ctl_lua {
    int dummy;
};

cpe_ctl_lua_t *cpe_ctl_lua_create(const char *sock_path)
{
    (void)sock_path;
    return NULL;
}
void cpe_ctl_lua_destroy(cpe_ctl_lua_t *Lwrap)
{
    (void)Lwrap;
}
int cpe_ctl_lua_dostring(cpe_ctl_lua_t *Lwrap, const char *src, char *err,
                         size_t err_len)
{
    (void)Lwrap;
    (void)src;
    if (err && err_len) {
        snprintf(err, err_len, "Lua not built");
    }
    return -1;
}
int cpe_ctl_lua_dofile(cpe_ctl_lua_t *Lwrap, const char *path, char *err,
                       size_t err_len)
{
    (void)Lwrap;
    (void)path;
    if (err && err_len) {
        snprintf(err, err_len, "Lua not built");
    }
    return -1;
}
int cpe_ctl_lua_repl(cpe_ctl_lua_t *Lwrap, const char *history_path)
{
    (void)Lwrap;
    (void)history_path;
    return 1;
}
void cpe_ctl_lua_print_help(FILE *fp)
{
    if (!fp) {
        fp = stdout;
    }
    fprintf(fp, "cpe_ctl: rebuild with -DCPE_AGENT_WITH_LUA=ON\n");
}

#endif
